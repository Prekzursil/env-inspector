from __future__ import annotations

import csv
import difflib
import io
import json
import os
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_BACKUP_RETENTION,
    DEFAULT_SCAN_DEPTH,
    SOURCE_DOTENV,
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_WSL_BASHRC,
    SOURCE_WSL_DOTENV,
    SOURCE_WSL_ETC_ENV,
)
from .models import EnvRecord, OperationResult
from .path_policy import (
    normalize_scope_roots,
    parse_scoped_dotenv_target,
    resolve_scan_root,
    validate_backup_path,
)
from .parsing import (
    remove_export,
    remove_key_value,
    remove_powershell_env,
    upsert_export,
    upsert_key_value,
    upsert_powershell_env,
    validate_env_key,
    validate_env_value,
)
from .providers import (
    WindowsRegistryProvider,
    WslProvider,
    collect_dotenv_records,
    collect_linux_records,
    collect_powershell_profile_records,
    collect_process_records,
    collect_wsl_dotenv_records,
    collect_wsl_records,
    build_registry_records,
    current_wsl_distro_name,
    get_runtime_context,
    is_windows,
)
from .resolver import resolve_effective_value
from .secrets import looks_secret, mask_value
from .storage import AuditLogger, BackupManager


class EnvInspectorService:
    _LINUX_ETC_ENV_PATH = "/etc/environment"

    def __init__(self, state_dir: Path | None = None, backup_retention: int = DEFAULT_BACKUP_RETENTION) -> None:
        self.state_dir = Path(state_dir or (Path.cwd() / ".env-inspector-state"))
        self.backup_mgr = BackupManager(self.state_dir / "backups", retention=backup_retention)
        self.audit = AuditLogger(self.state_dir)
        self.default_scope_roots = normalize_scope_roots([Path.cwd()])
        self.runtime_context = get_runtime_context()
        self.current_wsl_distro = current_wsl_distro_name()

        self.wsl = WslProvider()
        self.win_provider: WindowsRegistryProvider | None = None
        if is_windows():
            try:
                self.win_provider = WindowsRegistryProvider()
            except Exception:
                self.win_provider = None

    def _effective_scope_roots(self, scope_roots: list[str | Path] | None = None) -> list[Path]:
        roots: list[Path] = list(self.default_scope_roots)
        if scope_roots:
            roots.extend(normalize_scope_roots(scope_roots))
        return normalize_scope_roots(roots)

    @staticmethod
    def get_powershell_profile_paths() -> list[Path]:
        docs = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
        current = docs / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
        all_users = Path(r"C:\\Program Files\\PowerShell\\7\\profile.ps1")
        return [current, all_users]

    @staticmethod
    def _is_path_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    @classmethod
    def _validate_path_in_roots(cls, path: Path, roots: list[Path] | tuple[Path, ...], *, label: str) -> Path:
        resolved_path = path.resolve(strict=False)
        resolved_roots = [root.resolve(strict=False) for root in roots]
        for root in resolved_roots:
            if cls._is_path_within(resolved_path, root):
                return resolved_path
        raise RuntimeError(f"{label} is outside approved roots: {resolved_path}")

    def _validated_powershell_restore_path(self, target: str) -> Path:
        if target not in {"powershell:current_user", "powershell:all_users"}:
            raise RuntimeError(f"Unsupported PowerShell target: {target}")
        profile = self._powershell_profile_path(target).resolve(strict=False)
        if target == "powershell:current_user":
            allowed_root = Path.home().resolve(strict=False)
        else:
            allowed_root = Path(r"C:\\Program Files").resolve(strict=False)
        if not self._is_path_within(profile, allowed_root):
            raise RuntimeError(f"PowerShell profile path is outside expected root: {profile}")
        return profile

    @classmethod
    def _linux_etc_environment_path(cls) -> Path:
        path = Path(cls._LINUX_ETC_ENV_PATH)
        if path.as_posix() != cls._LINUX_ETC_ENV_PATH:
            raise RuntimeError(f"Unexpected /etc/environment resolution: {path}")
        return path

    def list_contexts(self) -> list[str]:
        contexts = [self.runtime_context]
        if self.wsl.available():
            for distro in self._bridge_distros():
                contexts.append(f"wsl:{distro}")
        return contexts

    def _bridge_distros(self) -> list[str]:
        if not self.wsl.available():
            return []
        distros = self.wsl.list_distros_for_ui()
        if self.runtime_context == "linux" and self.current_wsl_distro:
            current = self.current_wsl_distro.lower()
            distros = [d for d in distros if d.lower() != current]
        return distros

    def _collect_host_rows(self, root_path: Path, scan_depth: int) -> list[EnvRecord]:
        rows: list[EnvRecord] = []
        rows.extend(collect_process_records(context=self.runtime_context))
        rows.extend(collect_dotenv_records(root_path, max_depth=scan_depth, context=self.runtime_context))

        if self.win_provider is not None:
            try:
                rows.extend(build_registry_records(self.win_provider))
            except Exception:
                pass

        if self.runtime_context == "windows":
            rows.extend(collect_powershell_profile_records(self.get_powershell_profile_paths()))
        else:
            rows.extend(collect_linux_records(context=self.runtime_context))

        return rows

    def _collect_wsl_rows(
        self,
        *,
        scan_depth: int,
        distro: str | None,
        wsl_path: str | None,
    ) -> list[EnvRecord]:
        rows: list[EnvRecord] = []
        if not self.wsl.available():
            return rows

        try:
            exclude_distros: set[str] | None = None
            if self.runtime_context == "linux" and self.current_wsl_distro:
                exclude_distros = {self.current_wsl_distro}
            rows.extend(collect_wsl_records(self.wsl, include_etc=True, exclude_distros=exclude_distros))
        except Exception:
            pass

        if distro and wsl_path:
            try:
                rows.extend(collect_wsl_dotenv_records(self.wsl, distro=distro, root_path=wsl_path, max_depth=scan_depth))
            except Exception:
                pass

        return rows

    @staticmethod
    def _apply_row_filters(
        rows: list[EnvRecord],
        *,
        source: list[str] | None,
        context: str | None,
    ) -> list[EnvRecord]:
        if source:
            source_set = set(source)
            rows = [r for r in rows if r.source_type in source_set]
        if context:
            rows = [r for r in rows if r.context == context]
        return rows

    def list_records(
        self,
        *,
        root: str | Path | None = None,
        context: str | None = None,
        source: list[str] | None = None,
        wsl_path: str | None = None,
        distro: str | None = None,
        scan_depth: int = DEFAULT_SCAN_DEPTH,
        include_raw_secrets: bool = False,
    ) -> list[dict[str, Any]]:
        root_path = resolve_scan_root(root or Path.cwd())
        rows = self._collect_host_rows(root_path, scan_depth)
        rows.extend(self._collect_wsl_rows(scan_depth=scan_depth, distro=distro, wsl_path=wsl_path))
        rows = self._apply_row_filters(rows, source=source, context=context)
        rows.sort(key=lambda r: (r.name.lower(), r.context, r.source_type, r.source_path))

        payload: list[dict[str, Any]] = []
        for rec in rows:
            item = rec.to_dict(include_value=True)
            if rec.is_secret and not include_raw_secrets:
                item["value"] = mask_value(rec.value)
            payload.append(item)
        return payload

    def list_records_raw(self, **kwargs: Any) -> list[EnvRecord]:
        payload = self.list_records(include_raw_secrets=True, **kwargs)
        rows: list[EnvRecord] = []
        for item in payload:
            rows.append(EnvRecord(**item))
        return rows

    def resolve_effective(self, key: str, context: str, records: list[EnvRecord]) -> EnvRecord | None:
        return resolve_effective_value(records, key, context)

    @staticmethod
    def _diff(before: str, after: str, target: str) -> str:
        diff = difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"{target} (before)",
            tofile=f"{target} (after)",
            lineterm="",
        )
        return "\n".join(diff)

    def _write_linux_etc_environment_with_privilege(self, text: str) -> None:
        path = self._linux_etc_environment_path()
        try:
            path.write_text(text, encoding="utf-8")
            return
        except PermissionError:
            pass

        proc = subprocess.run(
            ["sudo", "-n", "tee", self._LINUX_ETC_ENV_PATH],
            input=text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode == 0:
            return

        err = proc.stderr.decode(errors="ignore").strip()
        raise RuntimeError(
            "Failed to write /etc/environment using direct write and sudo fallback. "
            "Run with elevated privileges or configure passwordless sudo for this command."
            + (f" Details: {err}" if err else "")
        )

    def available_targets(self, records: list[EnvRecord], context: str | None = None) -> list[str]:
        targets: set[str] = set()
        for record in records:
            if context and record.context != context:
                continue
            mapped_target = self._record_target(record)
            if mapped_target:
                targets.add(mapped_target)
        if self.win_provider is not None:
            targets.add("windows:user")
            targets.add("windows:machine")
        if context == "linux":
            targets.add("linux:bashrc")
            targets.add("linux:etc_environment")
        return sorted(targets)

    @staticmethod
    def _record_target(record: EnvRecord) -> str | None:
        if record.source_type == SOURCE_DOTENV:
            return f"dotenv:{record.source_path}"
        if record.source_type == SOURCE_LINUX_BASHRC:
            return "linux:bashrc"
        if record.source_type == SOURCE_LINUX_ETC_ENV:
            return "linux:etc_environment"
        if record.source_type == SOURCE_WSL_DOTENV:
            return f"wsl_dotenv:{record.source_path}"
        if record.source_type == SOURCE_WSL_BASHRC:
            return f"wsl:{record.source_id}:bashrc"
        if record.source_type == SOURCE_WSL_ETC_ENV:
            return f"wsl:{record.source_id}:etc_environment"
        if record.source_type == SOURCE_POWERSHELL_PROFILE:
            if "Program Files" in record.source_path:
                return "powershell:all_users"
            return "powershell:current_user"
        return None

    def _registry_write(
        self,
        target: str,
        key: str,
        value: str | None,
        action: str,
        *,
        apply_changes: bool,
    ) -> tuple[str, str, str | None, bool, str | None]:
        if self.win_provider is None:
            raise RuntimeError("Windows registry provider unavailable.")
        scope = WindowsRegistryProvider.USER_SCOPE if target == "windows:user" else WindowsRegistryProvider.MACHINE_SCOPE
        current = self.win_provider.list_scope(scope)
        before = json.dumps(current, indent=2, sort_keys=True)
        if action == "set" and value is not None:
            if apply_changes:
                self.win_provider.set_scope_value(scope, key, value)
            current[key] = value
        elif action == "remove":
            if apply_changes:
                self.win_provider.remove_scope_value(scope, key)
            current.pop(key, None)
        after = json.dumps(current, indent=2, sort_keys=True)
        requires_priv = target == "windows:machine"
        return before, after, None, requires_priv, None

    def _powershell_profile_path(self, target: str) -> Path:
        current, all_users = self.get_powershell_profile_paths()
        if target == "powershell:current_user":
            return current
        if target == "powershell:all_users":
            return all_users
        raise RuntimeError(f"Unsupported PowerShell target: {target}")

    def _update_dotenv_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
        scope_roots: list[Path],
    ) -> tuple[str, str, str | None, bool, str | None]:
        scoped = parse_scoped_dotenv_target(target, roots=scope_roots)
        path = self._validate_path_in_roots(scoped.path, list(scoped.roots), label="dotenv target path")
        before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        after = upsert_key_value(before, key, value or "", quote=False) if action == "set" else remove_key_value(before, key)
        if apply_changes:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(after, encoding="utf-8")
        return before, after, str(path), False, None

    def _update_linux_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> tuple[str, str, str | None, bool, str | None]:
        if target == "linux:bashrc":
            path = Path.home() / ".bashrc"
            before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
            after = upsert_export(before, key, value or "") if action == "set" else remove_export(before, key)
            if apply_changes:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(after, encoding="utf-8")
            return before, after, str(path), False, None
        if target == "linux:etc_environment":
            path = self._linux_etc_environment_path()
            before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
            after = upsert_key_value(before, key, value or "", quote=False) if action == "set" else remove_key_value(before, key)
            if apply_changes:
                self._write_linux_etc_environment_with_privilege(after)
            return before, after, self._LINUX_ETC_ENV_PATH, True, None
        raise RuntimeError(f"Unsupported Linux target: {target}")

    def _update_wsl_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> tuple[str, str, str | None, bool, str | None]:
        if target.startswith("wsl_dotenv:"):
            raw = target[len("wsl_dotenv:") :]
            distro, path = raw.split(":", 1)
            before = self.wsl.read_file(distro, path)
            after = upsert_key_value(before, key, value or "", quote=False) if action == "set" else remove_key_value(before, key)
            if apply_changes:
                self.wsl.write_file(distro, path, after)
            return before, after, f"{distro}:{path}", False, None
        if target.startswith("wsl:") and target.endswith(":bashrc"):
            distro = target.split(":", 2)[1]
            path = "~/.bashrc"
            before = self.wsl.read_file(distro, path)
            after = upsert_export(before, key, value or "") if action == "set" else remove_export(before, key)
            if apply_changes:
                self.wsl.write_file(distro, path, after)
            return before, after, f"{distro}:{path}", False, None
        if target.startswith("wsl:") and target.endswith(":etc_environment"):
            distro = target.split(":", 2)[1]
            path = self._LINUX_ETC_ENV_PATH
            before = self.wsl.read_file(distro, path)
            after = upsert_key_value(before, key, value or "", quote=False) if action == "set" else remove_key_value(before, key)
            if apply_changes:
                self.wsl.write_file_with_privilege(distro, path, after)
            return before, after, f"{distro}:{path}", True, None
        raise RuntimeError(f"Unsupported WSL target: {target}")

    def _update_powershell_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> tuple[str, str, str | None, bool, str | None]:
        path = self._powershell_profile_path(target)
        before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        after = upsert_powershell_env(before, key, value or "") if action == "set" else remove_powershell_env(before, key)
        if apply_changes:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(after, encoding="utf-8")
        requires_priv = "all_users" in target
        return before, after, str(path), requires_priv, None

    def _file_update(
        self,
        target: str,
        key: str,
        value: str | None,
        action: str,
        *,
        apply_changes: bool,
        scope_roots: list[Path],
    ) -> tuple[str, str, str | None, bool, str | None]:
        if target.startswith("dotenv:"):
            return self._update_dotenv_file(
                target=target,
                key=key,
                value=value,
                action=action,
                apply_changes=apply_changes,
                scope_roots=scope_roots,
            )
        if target.startswith("linux:"):
            return self._update_linux_file(
                target=target,
                key=key,
                value=value,
                action=action,
                apply_changes=apply_changes,
            )
        if target.startswith("wsl"):
            return self._update_wsl_file(
                target=target,
                key=key,
                value=value,
                action=action,
                apply_changes=apply_changes,
            )
        if target.startswith("powershell:"):
            return self._update_powershell_file(
                target=target,
                key=key,
                value=value,
                action=action,
                apply_changes=apply_changes,
            )
        raise RuntimeError(f"Unsupported target: {target}")

    def _plan_target_operation(
        self,
        target: str,
        key: str,
        value: str | None,
        action: str,
        *,
        apply_changes: bool,
        scope_roots: list[Path],
    ) -> tuple[str, str, str | None, bool, str | None]:
        if target in {"windows:user", "windows:machine"}:
            return self._registry_write(target, key, value, action, apply_changes=apply_changes)
        return self._file_update(target, key, value, action, apply_changes=apply_changes, scope_roots=scope_roots)

    def _apply(
        self,
        action: str,
        *,
        key: str,
        value: str | None,
        targets: list[str],
        preview_only: bool = False,
        scope_roots: list[str | Path] | None = None,
    ) -> list[OperationResult]:
        validate_env_key(key)
        if action == "set":
            validate_env_value(value or "")
        secret_operation = looks_secret(key, value or "")
        resolved_scope_roots = self._effective_scope_roots(scope_roots)

        results: list[OperationResult] = []
        for target in targets:
            operation_id = f"{action}-{uuid.uuid4().hex[:10]}"
            backup_path: str | None = None
            diff_preview = ""
            try:
                before, after, _, _, _ = self._plan_target_operation(
                    target=target,
                    key=key,
                    value=value,
                    action=action,
                    apply_changes=False,
                    scope_roots=resolved_scope_roots,
                )
                diff_preview = self._diff(before, after, target)

                if preview_only:
                    result = OperationResult(
                        operation_id=operation_id,
                        target=target,
                        action=action,
                        success=True,
                        backup_path=None,
                        diff_preview=diff_preview,
                        error_message=None,
                        value_masked=mask_value(value or "") if secret_operation and value is not None else None,
                    )
                else:
                    backup = self.backup_mgr.backup_text(target, before)
                    backup_path = str(backup)

                    self._plan_target_operation(
                        target=target,
                        key=key,
                        value=value,
                        action=action,
                        apply_changes=True,
                        scope_roots=resolved_scope_roots,
                    )

                    result = OperationResult(
                        operation_id=operation_id,
                        target=target,
                        action=action,
                        success=True,
                        backup_path=backup_path,
                        diff_preview=diff_preview,
                        error_message=None,
                        value_masked=mask_value(value or "") if secret_operation and value is not None else None,
                    )

            except Exception as exc:
                result = OperationResult(
                    operation_id=operation_id,
                    target=target,
                    action=action,
                    success=False,
                    backup_path=backup_path,
                    diff_preview=diff_preview,
                    error_message=str(exc),
                    value_masked=mask_value(value or "") if secret_operation and value is not None else None,
                )

            self.audit.log(self._audit_safe_result(result, redact=secret_operation))
            results.append(result)

        return results

    @staticmethod
    def _audit_safe_result(result: OperationResult, *, redact: bool) -> OperationResult:
        if not redact:
            return result
        redacted_diff = "[secret diff masked]"
        return replace(result, diff_preview=redacted_diff)

    def preview_set(
        self,
        *,
        key: str,
        value: str,
        targets: list[str],
        scope_roots: list[str | Path] | None = None,
    ) -> list[dict[str, Any]]:
        return [
            r.to_dict()
            for r in self._apply("set", key=key, value=value, targets=targets, preview_only=True, scope_roots=scope_roots)
        ]

    def preview_remove(
        self,
        *,
        key: str,
        targets: list[str],
        scope_roots: list[str | Path] | None = None,
    ) -> list[dict[str, Any]]:
        return [
            r.to_dict()
            for r in self._apply(
                "remove",
                key=key,
                value=None,
                targets=targets,
                preview_only=True,
                scope_roots=scope_roots,
            )
        ]

    def set_key(
        self,
        *,
        key: str,
        value: str,
        targets: list[str],
        scope_roots: list[str | Path] | None = None,
    ) -> dict[str, Any]:
        results = self._apply("set", key=key, value=value, targets=targets, preview_only=False, scope_roots=scope_roots)
        if len(results) == 1:
            return results[0].to_dict()
        return {"success": all(r.success for r in results), "results": [r.to_dict() for r in results]}

    def remove_key(
        self,
        *,
        key: str,
        targets: list[str],
        scope_roots: list[str | Path] | None = None,
    ) -> dict[str, Any]:
        results = self._apply("remove", key=key, value=None, targets=targets, preview_only=False, scope_roots=scope_roots)
        if len(results) == 1:
            return results[0].to_dict()
        return {"success": all(r.success for r in results), "results": [r.to_dict() for r in results]}

    def export_records(
        self,
        *,
        output: str,
        include_raw_secrets: bool,
        **list_kwargs: Any,
    ) -> str:
        rows = self.list_records(include_raw_secrets=include_raw_secrets, **list_kwargs)
        if output == "json":
            return json.dumps(rows, ensure_ascii=True, indent=2)
        if output == "csv":
            if not rows:
                return ""
            keys = sorted(rows[0].keys())
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=keys)
            writer.writeheader()
            writer.writerows(rows)
            return buf.getvalue()

        # table
        lines = []
        for row in rows:
            lines.append(f"{row['context']}\t{row['source_type']}\t{row['name']}\t{row['value']}")
        return "\n".join(lines) + ("\n" if lines else "")

    def list_backups(self, *, target: str | None = None) -> list[str]:
        if target:
            return [str(p) for p in self.backup_mgr.list_backups(target)]
        return [str(p) for p in self.backup_mgr.list_all_backups()]

    def _restore_dotenv_target(self, *, target: str, text: str, scope_roots: list[Path]) -> None:
        scoped = parse_scoped_dotenv_target(target, roots=scope_roots)

        candidate_abs = os.path.abspath(os.path.normpath(str(scoped.path)))
        allowed_roots_abs = [os.path.abspath(os.path.normpath(str(root))) for root in scope_roots]
        if not any(os.path.commonpath([candidate_abs, root_abs]) == root_abs for root_abs in allowed_roots_abs):
            raise RuntimeError(f"restore dotenv path is outside approved roots: {candidate_abs}")

        safe_path = Path(candidate_abs).resolve(strict=False)
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        safe_path.write_text(text, encoding="utf-8")

    def _restore_linux_target(self, *, target: str, text: str) -> None:
        if target == "linux:bashrc":
            path_out = Path.home() / ".bashrc"
            path_out.parent.mkdir(parents=True, exist_ok=True)
            path_out.write_text(text, encoding="utf-8")
            return
        if target == "linux:etc_environment":
            self._write_linux_etc_environment_with_privilege(text)
            return
        raise RuntimeError(f"Unsupported Linux restore target: {target}")

    def _restore_wsl_target(self, *, target: str, text: str) -> None:
        if target.startswith("wsl_dotenv:"):
            raw = target[len("wsl_dotenv:") :]
            distro, pth = raw.split(":", 1)
            self.wsl.write_file(distro, pth, text)
            return
        if target.startswith("wsl:") and target.endswith(":bashrc"):
            distro = target.split(":", 2)[1]
            self.wsl.write_file(distro, "~/.bashrc", text)
            return
        if target.startswith("wsl:") and target.endswith(":etc_environment"):
            distro = target.split(":", 2)[1]
            self.wsl.write_file_with_privilege(distro, self._LINUX_ETC_ENV_PATH, text)
            return
        raise RuntimeError(f"Unsupported WSL restore target: {target}")

    def _restore_powershell_target(self, *, target: str, text: str) -> None:
        profile = self._validated_powershell_restore_path(target)
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_text(text, encoding="utf-8")

    def _restore_windows_registry_target(self, *, target: str, text: str) -> None:
        if self.win_provider is None:
            raise RuntimeError("Windows provider unavailable for registry restore")
        data = json.loads(text)
        scope = WindowsRegistryProvider.USER_SCOPE if target == "windows:user" else WindowsRegistryProvider.MACHINE_SCOPE
        current = self.win_provider.list_scope(scope)
        for key in list(current.keys()):
            if key not in data:
                self.win_provider.remove_scope_value(scope, key)
        for key, value in data.items():
            self.win_provider.set_scope_value(scope, key, str(value))

    def _restore_target(self, *, target: str, text: str, scope_roots: list[Path]) -> None:
        if target.startswith("dotenv:"):
            self._restore_dotenv_target(target=target, text=text, scope_roots=scope_roots)
            return
        if target in {"linux:bashrc", "linux:etc_environment"}:
            self._restore_linux_target(target=target, text=text)
            return
        if target.startswith("wsl"):
            self._restore_wsl_target(target=target, text=text)
            return
        if target in {"powershell:current_user", "powershell:all_users"}:
            self._restore_powershell_target(target=target, text=text)
            return
        if target in {"windows:user", "windows:machine"}:
            self._restore_windows_registry_target(target=target, text=text)
            return
        raise RuntimeError(f"Unsupported restore target: {target}")

    def restore_backup(
        self,
        *,
        backup: str,
        scope_roots: list[str | Path] | None = None,
    ) -> dict[str, Any]:
        operation_id = f"restore-{uuid.uuid4().hex[:10]}"
        path = Path(backup)
        try:
            resolved_scope_roots = self._effective_scope_roots(scope_roots)
            path = validate_backup_path(backup, backups_dir=self.backup_mgr.base_dir)
            payload = self.backup_mgr.read_backup_payload(path)
            target = payload["target"]
            text = payload["text"]

            self._restore_target(target=target, text=text, scope_roots=resolved_scope_roots)

            result = OperationResult(
                operation_id=operation_id,
                target=target,
                action="restore",
                success=True,
                backup_path=str(path),
                diff_preview="",
                error_message=None,
                value_masked=None,
            )
        except Exception as exc:
            result = OperationResult(
                operation_id=operation_id,
                target="restore",
                action="restore",
                success=False,
                backup_path=str(path),
                diff_preview="",
                error_message=str(exc),
                value_masked=None,
            )

        self.audit.log(result)
        return result.to_dict()

