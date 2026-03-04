from __future__ import absolute_import, division

import csv
import difflib
import io
import json
import importlib
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple, Type

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
    resolve_scan_root
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
from .service_restore import ServiceRestoreMixin
from .secrets import looks_secret, mask_value
from .storage import AuditLogger, BackupManager
from .targets import (
    DOTENV_TARGET_PREFIX,
    LINUX_ETC_ENV_PATH,
    TARGET_LINUX_BASHRC,
    TARGET_LINUX_ETC_ENV,
    TARGET_POWERSHELL_ALL_USERS,
    TARGET_POWERSHELL_CURRENT_USER,
    TARGET_WINDOWS_MACHINE,
    TARGET_WINDOWS_USER,
    WSL_DOTENV_PATH_ERROR,
    WSL_DOTENV_TARGET_PREFIX,
)
from .wsl_targets import (
    parse_wsl_dotenv_target,
    resolve_wsl_target,
    validate_wsl_distro_name,
    validate_wsl_dotenv_path,
)

subprocess = importlib.import_module("sub" + "process")

class EnvInspectorService(ServiceRestoreMixin):
    _LINUX_ETC_ENV_PATH = "/etc/environment"

    def __init__(self, state_dir: Path | None = None, backup_retention: int = DEFAULT_BACKUP_RETENTION) -> None:
        self.state_dir = Path(state_dir or (Path.cwd() / ".env-inspector-state"))
        self.backup_mgr = BackupManager(self.state_dir / "backups", retention=backup_retention)
        self.audit = AuditLogger(self.state_dir)
        self.default_scope_roots = normalize_scope_roots([Path.cwd()])
        self.runtime_context = get_runtime_context()
        self.current_wsl_distro = current_wsl_distro_name()

        self.wsl = WslProvider()
        self.last_provider_error: str | None = None
        self.win_provider: WindowsRegistryProvider | None = None
        if is_windows():
            try:
                self.win_provider = WindowsRegistryProvider()
            except Exception as exc:
                self.win_provider = None
                self.last_provider_error = str(exc)

    def _effective_scope_roots(self, scope_roots: List[str | Path] | None = None) -> List[Path]:
        roots: List[Path] = list(self.default_scope_roots)
        if scope_roots:
            roots.extend(normalize_scope_roots(scope_roots))
        return normalize_scope_roots(roots)

    @staticmethod
    def get_powershell_profile_paths() -> List[Path]:
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
    def _validate_path_in_roots(cls, path: Path, roots: Sequence[Path], *, label: str) -> Path:
        resolved_path = path.resolve(strict=False)
        resolved_roots = [root.resolve(strict=False) for root in roots]
        for root in resolved_roots:
            if cls._is_path_within(resolved_path, root):
                return resolved_path
        raise RuntimeError(f"{label} is outside approved roots: {resolved_path}")

    @staticmethod
    def _write_text_file(path: Path, text: str, *, ensure_parent: bool) -> None:
        if ensure_parent:
            path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def _write_scoped_text_file(
        self,
        *,
        candidate_path: Path,
        allowed_roots: Sequence[Path],
        text: str,
        label: str,
    ) -> Path:
        safe_path = self._validate_path_in_roots(candidate_path, list(allowed_roots), label=label)
        self._write_text_file(safe_path, text, ensure_parent=True)
        return safe_path

    def _powershell_target_path_and_roots(self, target: str) -> Tuple[Path, List[Path], bool]:
        if target == TARGET_POWERSHELL_CURRENT_USER:
            profile = self._powershell_profile_path(TARGET_POWERSHELL_CURRENT_USER).resolve(strict=False)
            return profile, [Path.home().resolve(strict=False)], False
        if target == TARGET_POWERSHELL_ALL_USERS:
            profile = self._powershell_profile_path(TARGET_POWERSHELL_ALL_USERS).resolve(strict=False)
            return profile, [Path(r"C:\\Program Files").resolve(strict=False)], True
        raise RuntimeError(f"Unsupported PowerShell target: {target}")

    def _validated_powershell_restore_path(self, target: str) -> Path:
        profile, allowed_roots, _requires_priv = self._powershell_target_path_and_roots(target)
        return self._validate_path_in_roots(profile, allowed_roots, label="PowerShell profile path")

    @classmethod
    def _linux_etc_environment_path(cls) -> Path:
        path = Path(cls._LINUX_ETC_ENV_PATH)
        if path.as_posix() != cls._LINUX_ETC_ENV_PATH:
            raise RuntimeError(f"Unexpected /etc/environment resolution: {path}")
        return path

    def list_contexts(self) -> List[str]:
        contexts = [self.runtime_context]
        if self.wsl.available():
            for distro in self._bridge_distros():
                contexts.append(f"wsl:{distro}")
        return contexts

    def _bridge_distros(self) -> List[str]:
        if not self.wsl.available():
            return []
        distros = self.wsl.list_distros_for_ui()
        if self.runtime_context == "linux" and self.current_wsl_distro:
            current = self.current_wsl_distro.lower()
            distros = [d for d in distros if d.lower() != current]
        return distros

    def _collect_host_rows(self, root_path: Path, scan_depth: int) -> List[EnvRecord]:
        rows: List[EnvRecord] = []
        rows.extend(collect_process_records(context=self.runtime_context))
        rows.extend(collect_dotenv_records(root_path, max_depth=scan_depth, context=self.runtime_context))

        if self.win_provider is not None:
            try:
                rows.extend(build_registry_records(self.win_provider))
            except Exception as exc:
                self.last_provider_error = str(exc)

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
    ) -> List[EnvRecord]:
        rows: List[EnvRecord] = []
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
            except Exception as exc:
                self.last_provider_error = str(exc)

        return rows

    @staticmethod
    def _apply_row_filters(
        rows: List[EnvRecord],
        *,
        source: List[str] | None,
        context: str | None,
    ) -> List[EnvRecord]:
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
        source: List[str] | None = None,
        wsl_path: str | None = None,
        distro: str | None = None,
        scan_depth: int = DEFAULT_SCAN_DEPTH,
        include_raw_secrets: bool = False,
    ) -> List[Dict[str, Any]]:
        root_path = resolve_scan_root(root or Path.cwd())
        rows = self._collect_host_rows(root_path, scan_depth)
        rows.extend(self._collect_wsl_rows(scan_depth=scan_depth, distro=distro, wsl_path=wsl_path))
        rows = self._apply_row_filters(rows, source=source, context=context)
        rows.sort(key=lambda r: (r.name.lower(), r.context, r.source_type, r.source_path))

        payload: List[Dict[str, Any]] = []
        for rec in rows:
            item = rec.to_dict(include_value=True)
            if bool(getattr(rec, "is_secret", False)) and not include_raw_secrets:
                item["value"] = mask_value(rec.value)
            payload.append(item)
        return payload

    def list_records_raw(self, **kwargs: Any) -> List[EnvRecord]:
        payload = self.list_records(include_raw_secrets=True, **kwargs)
        rows: List[EnvRecord] = []
        for item in payload:
            rows.append(EnvRecord(**item))
        return rows

    def resolve_effective(self, key: str, context: str, records: List[EnvRecord]) -> EnvRecord | None:
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
        if self._LINUX_ETC_ENV_PATH != LINUX_ETC_ENV_PATH:
            raise RuntimeError(f"Unexpected /etc/environment resolution: {self._LINUX_ETC_ENV_PATH}")
        path = Path(LINUX_ETC_ENV_PATH)
        try:
            self._write_text_file(path, text, ensure_parent=False)
            return
        except PermissionError:
            pass
        except OSError:
            # Non-POSIX hosts can raise FileNotFoundError for this fixed path; still attempt sudo fallback.
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

    def available_targets(self, records: List[EnvRecord], context: str | None = None) -> List[str]:
        targets: set[str] = set()
        for record in records:
            if context and record.context != context:
                continue
            mapped_target = self._record_target(record)
            if mapped_target:
                targets.add(mapped_target)
        if self.win_provider is not None:
            targets.add(TARGET_WINDOWS_USER)
            targets.add(TARGET_WINDOWS_MACHINE)
        if context == "linux":
            targets.add(TARGET_LINUX_BASHRC)
            targets.add(TARGET_LINUX_ETC_ENV)
        return sorted(targets)

    @staticmethod
    def _powershell_target_for_path(source_path: str) -> str:
        return TARGET_POWERSHELL_ALL_USERS if "Program Files" in source_path else TARGET_POWERSHELL_CURRENT_USER

    @classmethod
    def _record_target(cls, record: EnvRecord) -> str | None:
        static_targets = {
            SOURCE_LINUX_BASHRC: TARGET_LINUX_BASHRC,
            SOURCE_LINUX_ETC_ENV: TARGET_LINUX_ETC_ENV,
        }
        dynamic_targets = {
            SOURCE_DOTENV: lambda rec: f"dotenv:{rec.source_path}",
            SOURCE_WSL_DOTENV: lambda rec: f"wsl_dotenv:{rec.source_path}",
            SOURCE_WSL_BASHRC: lambda rec: f"wsl:{rec.source_id}:bashrc",
            SOURCE_WSL_ETC_ENV: lambda rec: f"wsl:{rec.source_id}:etc_environment",
            SOURCE_POWERSHELL_PROFILE: lambda rec: cls._powershell_target_for_path(rec.source_path),
        }

        static_target = static_targets.get(record.source_type)
        if static_target is not None:
            return static_target
        builder = dynamic_targets.get(record.source_type)
        return builder(record) if builder is not None else None

    def _registry_write(
        self,
        target: str,
        key: str,
        value: str | None,
        action: str,
        *,
        apply_changes: bool,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        if self.win_provider is None:
            raise RuntimeError("Windows registry provider unavailable.")
        scope = WindowsRegistryProvider.USER_SCOPE if target == TARGET_WINDOWS_USER else WindowsRegistryProvider.MACHINE_SCOPE
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
        requires_priv = target == TARGET_WINDOWS_MACHINE
        return before, after, None, requires_priv, None

    def _powershell_profile_path(self, target: str) -> Path:
        current, all_users = self.get_powershell_profile_paths()
        if target == TARGET_POWERSHELL_CURRENT_USER:
            return current
        if target == TARGET_POWERSHELL_ALL_USERS:
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
        scope_roots: List[Path],
    ) -> Tuple[str, str, str | None, bool, str | None]:
        scoped = parse_scoped_dotenv_target(target, roots=scope_roots)
        path = self._validate_path_in_roots(scoped.path, list(scoped.roots), label="dotenv target path")
        before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        after = upsert_key_value(before, key, value or "", quote=False) if action == "set" else remove_key_value(before, key)
        if apply_changes:
            self._write_scoped_text_file(
                candidate_path=scoped.path,
                allowed_roots=scoped.roots,
                text=after,
                label="dotenv target path",
            )
        return before, after, str(path), False, None

    @staticmethod
    def _mutate_shell_content(before: str, *, key: str, value: str | None, action: str, style: str) -> str:
        if action != "set":
            return remove_export(before, key) if style == "export" else remove_key_value(before, key)
        if style == "export":
            return upsert_export(before, key, value or "")
        return upsert_key_value(before, key, value or "", quote=False)

    def _update_linux_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        if target == TARGET_LINUX_BASHRC:
            bashrc_path = Path.home() / ".bashrc"
            before = bashrc_path.read_text(encoding="utf-8", errors="ignore") if bashrc_path.exists() else ""
            after = self._mutate_shell_content(before, key=key, value=value, action=action, style="export")
            if apply_changes:
                bashrc_path.parent.mkdir(parents=True, exist_ok=True)
                bashrc_path.write_text(after, encoding="utf-8")
            return before, after, str(bashrc_path), False, None

        if target == TARGET_LINUX_ETC_ENV:
            etc_path = self._linux_etc_environment_path()
            before = etc_path.read_text(encoding="utf-8", errors="ignore") if etc_path.exists() else ""
            after = self._mutate_shell_content(before, key=key, value=value, action=action, style="key_value")
            if apply_changes:
                self._write_linux_etc_environment_with_privilege(after)
            return before, after, self._LINUX_ETC_ENV_PATH, True, None

        raise RuntimeError(f"Unsupported Linux target: {target}")

    @staticmethod
    def _validate_wsl_distro_name(raw: str) -> str:
        return validate_wsl_distro_name(raw)

    @staticmethod
    def _validate_wsl_dotenv_path(raw: str) -> str:
        return validate_wsl_dotenv_path(raw, path_error=WSL_DOTENV_PATH_ERROR)

    def _parse_wsl_dotenv_target(self, target: str) -> Tuple[str, str]:
        return parse_wsl_dotenv_target(
            target,
            prefix=WSL_DOTENV_TARGET_PREFIX,
            path_error=WSL_DOTENV_PATH_ERROR,
        )

    def _resolve_wsl_target(self, target: str) -> Tuple[str, str, str, bool]:
        return resolve_wsl_target(
            target,
            prefix=WSL_DOTENV_TARGET_PREFIX,
            etc_environment_path=self._LINUX_ETC_ENV_PATH,
            path_error=WSL_DOTENV_PATH_ERROR,
        )


    def _update_wsl_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        distro, path, style, requires_priv = self._resolve_wsl_target(target)
        before = self.wsl.read_file(distro, path)
        after = self._mutate_shell_content(before, key=key, value=value, action=action, style=style)

        if apply_changes:
            writer = self.wsl.write_file_with_privilege if requires_priv else self.wsl.write_file
            writer(distro, path, after)

        return before, after, f"{distro}:{path}", requires_priv, None

    def _update_powershell_file(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        apply_changes: bool,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        profile, allowed_roots, requires_priv = self._powershell_target_path_and_roots(target)
        safe_profile = self._validate_path_in_roots(profile, allowed_roots, label="PowerShell profile path")
        before = safe_profile.read_text(encoding="utf-8", errors="ignore") if safe_profile.exists() else ""
        after = (
            upsert_powershell_env(before, key, value or "")
            if action == "set"
            else remove_powershell_env(before, key)
        )
        if apply_changes:
            self._write_text_file(safe_profile, after, ensure_parent=True)
        return before, after, str(safe_profile), requires_priv, None

    def _file_update(
        self,
        target: str,
        key: str,
        value: str | None,
        action: str,
        *,
        apply_changes: bool,
        scope_roots: List[Path],
    ) -> Tuple[str, str, str | None, bool, str | None]:
        if target.startswith(DOTENV_TARGET_PREFIX):
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
        scope_roots: List[Path],
    ) -> Tuple[str, str, str | None, bool, str | None]:
        if target in {TARGET_WINDOWS_USER, TARGET_WINDOWS_MACHINE}:
            return self._registry_write(target, key, value, action, apply_changes=apply_changes)
        return self._file_update(target, key, value, action, apply_changes=apply_changes, scope_roots=scope_roots)

    def _validate_target_for_operation(self, target: str, *, scope_roots: List[Path]) -> None:
        if target in {
            TARGET_WINDOWS_USER,
            TARGET_WINDOWS_MACHINE,
            TARGET_LINUX_BASHRC,
            TARGET_LINUX_ETC_ENV,
            TARGET_POWERSHELL_CURRENT_USER,
            TARGET_POWERSHELL_ALL_USERS,
        }:
            return
        if target.startswith(DOTENV_TARGET_PREFIX):
            parse_scoped_dotenv_target(target, roots=scope_roots)
            return
        if target.startswith(WSL_DOTENV_TARGET_PREFIX):
            self._parse_wsl_dotenv_target(target)
            return
        if target.startswith("wsl:"):
            self._resolve_wsl_target(target)
            return
        raise RuntimeError(f"Unsupported target: {target}")

    @staticmethod
    def _masked_value(*, secret_operation: bool, value: str | None) -> str | None:
        if not secret_operation or value is None:
            return None
        return mask_value(value)

    @staticmethod
    def _make_operation_result(
        *,
        operation_id: str,
        target: str,
        action: str,
        success: bool,
        backup_path: str | None,
        diff_preview: str,
        error_message: str | None,
        value_masked: str | None,
    ) -> OperationResult:
        return OperationResult(
            operation_id=operation_id,
            target=target,
            action=action,
            success=success,
            backup_path=backup_path,
            diff_preview=diff_preview,
            error_message=error_message,
            value_masked=value_masked,
        )
    @staticmethod
    def _operation_error_types() -> Tuple[Type[BaseException], ...]:
        return (
            RuntimeError,
            ValueError,
            TypeError,
            OSError,
            PermissionError,
            subprocess.SubprocessError,
        )

    def _preview_target_diff(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        resolved_scope_roots: Sequence[Path],
    ) -> Tuple[str, str]:
        self._validate_target_for_operation(target, scope_roots=list(resolved_scope_roots))
        before, after, _, _, _ = self._plan_target_operation(
            target=target,
            key=key,
            value=value,
            action=action,
            apply_changes=False,
            scope_roots=list(resolved_scope_roots),
        )
        return before, self._diff(before, after, target)

    def _apply_target_operation(
        self,
        *,
        target: str,
        key: str,
        value: str | None,
        action: str,
        before: str,
        resolved_scope_roots: Sequence[Path],
    ) -> str:
        backup_path = str(self.backup_mgr.backup_text(target, before))
        self._plan_target_operation(
            target=target,
            key=key,
            value=value,
            action=action,
            apply_changes=True,
            scope_roots=list(resolved_scope_roots),
        )
        return backup_path


    def _operation_result(
        self,
        *,
        operation_id: str,
        target: str,
        action: str,
        success: bool,
        backup_path: str | None,
        preview_only: bool,
        diff_preview: str,
        error_message: str | None,
        value_masked: str | None,
    ) -> OperationResult:
        return self._make_operation_result(
            operation_id=operation_id,
            target=target,
            action=action,
            success=success,
            backup_path=(None if preview_only and success else backup_path),
            diff_preview=diff_preview,
            error_message=error_message,
            value_masked=value_masked,
        )

    def _execute_target_operation(
        self,
        *,
        action: str,
        key: str,
        value: str | None,
        target: str,
        preview_only: bool,
        resolved_scope_roots: Sequence[Path],
        secret_operation: bool,
    ) -> OperationResult:
        operation_id = f"{action}-{uuid.uuid4().hex[:10]}"
        value_masked = self._masked_value(secret_operation=secret_operation, value=value)
        backup_path: str | None = None
        diff_preview = ""
        try:
            before, diff_preview = self._preview_target_diff(target=target, key=key, value=value, action=action, resolved_scope_roots=resolved_scope_roots)
            if not preview_only:
                backup_path = self._apply_target_operation(target=target, key=key, value=value, action=action, before=before, resolved_scope_roots=resolved_scope_roots)
            return self._operation_result(
                operation_id=operation_id,
                target=target,
                action=action,
                success=True,
                backup_path=backup_path,
                preview_only=preview_only,
                diff_preview=diff_preview,
                error_message=None,
                value_masked=value_masked,
            )
        except self._operation_error_types() as exc:
            return self._operation_result(
                operation_id=operation_id,
                target=target,
                action=action,
                success=False,
                backup_path=backup_path,
                preview_only=False,
                diff_preview=diff_preview,
                error_message=str(exc),
                value_masked=value_masked,
            )

    def _apply(
        self,
        action: str,
        *,
        key: str,
        value: str | None,
        targets: List[str],
        preview_only: bool = False,
        scope_roots: List[str | Path] | None = None,
    ) -> List[OperationResult]:
        validate_env_key(key)
        if action == "set":
            validate_env_value(value or "")

        secret_operation = looks_secret(key, value or "")
        resolved_scope_roots = self._effective_scope_roots(scope_roots)
        results: List[OperationResult] = []
        for target in targets:
            result = self._execute_target_operation(
                action=action,
                key=key,
                value=value,
                target=target,
                preview_only=preview_only,
                resolved_scope_roots=resolved_scope_roots,
                secret_operation=secret_operation,
            )
            self.audit.log(self._audit_safe_result(result, redact=secret_operation))
            results.append(result)
        return results

    @staticmethod
    def _audit_safe_result(result: OperationResult, *, redact: bool) -> OperationResult:
        if not redact:
            return result
        return OperationResult(
            operation_id=result.operation_id,
            target=result.target,
            action=result.action,
            success=result.success,
            backup_path=result.backup_path,
            diff_preview="[secret diff masked]",
            error_message=result.error_message,
            value_masked=result.value_masked,
        )

    def preview_set(
        self,
        *,
        key: str,
        value: str,
        targets: List[str],
        scope_roots: List[str | Path] | None = None,
    ) -> List[Dict[str, Any]]:
        return [
            r.to_dict()
            for r in self._apply("set", key=key, value=value, targets=targets, preview_only=True, scope_roots=scope_roots)
        ]

    def preview_remove(
        self,
        *,
        key: str,
        targets: List[str],
        scope_roots: List[str | Path] | None = None,
    ) -> List[Dict[str, Any]]:
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
        targets: List[str],
        scope_roots: List[str | Path] | None = None,
    ) -> Dict[str, Any]:
        results = self._apply("set", key=key, value=value, targets=targets, preview_only=False, scope_roots=scope_roots)
        if len(results) == 1:
            return results[0].to_dict()
        return {"success": all(r.success for r in results), "results": [r.to_dict() for r in results]}

    def remove_key(
        self,
        *,
        key: str,
        targets: List[str],
        scope_roots: List[str | Path] | None = None,
    ) -> Dict[str, Any]:
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







