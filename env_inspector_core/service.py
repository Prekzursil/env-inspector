from __future__ import absolute_import, division

import json
import uuid
from pathlib import Path
from shutil import which
from subprocess import run
from typing import Any, Dict, List, Sequence, Tuple, Type

from .constants import (
    DEFAULT_BACKUP_RETENTION,
    DEFAULT_SCAN_DEPTH,
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
    build_registry_records,
    collect_dotenv_records,
    collect_linux_records,
    collect_powershell_profile_records,
    collect_process_records,
    collect_wsl_dotenv_records,
    collect_wsl_records,
    current_wsl_distro_name,
    get_runtime_context,
    is_windows,
)
from .rendering import audit_safe_result, export_rows
from .resolver import resolve_effective_value
from .secrets import looks_secret, mask_value
from .service_listing import (
    apply_row_filters as _apply_row_filters_helper,
    available_targets as _available_targets_helper,
    collect_host_rows as _collect_host_rows_helper,
    collect_wsl_rows as _collect_wsl_rows_helper,
    powershell_target_for_path as _powershell_target_for_path_helper,
    record_target as _record_target_helper,
    rows_to_payload as _rows_to_payload_helper,
)
from .service_ops import (
    diff_text as _diff_text_helper,
    make_operation_result as _make_operation_result_helper,
    masked_value as _masked_value_helper,
    operation_error_types as _operation_error_types_helper,
    operation_result as _operation_result_helper,
)
from .service_privileged import (
    write_linux_etc_environment_with_privilege as _write_linux_etc_environment_with_privilege_helper,
)
from .service_restore import (
    restore_dotenv_target as _restore_dotenv_target_helper,
    restore_linux_target as _restore_linux_target_helper,
    restore_powershell_target as _restore_powershell_target_helper,
    restore_target as _restore_target_helper,
    restore_windows_registry_target as _restore_windows_registry_target_helper,
    restore_wsl_target as _restore_wsl_target_helper,
)
from .service_wsl import (
    parse_wsl_dotenv_target as _parse_wsl_dotenv_target_helper,
    resolve_wsl_target as _resolve_wsl_target_helper,
    validate_wsl_distro_name as _validate_wsl_distro_name_helper,
    validate_wsl_dotenv_path as _validate_wsl_dotenv_path_helper,
)
from .service_paths import (
    get_powershell_profile_paths as _get_powershell_profile_paths,
    is_path_within as _is_path_within,
    linux_etc_environment_path as _linux_etc_environment_path,
    powershell_target_path_and_roots as _powershell_target_path_and_roots,
    validate_path_in_roots as _validate_path_in_roots,
    validated_powershell_restore_path as _validated_powershell_restore_path,
    write_scoped_text_file as _write_scoped_text_file,
    write_text_file as _write_text_file,
)
from .storage import AuditLogger, BackupManager

TARGET_WINDOWS_USER = "windows:user"
TARGET_WINDOWS_MACHINE = "windows:machine"
TARGET_LINUX_BASHRC = "linux:bashrc"
TARGET_LINUX_ETC_ENV = "linux:etc_environment"
TARGET_POWERSHELL_CURRENT_USER = "powershell:current_user"
TARGET_POWERSHELL_ALL_USERS = "powershell:all_users"
DOTENV_TARGET_PREFIX = "dotenv:"
WSL_DOTENV_TARGET_PREFIX = "wsl_dotenv:"
WSL_DOTENV_PATH_ERROR = "Unsupported WSL dotenv target path"
LINUX_ETC_ENV_PATH = "/etc/environment"


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

    def _effective_scope_roots(self, scope_roots: List[str | Path] | None = None) -> List[Path]:
        roots: List[Path] = list(self.default_scope_roots)
        if scope_roots:
            roots.extend(normalize_scope_roots(scope_roots))
        return normalize_scope_roots(roots)

    @staticmethod
    def get_powershell_profile_paths() -> List[Path]:
        return _get_powershell_profile_paths()

    @staticmethod
    def _is_path_within(path: Path, root: Path) -> bool:
        return _is_path_within(path, root)

    @classmethod
    def _validate_path_in_roots(cls, path: Path, roots: Sequence[Path], *, label: str) -> Path:
        return _validate_path_in_roots(path, roots, label=label)

    @staticmethod
    def _write_text_file(path: Path, text: str, *, ensure_parent: bool) -> None:
        _write_text_file(path, text, ensure_parent=ensure_parent)

    def _write_scoped_text_file(
        self,
        *,
        candidate_path: Path,
        allowed_roots: Sequence[Path],
        text: str,
        label: str,
    ) -> Path:
        return _write_scoped_text_file(
            candidate_path=candidate_path,
            allowed_roots=allowed_roots,
            text=text,
            label=label,
        )

    def _powershell_target_path_and_roots(self, target: str) -> Tuple[Path, List[Path], bool]:
        return _powershell_target_path_and_roots(
            target,
            profile_resolver=self._powershell_profile_path,
            current_user_target=TARGET_POWERSHELL_CURRENT_USER,
            all_users_target=TARGET_POWERSHELL_ALL_USERS,
        )

    def _validated_powershell_restore_path(self, target: str) -> Path:
        return _validated_powershell_restore_path(
            target,
            profile_resolver=self._powershell_profile_path,
            current_user_target=TARGET_POWERSHELL_CURRENT_USER,
            all_users_target=TARGET_POWERSHELL_ALL_USERS,
        )

    @classmethod
    def _linux_etc_environment_path(cls) -> Path:
        return _linux_etc_environment_path(cls._LINUX_ETC_ENV_PATH)

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
        return _collect_host_rows_helper(
            runtime_context=self.runtime_context,
            root_path=root_path,
            scan_depth=scan_depth,
            win_provider=self.win_provider,
            powershell_profile_paths=self.get_powershell_profile_paths(),
            collect_process_records_fn=collect_process_records,
            collect_dotenv_records_fn=collect_dotenv_records,
            build_registry_records_fn=build_registry_records,
            collect_powershell_profile_records_fn=collect_powershell_profile_records,
            collect_linux_records_fn=collect_linux_records,
        )

    def _collect_wsl_rows(
        self,
        *,
        scan_depth: int,
        distro: str | None,
        wsl_path: str | None,
    ) -> List[EnvRecord]:
        return _collect_wsl_rows_helper(
            runtime_context=self.runtime_context,
            current_wsl_distro=self.current_wsl_distro,
            wsl=self.wsl,
            scan_depth=scan_depth,
            distro=distro,
            wsl_path=wsl_path,
            collect_wsl_records_fn=collect_wsl_records,
            collect_wsl_dotenv_records_fn=collect_wsl_dotenv_records,
        )

    @staticmethod
    def _apply_row_filters(
        rows: List[EnvRecord],
        *,
        source: List[str] | None,
        context: str | None,
    ) -> List[EnvRecord]:
        return _apply_row_filters_helper(rows, source=source, context=context)

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

        return _rows_to_payload_helper(rows, include_raw_secrets=include_raw_secrets)

    def list_records_raw(self, **kwargs: Any) -> List[EnvRecord]:
        payload = self.list_records(include_raw_secrets=True, **kwargs)
        return [EnvRecord(**item) for item in payload]

    def resolve_effective(self, key: str, context: str, records: List[EnvRecord]) -> EnvRecord | None:
        return resolve_effective_value(records, key, context)

    @staticmethod
    def _diff(before: str, after: str, target: str) -> str:
        return _diff_text_helper(before, after, target)

    def _write_linux_etc_environment_with_privilege(self, text: str) -> None:
        _write_linux_etc_environment_with_privilege_helper(
            fixed_path=self._LINUX_ETC_ENV_PATH,
            expected_path=LINUX_ETC_ENV_PATH,
            text=text,
            write_text_file=lambda path, payload: self._write_text_file(path, payload, ensure_parent=False),
            which_fn=which,
            run_fn=run,
        )

    def available_targets(self, records: List[EnvRecord], context: str | None = None) -> List[str]:
        return _available_targets_helper(
            records,
            context=context,
            win_provider_present=self.win_provider is not None,
        )

    @staticmethod
    def _powershell_target_for_path(source_path: str) -> str:
        return _powershell_target_for_path_helper(source_path)

    @classmethod
    def _record_target(cls, record: EnvRecord) -> str | None:
        return _record_target_helper(record)

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
        return _validate_wsl_distro_name_helper(raw)

    @staticmethod
    def _validate_wsl_dotenv_path(raw: str) -> str:
        return _validate_wsl_dotenv_path_helper(raw, path_error=WSL_DOTENV_PATH_ERROR)

    def _parse_wsl_dotenv_target(self, target: str) -> Tuple[str, str]:
        return _parse_wsl_dotenv_target_helper(
            target,
            prefix=WSL_DOTENV_TARGET_PREFIX,
            validate_distro_name_fn=self._validate_wsl_distro_name,
            validate_dotenv_path_fn=self._validate_wsl_dotenv_path,
        )

    def _resolve_wsl_target(self, target: str) -> Tuple[str, str, str, bool]:
        return _resolve_wsl_target_helper(
            target,
            dotenv_prefix=WSL_DOTENV_TARGET_PREFIX,
            validate_distro_name_fn=self._validate_wsl_distro_name,
            parse_wsl_dotenv_target_fn=self._parse_wsl_dotenv_target,
            linux_etc_env_path=self._LINUX_ETC_ENV_PATH,
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
        return _masked_value_helper(secret_operation=secret_operation, value=value)

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
        return _make_operation_result_helper(
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
        return _operation_error_types_helper()

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
        return _operation_result_helper(
            operation_id=operation_id,
            target=target,
            action=action,
            success=success,
            backup_path=backup_path,
            preview_only=preview_only,
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
            self.audit.log(audit_safe_result(result, redact=secret_operation))
            results.append(result)
        return results

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
        return export_rows(rows, output=output)

    def list_backups(self, *, target: str | None = None) -> List[str]:
        if target:
            return [str(p) for p in self.backup_mgr.list_backups(target)]
        return [str(p) for p in self.backup_mgr.list_all_backups()]

    def _restore_dotenv_target(self, *, target: str, text: str, scope_roots: List[Path]) -> None:
        _restore_dotenv_target_helper(
            target=target,
            text=text,
            scope_roots=scope_roots,
            parse_scoped_dotenv_target_fn=parse_scoped_dotenv_target,
            write_scoped_text_file_fn=self._write_scoped_text_file,
        )

    def _restore_linux_target(self, *, target: str, text: str) -> None:
        _restore_linux_target_helper(
            target=target,
            text=text,
            write_linux_etc_environment_with_privilege_fn=self._write_linux_etc_environment_with_privilege,
        )

    def _restore_wsl_target(self, *, target: str, text: str) -> None:
        _restore_wsl_target_helper(
            target=target,
            text=text,
            wsl=self.wsl,
            parse_wsl_dotenv_target_fn=self._parse_wsl_dotenv_target,
            validate_wsl_distro_name_fn=self._validate_wsl_distro_name,
            linux_etc_env_path=self._LINUX_ETC_ENV_PATH,
        )

    def _restore_powershell_target(self, *, target: str, text: str) -> None:
        _restore_powershell_target_helper(
            target=target,
            text=text,
            validated_powershell_restore_path_fn=self._validated_powershell_restore_path,
            write_text_file_fn=lambda path, content: self._write_text_file(path, content, ensure_parent=True),
        )

    def _restore_windows_registry_target(self, *, target: str, text: str) -> None:
        _restore_windows_registry_target_helper(
            target=target,
            text=text,
            win_provider=self.win_provider,
            windows_registry_provider_cls=WindowsRegistryProvider,
        )

    def _restore_target(self, *, target: str, text: str, scope_roots: List[Path]) -> None:
        _restore_target_helper(
            target=target,
            text=text,
            scope_roots=scope_roots,
            restore_dotenv_target_fn=self._restore_dotenv_target,
            restore_linux_target_fn=self._restore_linux_target,
            restore_wsl_target_fn=self._restore_wsl_target,
            restore_powershell_target_fn=self._restore_powershell_target,
            restore_windows_registry_target_fn=self._restore_windows_registry_target,
        )

    def restore_backup(
        self,
        *,
        backup: str,
        scope_roots: List[str | Path] | None = None,
    ) -> Dict[str, Any]:
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
