from __future__ import absolute_import, division

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
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
from .secrets import looks_secret
from .service_listing import (
    HostCollectionRequest,
    HostRowCollectors,
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
    masked_value as _masked_value_helper,
    OperationResultInput,
    operation_error_types as _operation_error_types_helper,
    operation_result as _operation_result_helper,
    normalize_target_operation_batch as _normalize_target_operation_batch_helper,
    normalize_target_operation_request as _normalize_target_operation_request_helper,
)
from .service_privileged import (
    run as _privileged_run,
    which as _privileged_which,
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
from . import service_aliases as _service_aliases
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
which = _privileged_which
run = _privileged_run


def _path_exists(path: Path) -> bool:
    return os.path.exists(path)


def _read_text_if_exists(path: Path) -> str:
    if not _path_exists(path):
        return ""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return handle.read()


@dataclass(frozen=True)
class TargetOperationRequest:
    target: str
    key: str
    value: str | None
    action: str
    scope_roots: Sequence[Path]


@dataclass(frozen=True)
class TargetOperationBatch:
    action: str
    key: str
    value: str | None
    targets: List[str]
    scope_roots: List[str | Path] | None = None


@dataclass(frozen=True)
class ListRecordsRequest:
    root: str | Path | None = None
    context: str | None = None
    source: List[str] | None = None
    wsl_path: str | None = None
    distro: str | None = None
    scan_depth: int = DEFAULT_SCAN_DEPTH
    include_raw_secrets: bool = False


@dataclass(frozen=True)
class ShellMutationRequest:
    key: str
    value: str | None
    action: str
    style: str


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
            except RuntimeError:
                self.win_provider = None

    def _effective_scope_roots(self, scope_roots: List[str | Path] | None = None) -> List[Path]:
        roots: List[Path] = list(self.default_scope_roots)
        if scope_roots:
            roots.extend(normalize_scope_roots(scope_roots))
        return normalize_scope_roots(roots)

    def resolve_effective(self, key: str, context: str, records: List[EnvRecord]) -> EnvRecord | None:
        return resolve_effective_value(records, key, context)











    def _collect_host_rows(self, root_path: Path, scan_depth: int) -> List[EnvRecord]:
        return _collect_host_rows_helper(
            request=HostCollectionRequest(
                runtime_context=self.runtime_context,
                root_path=root_path,
                scan_depth=scan_depth,
                win_provider=self.win_provider,
                powershell_profile_paths=self.get_powershell_profile_paths(),
            ),
            collectors=HostRowCollectors(
                collect_process_records_fn=collect_process_records,
                collect_dotenv_records_fn=collect_dotenv_records,
                build_registry_records_fn=build_registry_records,
                collect_powershell_profile_records_fn=collect_powershell_profile_records,
                collect_linux_records_fn=collect_linux_records,
            ),
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


    def list_records(
        self,
        request: ListRecordsRequest | None = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if request is None:
            request = ListRecordsRequest(**kwargs)
        elif kwargs:
            raise TypeError("Pass either a ListRecordsRequest or keyword arguments, not both.")

        root_path = resolve_scan_root(request.root or Path.cwd())
        rows = self._collect_host_rows(root_path, request.scan_depth)
        rows.extend(
            self._collect_wsl_rows(scan_depth=request.scan_depth, distro=request.distro, wsl_path=request.wsl_path)
        )
        rows = self._apply_row_filters(rows, source=request.source, context=request.context)
        rows.sort(key=lambda r: (r.name.lower(), r.context, r.source_type, r.source_path))

        return _rows_to_payload_helper(rows, include_raw_secrets=request.include_raw_secrets)









    def _powershell_profile_path(self, target: str) -> Path:
        current, all_users = self.get_powershell_profile_paths()
        if target == TARGET_POWERSHELL_CURRENT_USER:
            return current
        if target == TARGET_POWERSHELL_ALL_USERS:
            return all_users
        raise RuntimeError(f"Unsupported PowerShell target: {target}")

    def _update_dotenv_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        scoped = parse_scoped_dotenv_target(request.target, roots=list(request.scope_roots))
        path = self._validate_path_in_roots(scoped.path, list(scoped.roots), label="dotenv target path")
        before = _read_text_if_exists(path)
        after = (
            upsert_key_value(before, request.key, request.value or "", quote=False)
            if request.action == "set"
            else remove_key_value(before, request.key)
        )
        if apply_changes:
            self._write_scoped_text_file(
                candidate_path=scoped.path,
                allowed_roots=scoped.roots,
                text=after,
                label="dotenv target path",
            )
        return before, after, str(path), False, None

    def _mutate_shell_content(self, before: str, request: ShellMutationRequest) -> str:
        if request.action != "set":
            return remove_export(before, request.key) if request.style == "export" else remove_key_value(before, request.key)
        if request.style == "export":
            return upsert_export(before, request.key, request.value or "")
        return upsert_key_value(before, request.key, request.value or "", quote=False)

    def _update_linux_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        if request.target == TARGET_LINUX_BASHRC:
            bashrc_path = Path.home() / ".bashrc"
            before = _read_text_if_exists(bashrc_path)
            after = self._mutate_shell_content(before, ShellMutationRequest(request.key, request.value, request.action, "export"))
            if apply_changes:
                self._write_text_file(bashrc_path, after, ensure_parent=True)
            return before, after, str(bashrc_path), False, None

        if request.target == TARGET_LINUX_ETC_ENV:
            etc_path = self._linux_etc_environment_path()
            before = _read_text_if_exists(etc_path)
            after = self._mutate_shell_content(
                before,
                ShellMutationRequest(request.key, request.value, request.action, "key_value"),
            )
            if apply_changes:
                self._write_linux_etc_environment_with_privilege(after)
            return before, after, self._LINUX_ETC_ENV_PATH, True, None

        raise RuntimeError(f"Unsupported Linux target: {request.target}")

    def _write_linux_etc_environment_with_privilege(self, text: str) -> None:
        _write_linux_etc_environment_with_privilege_helper(
            fixed_path=LINUX_ETC_ENV_PATH,
            expected_path=self._LINUX_ETC_ENV_PATH,
            text=text,
            write_text_file=lambda path, payload: self._write_text_file(path, payload, ensure_parent=False),
            which_fn=which,
            run_fn=run,
        )



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
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        distro, path, style, requires_priv = self._resolve_wsl_target(request.target)
        before = self.wsl.read_file(distro, path)
        after = self._mutate_shell_content(before, ShellMutationRequest(request.key, request.value, request.action, style))

        if apply_changes:
            writer = self.wsl.write_file_with_privilege if requires_priv else self.wsl.write_file
            writer(distro, path, after)

        return before, after, f"{distro}:{path}", requires_priv, None

    def _update_powershell_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        profile, allowed_roots, requires_priv = self._powershell_target_path_and_roots(request.target)
        safe_profile = self._validate_path_in_roots(profile, allowed_roots, label="PowerShell profile path")
        before = _read_text_if_exists(safe_profile)
        after = (
            upsert_powershell_env(before, request.key, request.value or "")
            if request.action == "set"
            else remove_powershell_env(before, request.key)
        )
        if apply_changes:
            self._write_text_file(safe_profile, after, ensure_parent=True)
        return before, after, str(safe_profile), requires_priv, None

    def _file_update(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        if request.target.startswith(DOTENV_TARGET_PREFIX):
            return self._update_dotenv_file(request=request, apply_changes=apply_changes)
        if request.target.startswith("linux:"):
            return self._update_linux_file(request=request, apply_changes=apply_changes)
        if request.target.startswith("wsl"):
            return self._update_wsl_file(request=request, apply_changes=apply_changes)
        if request.target.startswith("powershell:"):
            return self._update_powershell_file(request=request, apply_changes=apply_changes)
        raise RuntimeError(f"Unsupported target: {request.target}")

    def _plan_target_operation(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Tuple[str, str, str | None, bool, str | None]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        if request.target in {TARGET_WINDOWS_USER, TARGET_WINDOWS_MACHINE}:
            return self._registry_write(request=request, apply_changes=apply_changes)
        return self._file_update(request=request, apply_changes=apply_changes)

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



    def _preview_target_diff(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Tuple[str, str]:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        self._validate_target_for_operation(request.target, scope_roots=list(request.scope_roots))
        before, after, _, _, _ = self._plan_target_operation(request=request, apply_changes=False)
        return before, self._diff(before, after, request.target)

    def _apply_target_operation(
        self,
        *args: Any,
        before: str,
        **kwargs: Any,
    ) -> str:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        backup_path = str(self.backup_mgr.backup_text(request.target, before))
        self._plan_target_operation(request=request, apply_changes=True)
        return backup_path


    def _execute_target_operation(
        self,
        *args: Any,
        preview_only: bool,
        secret_operation: bool,
        **kwargs: Any,
    ) -> OperationResult:
        request_data = _normalize_target_operation_request_helper(*args, **kwargs)
        request = TargetOperationRequest(
            target=request_data["target"],
            key=request_data["key"],
            value=request_data["value"],
            action=request_data["action"],
            scope_roots=request_data["scope_roots"],
        )
        operation_id = f"{request.action}-{uuid.uuid4().hex[:10]}"
        value_masked = self._masked_value(secret_operation=secret_operation, value=request.value)
        backup_path: str | None = None
        diff_preview = ""
        try:
            before, diff_preview = self._preview_target_diff(request)
            if not preview_only:
                backup_path = self._apply_target_operation(request, before=before)
            return _operation_result_helper(
                OperationResultInput(
                    operation_id=operation_id,
                    target=request.target,
                    action=request.action,
                    success=True,
                    backup_path=backup_path,
                    preview_only=preview_only,
                    diff_preview=diff_preview,
                    error_message=None,
                    value_masked=value_masked,
                )
            )
        except self._operation_error_types() as exc:
            return _operation_result_helper(
                OperationResultInput(
                    operation_id=operation_id,
                    target=request.target,
                    action=request.action,
                    success=False,
                    backup_path=backup_path,
                    preview_only=False,
                    diff_preview=diff_preview,
                    error_message=str(exc),
                    value_masked=value_masked,
                )
            )

    def _apply(
        self,
        *args: Any,
        preview_only: bool = False,
        **kwargs: Any,
    ) -> List[OperationResult]:
        request_data = _normalize_target_operation_batch_helper(*args, **kwargs)
        request = TargetOperationBatch(
            action=request_data["action"],
            key=request_data["key"],
            value=request_data["value"],
            targets=request_data["targets"],
            scope_roots=request_data["scope_roots"],
        )
        validate_env_key(request.key)
        if request.action == "set":
            validate_env_value(request.value or "")

        secret_operation = looks_secret(request.key, request.value or "")
        resolved_scope_roots = self._effective_scope_roots(request.scope_roots)
        results: List[OperationResult] = []
        for target in request.targets:
            target_request = TargetOperationRequest(
                target=target,
                key=request.key,
                value=request.value,
                action=request.action,
                scope_roots=resolved_scope_roots,
            )
            result = self._execute_target_operation(
                target_request,
                preview_only=preview_only,
                secret_operation=secret_operation,
            )
            self.audit.log(audit_safe_result(result, redact=secret_operation))
            results.append(result)
        return results







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
        except (RuntimeError, ValueError, TypeError, OSError, KeyError) as exc:
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

EnvInspectorService.which = which
EnvInspectorService.run = run
EnvInspectorService.get_powershell_profile_paths = staticmethod(_service_aliases.get_powershell_profile_paths)
EnvInspectorService._registry_write = _service_aliases.registry_write
EnvInspectorService._bridge_distros = _service_aliases.bridge_distros
EnvInspectorService.list_contexts = _service_aliases.list_contexts
EnvInspectorService._is_path_within = staticmethod(_is_path_within)
EnvInspectorService._validate_path_in_roots = staticmethod(_validate_path_in_roots)
EnvInspectorService._write_text_file = staticmethod(_write_text_file)
EnvInspectorService._write_scoped_text_file = staticmethod(_write_scoped_text_file)
EnvInspectorService._powershell_target_path_and_roots = _service_aliases.powershell_target_path_and_roots
EnvInspectorService._validated_powershell_restore_path = _service_aliases.validated_powershell_restore_path
EnvInspectorService._linux_etc_environment_path = classmethod(_service_aliases.linux_etc_environment_path)
EnvInspectorService._apply_row_filters = staticmethod(_apply_row_filters_helper)
EnvInspectorService._diff = staticmethod(_diff_text_helper)
EnvInspectorService.available_targets = _service_aliases.available_targets
EnvInspectorService._powershell_target_for_path = staticmethod(_powershell_target_for_path_helper)
EnvInspectorService._record_target = staticmethod(_record_target_helper)
EnvInspectorService._masked_value = staticmethod(_masked_value_helper)
EnvInspectorService._operation_error_types = staticmethod(_operation_error_types_helper)
EnvInspectorService._validate_wsl_distro_name = staticmethod(_validate_wsl_distro_name_helper)
EnvInspectorService._validate_wsl_dotenv_path = staticmethod(_service_aliases.validate_wsl_dotenv_path)
EnvInspectorService.list_records_raw = _service_aliases.list_records_raw
EnvInspectorService.preview_set = _service_aliases.preview_set
EnvInspectorService.preview_remove = _service_aliases.preview_remove
EnvInspectorService.set_key = _service_aliases.set_key
EnvInspectorService.remove_key = _service_aliases.remove_key
EnvInspectorService.export_records = _service_aliases.export_records
EnvInspectorService.list_backups = _service_aliases.list_backups
