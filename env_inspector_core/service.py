"""Primary Env Inspector service implementation."""

from __future__ import absolute_import, division

import uuid
from pathlib import Path
from typing import Any, Dict, List

from . import service_aliases as _service_aliases
from . import service_mutations as _service_mutations
from .constants import DEFAULT_BACKUP_RETENTION
from .models import EnvRecord, OperationResult
from .path_policy import normalize_scope_roots, parse_scoped_dotenv_target, resolve_scan_root, validate_backup_path
from .providers import (
    WindowsRegistryProvider, WslProvider, build_registry_records, collect_dotenv_records,
    collect_linux_records, collect_powershell_profile_records, collect_process_records,
    collect_wsl_dotenv_records, collect_wsl_records, current_wsl_distro_name,
    get_runtime_context, is_windows,
)
from .rendering import audit_safe_result
from .resolver import resolve_effective_value
from .service_listing import (
    HostCollectionRequest, HostRowCollectors, apply_row_filters as _apply_row_filters_helper,
    collect_host_rows as _collect_host_rows_helper, collect_wsl_rows as _collect_wsl_rows_helper,
    powershell_target_for_path as _powershell_target_for_path_helper,
    record_target as _record_target_helper, rows_to_payload as _rows_to_payload_helper,
)
from .service_ops import diff_text as _diff_text_helper, masked_value as _masked_value_helper, operation_error_types as _operation_error_types_helper
from .service_paths import (
    is_path_within as _is_path_within, validate_path_in_roots as _validate_path_in_roots,
    write_scoped_text_file as _write_scoped_text_file, write_text_file as _write_text_file,
)
from .service_privileged import run as _privileged_run, which as _privileged_which
from .service_restore import (
    restore_dotenv_target as _restore_dotenv_target_helper, restore_linux_target as _restore_linux_target_helper,
    restore_powershell_target as _restore_powershell_target_helper, restore_target as _restore_target_helper,
    restore_windows_registry_target as _restore_windows_registry_target_helper, restore_wsl_target as _restore_wsl_target_helper,
)
from .service_wsl import validate_wsl_distro_name as _validate_wsl_distro_name_helper
from .service_models import ListRecordsRequest, ShellMutationRequest, TargetOperationBatch, TargetOperationRequest
from .storage import AuditLogger, BackupManager

DOTENV_TARGET_PREFIX = _service_mutations.DOTENV_TARGET_PREFIX
LINUX_ETC_ENV_PATH = _service_mutations.LINUX_ETC_ENV_PATH
TARGET_LINUX_BASHRC = _service_mutations.TARGET_LINUX_BASHRC
TARGET_LINUX_ETC_ENV = _service_mutations.TARGET_LINUX_ETC_ENV
TARGET_POWERSHELL_ALL_USERS = _service_mutations.TARGET_POWERSHELL_ALL_USERS
TARGET_POWERSHELL_CURRENT_USER = _service_mutations.TARGET_POWERSHELL_CURRENT_USER
TARGET_WINDOWS_MACHINE = _service_mutations.TARGET_WINDOWS_MACHINE
TARGET_WINDOWS_USER = _service_mutations.TARGET_WINDOWS_USER
WSL_DOTENV_TARGET_PREFIX = _service_mutations.WSL_DOTENV_TARGET_PREFIX
which = _privileged_which
run = _privileged_run

__all__ = [
    "DOTENV_TARGET_PREFIX", "EnvInspectorService", "LINUX_ETC_ENV_PATH", "ListRecordsRequest",
    "ShellMutationRequest", "TARGET_LINUX_BASHRC", "TARGET_LINUX_ETC_ENV",
    "TARGET_POWERSHELL_ALL_USERS", "TARGET_POWERSHELL_CURRENT_USER", "TARGET_WINDOWS_MACHINE",
    "TARGET_WINDOWS_USER", "TargetOperationBatch", "TargetOperationRequest",
    "WSL_DOTENV_TARGET_PREFIX", "run", "which",
]


def _path_exists(path: Path) -> bool:
    """Return whether a path exists."""
    return path.exists()


def _read_text_if_exists(path: Path) -> str:
    """Read a UTF-8 file if it exists, otherwise return an empty string."""
    if not _path_exists(path):
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


class EnvInspectorService:
    """Collect, mutate, and restore environment-variable sources."""

    _LINUX_ETC_ENV_PATH = LINUX_ETC_ENV_PATH
    get_powershell_profile_paths = staticmethod(
        _service_aliases.get_powershell_profile_paths
    )
    _registry_write = _service_aliases.registry_write
    _bridge_distros = _service_aliases.bridge_distros
    list_contexts = _service_aliases.list_contexts
    _validate_path_in_roots = staticmethod(_validate_path_in_roots)
    _write_text_file = staticmethod(_write_text_file)
    _write_scoped_text_file = staticmethod(_write_scoped_text_file)
    _powershell_target_path_and_roots = (
        _service_aliases.powershell_target_path_and_roots
    )
    _validated_powershell_restore_path = (
        _service_aliases.validated_powershell_restore_path
    )
    _apply_row_filters = staticmethod(_apply_row_filters_helper)
    _diff = staticmethod(_diff_text_helper)
    available_targets = _service_aliases.available_targets
    _powershell_target_for_path = staticmethod(_powershell_target_for_path_helper)
    _record_target = staticmethod(_record_target_helper)
    _masked_value = staticmethod(_masked_value_helper)
    _operation_error_types = staticmethod(_operation_error_types_helper)
    _validate_wsl_distro_name = staticmethod(_validate_wsl_distro_name_helper)
    _validate_wsl_dotenv_path = staticmethod(_service_aliases.validate_wsl_dotenv_path)
    list_records_raw = _service_aliases.list_records_raw
    preview_set = _service_aliases.preview_set
    preview_remove = _service_aliases.preview_remove
    set_key = _service_aliases.set_key
    remove_key = _service_aliases.remove_key
    export_records = _service_aliases.export_records
    list_backups = _service_aliases.list_backups
    _powershell_profile_path = _service_mutations.powershell_profile_path
    _update_dotenv_file = _service_mutations.update_dotenv_file
    _mutate_shell_content = staticmethod(_service_mutations.mutate_shell_content)
    _update_linux_file = _service_mutations.update_linux_file
    _write_linux_etc_environment_with_privilege = (
        _service_mutations.write_linux_etc_environment_with_privilege
    )
    _parse_wsl_dotenv_target = _service_mutations.parse_wsl_dotenv_target
    _resolve_wsl_target = _service_mutations.resolve_wsl_target
    _update_wsl_file = _service_mutations.update_wsl_file
    _update_powershell_file = _service_mutations.update_powershell_file
    _file_update = _service_mutations.file_update
    _plan_target_operation = _service_mutations.plan_target_operation
    _validate_target_for_operation = _service_mutations.validate_target_for_operation
    _preview_target_diff = _service_mutations.preview_target_diff
    _apply_target_operation = _service_mutations.apply_target_operation
    _execute_target_operation = _service_mutations.execute_target_operation
    _apply = _service_mutations.apply
    _audit_safe_result = staticmethod(audit_safe_result)

    @staticmethod
    def which(name: str) -> str | None:
        """Resolve a binary path through the mutable module seam."""
        return which(name)

    @staticmethod
    def run(*args: Any, **kwargs: Any) -> Any:
        """Invoke the subprocess runner through the mutable module seam."""
        call_kwargs = dict(kwargs)
        check = call_kwargs.pop("check", False)
        return run(*args, check=check, **call_kwargs)

    @staticmethod
    def _read_text_if_exists(path: Path) -> str:
        """Read text through the mutable module seam."""
        return _read_text_if_exists(path)

    @staticmethod
    def _is_path_within(path: Path, root: Path) -> bool:
        """Check whether a path is contained within an approved root."""
        return _is_path_within(path, root)

    @classmethod
    def _linux_etc_environment_path(cls) -> Path:
        """Resolve `/etc/environment` through the class seam."""
        return _service_aliases.linux_etc_environment_path(cls)

    def bridge_distros(self) -> List[str]:
        """Return available WSL bridge distros."""
        return self._bridge_distros()

    def powershell_profile_path(self, target: str) -> Path:
        """Resolve a PowerShell target through the bound helper."""
        return self._powershell_profile_path(target)

    def validate_path_in_roots(
        self,
        path: Path,
        roots: List[Path],
        *,
        label: str,
    ) -> Path:
        """Validate a path against approved roots through the seam."""
        return self._validate_path_in_roots(path, roots, label=label)

    def write_text_file(self, path: Path, text: str, *, ensure_parent: bool) -> None:
        """Write text through the mutable file seam."""
        self._write_text_file(path, text, ensure_parent=ensure_parent)

    def write_scoped_text_file(
        self,
        *,
        candidate_path: Path,
        allowed_roots: List[Path],
        text: str,
        label: str,
    ) -> Path:
        """Write a scoped text file through the mutable file seam."""
        return self._write_scoped_text_file(
            candidate_path=candidate_path,
            allowed_roots=allowed_roots,
            text=text,
            label=label,
        )

    def read_text_if_exists(self, path: Path) -> str:
        """Read text through the mutable file seam."""
        return self._read_text_if_exists(path)

    @classmethod
    def linux_etc_environment_path(cls) -> Path:
        """Resolve `/etc/environment` through the public bridge."""
        return cls._linux_etc_environment_path()

    @classmethod
    def linux_etc_environment_value(cls) -> str:
        """Return the canonical `/etc/environment` path string."""
        return cls._LINUX_ETC_ENV_PATH

    def powershell_target_path_and_roots(self, target: str) -> Any:
        """Resolve a PowerShell target and its allowed roots."""
        return self._powershell_target_path_and_roots(target)

    def validate_wsl_distro_name(self, raw: str) -> str:
        """Validate a WSL distro name through the bound helper."""
        return self._validate_wsl_distro_name(raw)

    def validate_wsl_dotenv_path(self, raw: str) -> str:
        """Validate a WSL dotenv path through the bound helper."""
        return self._validate_wsl_dotenv_path(raw)

    def registry_write(self, *args: Any, apply_changes: bool, **kwargs: Any) -> Any:
        """Dispatch a registry mutation through the bound helper."""
        return self._registry_write(*args, apply_changes=apply_changes, **kwargs)

    def update_dotenv_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Any:
        """Dispatch a dotenv mutation through the bound helper."""
        return self._update_dotenv_file(*args, apply_changes=apply_changes, **kwargs)

    def update_linux_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Any:
        """Dispatch a Linux mutation through the bound helper."""
        return self._update_linux_file(*args, apply_changes=apply_changes, **kwargs)

    def write_linux_etc_environment_with_privilege(self, text: str) -> None:
        """Persist `/etc/environment` through the bound helper."""
        self._write_linux_etc_environment_with_privilege(text)

    def parse_wsl_dotenv_target(self, target: str) -> Any:
        """Parse a WSL dotenv target through the bound helper."""
        return self._parse_wsl_dotenv_target(target)

    def resolve_wsl_target(self, target: str) -> Any:
        """Resolve a WSL target through the bound helper."""
        return self._resolve_wsl_target(target)

    def update_wsl_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Any:
        """Dispatch a WSL mutation through the bound helper."""
        return self._update_wsl_file(*args, apply_changes=apply_changes, **kwargs)

    def update_powershell_file(
        self,
        *args: Any,
        apply_changes: bool,
        **kwargs: Any,
    ) -> Any:
        """Dispatch a PowerShell mutation through the bound helper."""
        return self._update_powershell_file(
            *args,
            apply_changes=apply_changes,
            **kwargs,
        )

    def apply(self, *args: Any, preview_only: bool = False, **kwargs: Any) -> Any:
        """Apply mutations through the bound helper."""
        return self._apply(*args, preview_only=preview_only, **kwargs)

    def effective_scope_roots(
        self,
        scope_roots: List[str | Path] | None = None,
    ) -> List[Path]:
        """Resolve scope roots through the bound helper."""
        return self._effective_scope_roots(scope_roots)

    def __init__(
        self,
        state_dir: Path | None = None,
        backup_retention: int = DEFAULT_BACKUP_RETENTION,
    ) -> None:
        """Initialize service state, backup management, and host providers."""
        self.state_dir = Path(state_dir or (Path.cwd() / ".env-inspector-state"))
        self.backup_mgr = BackupManager(
            self.state_dir / "backups",
            retention=backup_retention,
        )
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

    def _effective_scope_roots(
        self,
        scope_roots: List[str | Path] | None = None,
    ) -> List[Path]:
        """Return the default scope roots plus any validated overrides."""
        roots: List[Path] = list(self.default_scope_roots)
        if scope_roots:
            roots.extend(normalize_scope_roots(scope_roots))
        return normalize_scope_roots(roots)

    @staticmethod
    def resolve_effective(
        key: str,
        context: str,
        records: List[EnvRecord],
    ) -> EnvRecord | None:
        """Resolve the effective record for a key within a context."""
        return resolve_effective_value(records, key, context)

    def _collect_host_rows(self, root_path: Path, scan_depth: int) -> List[EnvRecord]:
        """Collect host-visible records for the active runtime context."""
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
                collect_powershell_profile_records_fn=(
                    collect_powershell_profile_records
                ),
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
        """Collect records from the requested WSL distro and optional dotenv path."""
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
        """Collect records, apply filters, and serialize the result payload."""
        if request is None:
            request = ListRecordsRequest(**kwargs)
        elif kwargs:
            raise TypeError(
                "Pass either a ListRecordsRequest or keyword arguments, not both."
            )

        root_path = resolve_scan_root(request.root or Path.cwd())
        rows = self._collect_host_rows(root_path, request.scan_depth)
        rows.extend(
            self._collect_wsl_rows(
                scan_depth=request.scan_depth,
                distro=request.distro,
                wsl_path=request.wsl_path,
            )
        )
        rows = self._apply_row_filters(
            rows,
            source=request.source,
            context=request.context,
        )
        rows.sort(
            key=lambda r: (r.name.lower(), r.context, r.source_type, r.source_path)
        )
        return _rows_to_payload_helper(
            rows,
            include_raw_secrets=request.include_raw_secrets,
        )

    def _restore_dotenv_target(
        self,
        *,
        target: str,
        text: str,
        scope_roots: List[Path],
    ) -> None:
        """Restore a scoped dotenv target from backup text."""
        _restore_dotenv_target_helper(
            target=target,
            text=text,
            scope_roots=scope_roots,
            parse_scoped_dotenv_target_fn=parse_scoped_dotenv_target,
            write_scoped_text_file_fn=self._write_scoped_text_file,
        )

    def _restore_linux_target(self, *, target: str, text: str) -> None:
        """Restore the host Linux `/etc/environment` target from backup text."""
        _restore_linux_target_helper(
            target=target,
            text=text,
            write_linux_etc_environment_with_privilege_fn=(
                self._write_linux_etc_environment_with_privilege
            ),
        )

    def _restore_wsl_target(self, *, target: str, text: str) -> None:
        """Restore a WSL bashrc or `/etc/environment` target from backup text."""
        _restore_wsl_target_helper(
            target=target,
            text=text,
            wsl=self.wsl,
            parse_wsl_dotenv_target_fn=self._parse_wsl_dotenv_target,
            validate_wsl_distro_name_fn=self._validate_wsl_distro_name,
            linux_etc_env_path=self._LINUX_ETC_ENV_PATH,
        )

    def _restore_powershell_target(self, *, target: str, text: str) -> None:
        """Restore a PowerShell profile target from backup text."""
        _restore_powershell_target_helper(
            target=target,
            text=text,
            validated_powershell_restore_path_fn=(
                self._validated_powershell_restore_path
            ),
            write_text_file_fn=lambda path, content: self._write_text_file(
                path,
                content,
                ensure_parent=True,
            ),
        )

    def _restore_windows_registry_target(self, *, target: str, text: str) -> None:
        """Restore a Windows registry target from backup text."""
        _restore_windows_registry_target_helper(
            target=target,
            text=text,
            win_provider=self.win_provider,
            windows_registry_provider_cls=WindowsRegistryProvider,
        )

    def _restore_target(
        self,
        *,
        target: str,
        text: str,
        scope_roots: List[Path],
    ) -> None:
        """Dispatch backup restoration to the target-specific helper."""
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
        """Restore a recorded backup payload to its original target."""
        operation_id = f"restore-{uuid.uuid4().hex[:10]}"
        path = Path(backup)
        try:
            resolved_scope_roots = self._effective_scope_roots(scope_roots)
            path = validate_backup_path(backup, backups_dir=self.backup_mgr.base_dir)
            payload = self.backup_mgr.read_backup_payload(path)
            target = payload["target"]
            text = payload["text"]

            self._restore_target(
                target=target,
                text=text,
                scope_roots=resolved_scope_roots,
            )

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
