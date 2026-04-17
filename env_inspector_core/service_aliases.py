"""Alias helpers that provide the service's compatibility surface."""

import json
from pathlib import Path
from typing import Any, List

from .models import EnvRecord
from .providers import WindowsRegistryProvider
from .rendering import export_rows
from .service_listing import available_targets as _available_targets_helper
from .service_ops import (
    normalize_target_operation_request as _normalize_target_operation_request_helper,
)
from .service_paths import (
    get_powershell_profile_paths as _get_powershell_profile_paths,
)
from .service_paths import (
    linux_etc_environment_path as _linux_etc_environment_path,
)
from .service_paths import (
    powershell_target_path_and_roots as _powershell_target_path_and_roots,
)
from .service_paths import (
    validated_powershell_restore_path as _validated_powershell_restore_path,
)
from .service_wsl import validate_wsl_dotenv_path as _validate_wsl_dotenv_path_helper


def registry_write(self, *args: Any, apply_changes: bool, **kwargs: Any):
    """Apply or preview a Windows registry mutation."""
    request_data = _normalize_target_operation_request_helper(*args, **kwargs)
    target = request_data["target"]
    key = request_data["key"]
    value = request_data["value"]
    action = request_data["action"]
    if self.win_provider is None:
        raise RuntimeError("Windows registry provider unavailable.")
    scope = (
        WindowsRegistryProvider.USER_SCOPE
        if target == "windows:user"
        else WindowsRegistryProvider.MACHINE_SCOPE
    )
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


def bridge_distros(self) -> List[str]:
    """Return bridge distros, excluding the active Linux-host distro."""
    if not self.wsl.available():
        return []
    distros = self.wsl.list_distros_for_ui()
    if self.runtime_context == "linux" and self.current_wsl_distro:
        current = self.current_wsl_distro.lower()
        distros = [d for d in distros if d.lower() != current]
    return distros


def list_contexts(self) -> List[str]:
    """Return the runtime context plus any available WSL bridge contexts."""
    contexts = [self.runtime_context]
    if self.wsl.available():
        for distro in self.bridge_distros():
            contexts.append(f"wsl:{distro}")
    return contexts


def get_powershell_profile_paths() -> List[Path]:
    """Return the PowerShell profile paths exposed by the path helper."""
    return _get_powershell_profile_paths()


def powershell_target_path_and_roots(self, target: str):
    """Resolve a PowerShell target into its path and allowed roots."""
    return _powershell_target_path_and_roots(
        target,
        profile_resolver=self.powershell_profile_path,
        current_user_target="powershell:current_user",
        all_users_target="powershell:all_users",
    )


def validated_powershell_restore_path(self, target: str) -> Path:
    """Resolve and validate the destination for a PowerShell restore."""
    return _validated_powershell_restore_path(
        target,
        profile_resolver=self.powershell_profile_path,
        current_user_target="powershell:current_user",
        all_users_target="powershell:all_users",
    )


def linux_etc_environment_path(cls) -> Path:
    """Resolve `/etc/environment` using the public service bridge."""
    return _linux_etc_environment_path(cls.linux_etc_environment_value())


def available_targets(
    self,
    records: List[EnvRecord],
    context: str | None = None,
) -> List[str]:
    """Return the set of editable targets visible for the provided records."""
    return _available_targets_helper(
        records,
        context=context,
        win_provider_present=self.win_provider is not None,
    )


def list_records_raw(self, **kwargs: Any) -> List[EnvRecord]:
    """Return raw `EnvRecord` instances instead of serialized payload rows."""
    payload = self.list_records(include_raw_secrets=True, **kwargs)
    return [EnvRecord(**item) for item in payload]


def preview_set(
    self,
    *,
    key: str,
    value: str,
    targets: List[str],
    scope_roots=None,
) -> List[dict]:
    """Preview a set operation and serialize the results."""
    return [
        r.to_dict()
        for r in self.apply(
            action="set",
            key=key,
            value=value,
            targets=targets,
            scope_roots=scope_roots,
            preview_only=True,
        )
    ]


def preview_remove(
    self,
    *,
    key: str,
    targets: List[str],
    scope_roots=None,
) -> List[dict]:
    """Preview a remove operation and serialize the results."""
    return [
        r.to_dict()
        for r in self.apply(
            action="remove",
            key=key,
            value=None,
            targets=targets,
            scope_roots=scope_roots,
            preview_only=True,
        )
    ]


def _results_payload(results):
    """Collapse one or more operation results into the legacy payload shape."""
    if len(results) == 1:
        return results[0].to_dict()
    return {
        "success": all(r.success for r in results),
        "results": [r.to_dict() for r in results],
    }


def set_key(self, *, key: str, value: str, targets: List[str], scope_roots=None):
    """Apply a set operation and return the legacy payload shape."""
    results = self.apply(
        action="set",
        key=key,
        value=value,
        targets=targets,
        scope_roots=scope_roots,
        preview_only=False,
    )
    return _results_payload(results)


def remove_key(self, *, key: str, targets: List[str], scope_roots=None):
    """Apply a remove operation and return the legacy payload shape."""
    results = self.apply(
        action="remove",
        key=key,
        value=None,
        targets=targets,
        scope_roots=scope_roots,
        preview_only=False,
    )
    return _results_payload(results)


def export_records(
    self,
    *,
    output: str,
    include_raw_secrets: bool,
    **list_kwargs: Any,
) -> str:
    """Export serialized rows in the requested output format."""
    rows = self.list_records(include_raw_secrets=include_raw_secrets, **list_kwargs)
    return export_rows(rows, output=output)


def list_backups(self, *, target: str | None = None) -> List[str]:
    """Return backup paths, optionally scoped to a single target."""
    if target:
        return [str(p) for p in self.backup_mgr.list_backups(target)]
    return [str(p) for p in self.backup_mgr.list_all_backups()]


def validate_wsl_dotenv_path(raw: str) -> str:
    """Validate a WSL dotenv path for legacy service callers."""
    return _validate_wsl_dotenv_path_helper(
        raw,
        path_error="Unsupported WSL dotenv target path",
    )
