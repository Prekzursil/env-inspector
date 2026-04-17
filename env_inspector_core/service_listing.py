"""Service listing module."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set
from collections.abc import Callable

from .constants import (
    SOURCE_DOTENV,
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_WSL_BASHRC,
    SOURCE_WSL_DOTENV,
    SOURCE_WSL_ETC_ENV,
)
from .models import EnvRecord
from .secrets import mask_value

TARGET_LINUX_BASHRC = "linux:bashrc"
TARGET_LINUX_ETC_ENV = "linux:etc_environment"
TARGET_POWERSHELL_CURRENT_USER = "powershell:current_user"
TARGET_POWERSHELL_ALL_USERS = "powershell:all_users"
TARGET_WINDOWS_USER = "windows:user"
TARGET_WINDOWS_MACHINE = "windows:machine"


@dataclass(frozen=True)
class HostCollectionRequest:
    """Parameters for collecting environment records from the host system."""

    runtime_context: str
    root_path: Path
    scan_depth: int
    win_provider: Any
    powershell_profile_paths: List[Path]


@dataclass(frozen=True)
class HostRowCollectors:
    """Callable references for each host record collection strategy."""

    collect_process_records_fn: Callable[..., List[EnvRecord]]
    collect_dotenv_records_fn: Callable[..., List[EnvRecord]]
    build_registry_records_fn: Callable[[Any], List[EnvRecord]]
    collect_powershell_profile_records_fn: Callable[[List[Path]], List[EnvRecord]]
    collect_linux_records_fn: Callable[..., List[EnvRecord]]


@dataclass(frozen=True)
class _WslDotenvRequest:
    """Parameters for a WSL dotenv file scan."""

    distro: str | None
    wsl_path: str | None
    scan_depth: int


def collect_host_rows(
    *,
    request: HostCollectionRequest,
    collectors: HostRowCollectors,
) -> List[EnvRecord]:
    """Collect host rows."""
    rows: List[EnvRecord] = []
    rows.extend(collectors.collect_process_records_fn(context=request.runtime_context))
    rows.extend(
        collectors.collect_dotenv_records_fn(
            request.root_path,
            max_depth=request.scan_depth,
            context=request.runtime_context,
        )
    )

    if request.win_provider is not None:
        try:
            registry_rows = collectors.build_registry_records_fn(request.win_provider)
        except (OSError, RuntimeError, ValueError):
            registry_rows = []
        rows.extend(registry_rows)

    if request.runtime_context == "windows":
        rows.extend(
            collectors.collect_powershell_profile_records_fn(
                request.powershell_profile_paths
            )
        )
    else:
        rows.extend(
            collectors.collect_linux_records_fn(context=request.runtime_context)
        )

    return rows


def collect_wsl_rows(*args: Any, **kwargs: Any) -> List[EnvRecord]:
    """Collect wsl rows."""
    if args:
        raise TypeError("collect_wsl_rows accepts keyword arguments only.")

    runtime_context = kwargs.pop("runtime_context")
    current_wsl_distro = kwargs.pop("current_wsl_distro")
    wsl = kwargs.pop("wsl")
    scan_depth = kwargs.pop("scan_depth")
    distro = kwargs.pop("distro")
    wsl_path = kwargs.pop("wsl_path")
    collect_wsl_records_fn = kwargs.pop("collect_wsl_records_fn")
    collect_wsl_dotenv_records_fn = kwargs.pop("collect_wsl_dotenv_records_fn")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected keyword argument(s): {unexpected}")

    if not wsl.available():
        return []

    rows = _bridge_rows(
        runtime_context=runtime_context,
        current_wsl_distro=current_wsl_distro,
        wsl=wsl,
        collect_wsl_records_fn=collect_wsl_records_fn,
    )
    rows.extend(
        _wsl_dotenv_rows(
            request=_WslDotenvRequest(
                distro=distro, wsl_path=wsl_path, scan_depth=scan_depth
            ),
            wsl=wsl,
            collect_wsl_dotenv_records_fn=collect_wsl_dotenv_records_fn,
        )
    )
    return rows


def _bridge_rows(
    *,
    runtime_context: str,
    current_wsl_distro: str | None,
    wsl: Any,
    collect_wsl_records_fn,
) -> List[EnvRecord]:
    """Bridge rows."""
    try:
        exclude_distros: Set[str] | None = None
        if runtime_context == "linux" and current_wsl_distro:
            exclude_distros = {current_wsl_distro}
        return collect_wsl_records_fn(
            wsl, include_etc=True, exclude_distros=exclude_distros
        )
    except (OSError, RuntimeError, ValueError):
        return []


def _wsl_dotenv_rows(
    *, request: _WslDotenvRequest, wsl: Any, collect_wsl_dotenv_records_fn
) -> List[EnvRecord]:
    """Wsl dotenv rows."""
    if not (request.distro and request.wsl_path):
        return []
    try:
        return collect_wsl_dotenv_records_fn(
            wsl,
            distro=request.distro,
            root_path=request.wsl_path,
            max_depth=request.scan_depth,
        )
    except (OSError, RuntimeError, ValueError):
        return []


def apply_row_filters(
    rows: List[EnvRecord],
    *,
    source: List[str] | None,
    context: str | None,
) -> List[EnvRecord]:
    """Apply row filters."""
    if source:
        source_set = set(source)
        rows = [record for record in rows if record.source_type in source_set]
    if context:
        rows = [record for record in rows if record.context == context]
    return rows


def powershell_target_for_path(source_path: str) -> str:
    """Powershell target for path."""
    return (
        TARGET_POWERSHELL_ALL_USERS
        if "Program Files" in source_path
        else TARGET_POWERSHELL_CURRENT_USER
    )


def record_target(record: EnvRecord) -> str | None:
    """Record target."""
    static_targets = {
        SOURCE_LINUX_BASHRC: TARGET_LINUX_BASHRC,
        SOURCE_LINUX_ETC_ENV: TARGET_LINUX_ETC_ENV,
    }
    dynamic_targets: Dict[str, Callable[[EnvRecord], str]] = {
        SOURCE_DOTENV: lambda rec: f"dotenv:{rec.source_path}",
        SOURCE_WSL_DOTENV: lambda rec: f"wsl_dotenv:{rec.source_path}",
        SOURCE_WSL_BASHRC: lambda rec: f"wsl:{rec.source_id}:bashrc",
        SOURCE_WSL_ETC_ENV: lambda rec: f"wsl:{rec.source_id}:etc_environment",
        SOURCE_POWERSHELL_PROFILE: lambda rec: powershell_target_for_path(
            rec.source_path
        ),
    }

    static_target = static_targets.get(record.source_type)
    if static_target is not None:
        return static_target
    builder = dynamic_targets.get(record.source_type)
    return builder(record) if builder is not None else None


def available_targets(
    records: List[EnvRecord],
    *,
    context: str | None,
    win_provider_present: bool,
) -> List[str]:
    """Available targets."""
    targets: Set[str] = set()
    for record in records:
        if context and record.context != context:
            continue
        mapped_target = record_target(record)
        if mapped_target:
            targets.add(mapped_target)
    if win_provider_present:
        targets.add(TARGET_WINDOWS_USER)
        targets.add(TARGET_WINDOWS_MACHINE)
    if context == "linux":
        targets.add(TARGET_LINUX_BASHRC)
        targets.add(TARGET_LINUX_ETC_ENV)
    return sorted(targets)


def rows_to_payload(
    rows: List[EnvRecord], *, include_raw_secrets: bool
) -> List[Dict[str, Any]]:
    """Rows to payload."""
    payload: List[Dict[str, Any]] = []
    for record in rows:
        item = record.to_dict(include_value=True)
        if bool(item.get("is_secret")) and not include_raw_secrets:
            item["value"] = mask_value(record.value)
        payload.append(item)
    return payload
