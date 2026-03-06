from __future__ import absolute_import, division

from pathlib import Path
from typing import Any, Callable, Dict, List

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
from .providers import (
    build_registry_records,
    collect_dotenv_records,
    collect_linux_records,
    collect_powershell_profile_records,
    collect_process_records,
    collect_wsl_dotenv_records,
    collect_wsl_records,
)
from .secrets import mask_value

TARGET_LINUX_BASHRC = "linux:bashrc"
TARGET_LINUX_ETC_ENV = "linux:etc_environment"
TARGET_POWERSHELL_CURRENT_USER = "powershell:current_user"
TARGET_POWERSHELL_ALL_USERS = "powershell:all_users"
TARGET_WINDOWS_USER = "windows:user"
TARGET_WINDOWS_MACHINE = "windows:machine"


def collect_host_rows(
    *,
    runtime_context: str,
    root_path: Path,
    scan_depth: int,
    win_provider: Any,
    powershell_profile_paths: List[Path],
    collect_process_records_fn: Callable[..., List[EnvRecord]],
    collect_dotenv_records_fn: Callable[..., List[EnvRecord]],
    build_registry_records_fn: Callable[[Any], List[EnvRecord]],
    collect_powershell_profile_records_fn: Callable[[List[Path]], List[EnvRecord]],
    collect_linux_records_fn: Callable[..., List[EnvRecord]],
) -> List[EnvRecord]:
    rows: List[EnvRecord] = []
    rows.extend(collect_process_records_fn(context=runtime_context))
    rows.extend(collect_dotenv_records_fn(root_path, max_depth=scan_depth, context=runtime_context))

    if win_provider is not None:
        try:
            registry_rows = build_registry_records_fn(win_provider)
        except (OSError, RuntimeError, ValueError):
            registry_rows = []
        rows.extend(registry_rows)

    if runtime_context == "windows":
        rows.extend(collect_powershell_profile_records_fn(powershell_profile_paths))
    else:
        rows.extend(collect_linux_records_fn(context=runtime_context))

    return rows


def collect_wsl_rows(
    *,
    runtime_context: str,
    current_wsl_distro: str | None,
    wsl: Any,
    scan_depth: int,
    distro: str | None,
    wsl_path: str | None,
    collect_wsl_records_fn: Callable[..., List[EnvRecord]],
    collect_wsl_dotenv_records_fn: Callable[..., List[EnvRecord]],
) -> List[EnvRecord]:
    rows: List[EnvRecord] = []
    if not wsl.available():
        return rows

    try:
        exclude_distros: set[str] | None = None
        if runtime_context == "linux" and current_wsl_distro:
            exclude_distros = {current_wsl_distro}
        bridge_rows = collect_wsl_records_fn(wsl, include_etc=True, exclude_distros=exclude_distros)
    except (OSError, RuntimeError, ValueError):
        bridge_rows = []
    rows.extend(bridge_rows)

    if distro and wsl_path:
        try:
            dotenv_rows = collect_wsl_dotenv_records_fn(
                wsl,
                distro=distro,
                root_path=wsl_path,
                max_depth=scan_depth,
            )
        except (OSError, RuntimeError, ValueError):
            dotenv_rows = []
        rows.extend(dotenv_rows)

    return rows


def apply_row_filters(
    rows: List[EnvRecord],
    *,
    source: List[str] | None,
    context: str | None,
) -> List[EnvRecord]:
    if source:
        source_set = set(source)
        rows = [record for record in rows if record.source_type in source_set]
    if context:
        rows = [record for record in rows if record.context == context]
    return rows


def powershell_target_for_path(source_path: str) -> str:
    return TARGET_POWERSHELL_ALL_USERS if "Program Files" in source_path else TARGET_POWERSHELL_CURRENT_USER


def record_target(record: EnvRecord) -> str | None:
    static_targets = {
        SOURCE_LINUX_BASHRC: TARGET_LINUX_BASHRC,
        SOURCE_LINUX_ETC_ENV: TARGET_LINUX_ETC_ENV,
    }
    dynamic_targets: Dict[str, Callable[[EnvRecord], str]] = {
        SOURCE_DOTENV: lambda rec: f"dotenv:{rec.source_path}",
        SOURCE_WSL_DOTENV: lambda rec: f"wsl_dotenv:{rec.source_path}",
        SOURCE_WSL_BASHRC: lambda rec: f"wsl:{rec.source_id}:bashrc",
        SOURCE_WSL_ETC_ENV: lambda rec: f"wsl:{rec.source_id}:etc_environment",
        SOURCE_POWERSHELL_PROFILE: lambda rec: powershell_target_for_path(rec.source_path),
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
    targets: set[str] = set()
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


def rows_to_payload(rows: List[EnvRecord], *, include_raw_secrets: bool) -> List[Dict[str, Any]]:
    payload: List[Dict[str, Any]] = []
    for record in rows:
        item = record.to_dict(include_value=True)
        if record.is_secret and not include_raw_secrets:
            item["value"] = mask_value(record.value)
        payload.append(item)
    return payload
