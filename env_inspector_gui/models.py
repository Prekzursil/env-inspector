from __future__ import absolute_import, division

from typing import Dict, List
from dataclasses import asdict, dataclass, field

from env_inspector_core.models import EnvRecord


def _coerce_text(payload: Dict[str, object], key: str, default: str) -> str:
    value = payload.get(key, default)
    return str(value or default)


def _coerce_flag(payload: Dict[str, object], key: str, default: bool = False) -> bool:
    return bool(payload.get(key, default))


def _coerce_items(payload: Dict[str, object], key: str) -> List[str]:
    value = payload.get(key) or []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _coerce_number(payload: Dict[str, object], key: str, default: int) -> int:
    value = payload.get(key, default)
    try:
        return int(value or default)
    except Exception:
        return default


@dataclass(frozen=True)
class SortState:
    column: str = "name"
    descending: bool = False


@dataclass
class PersistedUiState:
    version: int = 1
    window_geometry: str = "1480x860"
    root_path: str = ""
    context: str = ""
    show_secrets: bool = False
    only_secrets: bool = False
    filter_text: str = ""
    selected_targets: List[str] = field(default_factory=list)
    sort_column: str = "name"
    sort_descending: bool = False
    wsl_distro: str = ""
    wsl_path: str = ""
    scan_depth: int = 5

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "PersistedUiState":
        return cls(
            version=_coerce_number(payload, "version", 1),
            window_geometry=_coerce_text(payload, "window_geometry", "1480x860"),
            root_path=_coerce_text(payload, "root_path", ""),
            context=_coerce_text(payload, "context", ""),
            show_secrets=_coerce_flag(payload, "show_secrets"),
            only_secrets=_coerce_flag(payload, "only_secrets"),
            filter_text=_coerce_text(payload, "filter_text", ""),
            selected_targets=_coerce_items(payload, "selected_targets"),
            sort_column=_coerce_text(payload, "sort_column", "name"),
            sort_descending=_coerce_flag(payload, "sort_descending"),
            wsl_distro=_coerce_text(payload, "wsl_distro", ""),
            wsl_path=_coerce_text(payload, "wsl_path", ""),
            scan_depth=_coerce_number(payload, "scan_depth", 5),
        )


@dataclass
class DisplayedRow:
    record: EnvRecord
    visible_value: str
    search_value: str
    source_label: str
    secret_text: str
    persistent_text: str
    mutable_text: str
    writable_text: str
    requires_privilege_text: str
    original_index: int
