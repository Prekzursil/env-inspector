from __future__ import absolute_import, division

from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence
from dataclasses import asdict, dataclass, field

from env_inspector_core.models import EnvRecord

from .secret_policy import resolve_copy_payload


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
    result = default
    if isinstance(value, bool):
        result = default
    elif isinstance(value, int):
        result = value
    elif isinstance(value, float):
        result = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if text:
            try:
                result = int(text)
            except ValueError:
                result = default
    return result


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


@dataclass(frozen=True)
class ContextSelection:
    context: str
    wsl_distro: str
    distros: List[str]


@dataclass(frozen=True)
class OperationResultSummary:
    status_message: str | None
    error_message: str | None


def select_theme_name(os_name: str, themes: Sequence[str]) -> str | None:
    theme_set = set(themes)
    if os_name == "nt":
        for preferred in ("vista", "xpnative"):
            if preferred in theme_set:
                return preferred
        if "clam" in theme_set:
            return "clam"
        return None
    if "clam" in theme_set:
        return "clam"
    return None


def resolve_context_selection(
    *,
    contexts: Sequence[str],
    current_context: str,
    current_wsl_distro: str,
    runtime_context: str,
) -> ContextSelection:
    distros = [context.split(":", 1)[1] for context in contexts if context.startswith("wsl:")]
    if current_context in contexts:
        context = current_context
    elif contexts:
        context = contexts[0]
    else:
        context = runtime_context

    if current_wsl_distro in distros:
        wsl_distro = current_wsl_distro
    elif distros:
        wsl_distro = distros[0]
    else:
        wsl_distro = ""
    return ContextSelection(context=context, wsl_distro=wsl_distro, distros=distros)


def reconcile_selected_targets(selected_targets: Sequence[str], available_targets: Sequence[str]) -> List[str]:
    if not selected_targets:
        return list(available_targets)
    remaining = [target for target in selected_targets if target in available_targets]
    return remaining or list(available_targets)


def has_multiple_dotenv_matches(records: Iterable[EnvRecord], key: str) -> bool:
    found = 0
    for record in records:
        if record.name == key and record.source_type in {"dotenv", "wsl_dotenv"}:
            found += 1
            if found > 1:
                return True
    return False


def build_status_line(shown: int, total: int, context: str, last_refresh_at) -> str:
    when = "-" if last_refresh_at is None else last_refresh_at.strftime("%H:%M:%S")
    return f"Showing {shown} / {total} entries | Context: {context} | Last refresh: {when}"


def resolve_selected_targets(
    *,
    selected_targets: Sequence[str],
    choose_targets: Callable[[], List[str] | None],
    key: str,
    maybe_choose_dotenv_targets: Callable[[str, List[str]], List[str] | None],
) -> List[str] | None:
    targets = list(selected_targets)
    if not targets:
        targets = choose_targets() or []
        if not targets:
            return None

    scoped_targets = maybe_choose_dotenv_targets(key, list(targets))
    return scoped_targets


def summarize_operation_result(action: str, result: Mapping[str, Any]) -> OperationResultSummary:
    if isinstance(result, dict) and "results" in result:
        failures = _batch_failures(result["results"])
        if failures:
            return OperationResultSummary(
                status_message=None,
                error_message=f"{action.title()} had failures:\n" + "\n".join(str(item.get("error_message", "")) for item in failures),
            )
        return OperationResultSummary(
            status_message=f"{action.title()} succeeded for {len(result['results'])} targets",
            error_message=None,
        )

    if result.get("success"):
        return OperationResultSummary(
            status_message=f"{action.title()} succeeded ({result.get('operation_id')})",
            error_message=None,
        )
    return OperationResultSummary(
        status_message=None,
        error_message=f"{action.title()} failed: {result.get('error_message')}",
    )


def _batch_failures(results: Any) -> List[Mapping[str, Any]]:
    return [item for item in results if isinstance(item, dict) and not item.get("success")]


def select_target_dialog_result(result: List[str] | None, *, messagebox: Any, app_name: str) -> List[str] | None:
    if result is None:
        return None
    if not result:
        messagebox.showinfo(app_name, "No targets selected.")
        return None
    return list(result)


def build_effective_value_text(
    record: EnvRecord | None,
    *,
    context: str,
    key: str,
    show_secrets: bool,
) -> str:
    if not key:
        return "Effective: (select key)"
    if record is None:
        return "Effective: (not found)"

    row_value, _ = resolve_copy_payload(
        record,
        show_secrets=show_secrets,
        confirm_raw=lambda: False,
        as_pair=False,
    )
    return f"Effective ({context}): {key}={row_value} from {record.source_type}"
