"""Helpers for filtering and sorting GUI table rows."""

from dataclasses import dataclass
from typing import Dict, List
from collections.abc import Iterable

from env_inspector_core.models import EnvRecord

from .models import DisplayedRow, SortState
from .secret_policy import build_search_value, build_visible_value


def _record_payload(rec: EnvRecord) -> Dict[str, object]:
    """Return a normalized payload for analyzer-friendly flag access."""
    return rec.to_dict()


def _record_flag(rec_payload: Dict[str, object], key: str) -> bool:
    """Return a boolean flag from a serialized record payload."""
    return bool(rec_payload.get(key, False))


def _record_matches_filters(
    rec: EnvRecord,
    *,
    context: str,
    only_secrets: bool,
) -> bool:
    """Return whether a record should survive the current filter set."""
    rec_payload = _record_payload(rec)
    if only_secrets and not _record_flag(rec_payload, "is_secret"):
        return False
    if context and rec.context != context:
        return False
    return True


def _to_displayed_row(
    rec: EnvRecord,
    *,
    show_secrets: bool,
    search_value: str,
    idx: int,
) -> DisplayedRow:
    """Convert a record into the GUI row model used by the table."""
    rec_payload = _record_payload(rec)
    is_secret = _record_flag(rec_payload, "is_secret")
    is_persistent = _record_flag(rec_payload, "is_persistent")
    is_mutable = _record_flag(rec_payload, "is_mutable")
    is_writable = _record_flag(rec_payload, "writable")
    requires_privilege = _record_flag(rec_payload, "requires_privilege")
    return DisplayedRow(
        record=rec,
        visible_value=build_visible_value(rec, show_secrets=show_secrets),
        search_value=search_value,
        source_label=rec.source_type,
        secret_text="yes" if is_secret else "no",
        persistent_text="yes" if is_persistent else "no",
        mutable_text="yes" if is_mutable else "no",
        writable_text="yes" if is_writable else "no",
        requires_privilege_text="yes" if requires_privilege else "no",
        original_index=idx,
    )


@dataclass(frozen=True)
class DisplayRowsRequest:
    """Inputs required to build the filtered, searchable GUI row list."""

    records: Iterable[EnvRecord]
    context: str
    query: str
    only_secrets: bool
    show_secrets: bool


def build_display_rows(request: DisplayRowsRequest) -> List[DisplayedRow]:
    """Build the filtered GUI rows for the current table request."""
    rows: List[DisplayedRow] = []
    query_text = request.query.strip().lower()

    for idx, rec in enumerate(request.records):
        if not _record_matches_filters(
            rec,
            context=request.context,
            only_secrets=request.only_secrets,
        ):
            continue

        search_value = build_search_value(rec, show_secrets=request.show_secrets)
        if query_text and query_text not in search_value:
            continue

        rows.append(
            _to_displayed_row(
                rec,
                show_secrets=request.show_secrets,
                search_value=search_value,
                idx=idx,
            )
        )

    return rows


def toggle_sort(current: SortState, column: str) -> SortState:
    """Toggle the active sort direction or start sorting by a new column."""
    if current.column == column:
        return SortState(column=column, descending=not current.descending)
    return SortState(column=column, descending=False)


def _sort_key(row: DisplayedRow, column: str):
    """Return the sortable value for the requested GUI table column."""
    rec = row.record
    rec_payload = _record_payload(rec)

    str_map = {
        "context": rec.context.lower(),
        "source": row.source_label.lower(),
        "name": rec.name.lower(),
        "value": row.visible_value.lower(),
        "source_path": rec.source_path.lower(),
    }
    if column in str_map:
        return str_map[column]

    bool_map = {
        "secret": _record_flag(rec_payload, "is_secret"),
        "persistent": _record_flag(rec_payload, "is_persistent"),
        "mutable": _record_flag(rec_payload, "is_mutable"),
    }
    if column in bool_map:
        return bool_map[column]

    if column == "precedence_rank":
        return int(rec.precedence_rank)

    return str_map["name"]


def sort_display_rows(
    rows: List[DisplayedRow],
    sort_state: SortState,
) -> List[DisplayedRow]:
    """Return rows sorted by the active GUI sort state."""
    column = sort_state.column or "name"
    return sorted(
        rows,
        key=lambda row: (_sort_key(row, column), row.original_index),
        reverse=sort_state.descending,
    )
