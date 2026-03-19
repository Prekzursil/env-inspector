from __future__ import absolute_import, division

from dataclasses import dataclass
from typing import Iterable, List

from .models import DisplayedRow, SortState
from .secret_policy import build_search_value, build_visible_value


def _record_matches_filters(rec, *, context: str, only_secrets: bool) -> bool:
    if only_secrets and not rec.is_secret:
        return False
    if context and rec.context != context:
        return False
    return True


def _to_displayed_row(rec, *, show_secrets: bool, search_value: str, idx: int) -> DisplayedRow:
    return DisplayedRow(
        record=rec,
        visible_value=build_visible_value(rec, show_secrets=show_secrets),
        search_value=search_value,
        source_label=rec.source_type,
        secret_text="yes" if rec.is_secret else "no",
        persistent_text="yes" if rec.is_persistent else "no",
        mutable_text="yes" if rec.is_mutable else "no",
        writable_text="yes" if rec.writable else "no",
        requires_privilege_text="yes" if rec.requires_privilege else "no",
        original_index=idx,
    )


@dataclass(frozen=True)
class DisplayRowsRequest:
    records: Iterable
    context: str
    query: str
    only_secrets: bool
    show_secrets: bool


def build_display_rows(request: DisplayRowsRequest) -> List[DisplayedRow]:
    rows: List[DisplayedRow] = []
    query_text = request.query.strip().lower()

    for idx, rec in enumerate(request.records):
        if not _record_matches_filters(rec, context=request.context, only_secrets=request.only_secrets):
            continue

        search_value = build_search_value(rec, show_secrets=request.show_secrets)
        if query_text and query_text not in search_value:
            continue

        rows.append(_to_displayed_row(rec, show_secrets=request.show_secrets, search_value=search_value, idx=idx))

    return rows


def toggle_sort(current: SortState, column: str) -> SortState:
    if current.column == column:
        return SortState(column=column, descending=not current.descending)
    return SortState(column=column, descending=False)


def _sort_key(row: DisplayedRow, column: str):
    rec = row.record

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
        "secret": bool(rec.is_secret),
        "persistent": bool(rec.is_persistent),
        "mutable": bool(rec.is_mutable),
    }
    if column in bool_map:
        return bool_map[column]

    if column == "precedence_rank":
        return int(rec.precedence_rank)

    return str_map["name"]


def sort_display_rows(rows: List[DisplayedRow], sort_state: SortState) -> List[DisplayedRow]:
    column = sort_state.column or "name"
    return sorted(
        rows,
        key=lambda row: (_sort_key(row, column), row.original_index),
        reverse=sort_state.descending,
    )
