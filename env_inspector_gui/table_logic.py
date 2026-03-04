from __future__ import absolute_import, division

from .models import DisplayedRow, SortState
from .secret_policy import build_search_value, build_visible_value


def _secret_flag(record) -> bool:
    return bool(getattr(record, "is_secret", False))


def _persistent_flag(record) -> bool:
    return bool(getattr(record, "is_persistent", False))


def _mutable_flag(record) -> bool:
    return bool(getattr(record, "is_mutable", False))


def _record_matches_filters(rec, *, context: str, only_secrets: bool) -> bool:
    if only_secrets and not _secret_flag(rec):
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
        secret_text="yes" if _secret_flag(rec) else "no",
        persistent_text="yes" if _persistent_flag(rec) else "no",
        mutable_text="yes" if _mutable_flag(rec) else "no",
        writable_text="yes" if rec.writable else "no",
        requires_privilege_text="yes" if rec.requires_privilege else "no",
        original_index=idx,
    )


def build_display_rows(
    records,
    *,
    context: str,
    query: str,
    only_secrets: bool,
    show_secrets: bool,
) -> list[DisplayedRow]:
    rows: list[DisplayedRow] = []
    query_text = query.strip().lower()

    for idx, rec in enumerate(records):
        if not _record_matches_filters(rec, context=context, only_secrets=only_secrets):
            continue

        search_value = build_search_value(rec, show_secrets=show_secrets)
        if query_text and query_text not in search_value:
            continue

        rows.append(_to_displayed_row(rec, show_secrets=show_secrets, search_value=search_value, idx=idx))

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
        "secret": _secret_flag(rec),
        "persistent": _persistent_flag(rec),
        "mutable": _mutable_flag(rec),
    }
    if column in bool_map:
        return bool_map[column]

    if column == "precedence_rank":
        return int(rec.precedence_rank)

    return str_map["name"]


def sort_display_rows(rows: list[DisplayedRow], sort_state: SortState) -> list[DisplayedRow]:
    column = sort_state.column or "name"
    return sorted(
        rows,
        key=lambda row: (_sort_key(row, column), row.original_index),
        reverse=sort_state.descending,
    )
