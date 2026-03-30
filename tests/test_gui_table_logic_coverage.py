"""Coverage tests for env_inspector_gui.table_logic — missing lines 111, 137-140."""

from __future__ import absolute_import, division

from typing import Dict

from env_inspector_core.models import EnvRecord
from env_inspector_gui.models import SortState
from env_inspector_gui.table_logic import (
    DisplayRowsRequest,
    build_display_rows,
    sort_display_rows,
    toggle_sort,
)

from tests.assertions import ensure


def _rec(name: str, value: str, **overrides: object) -> EnvRecord:
    payload: Dict[str, object] = {
        "source_type": "dotenv",
        "source_path": "/workspace/.env",
        "context": "windows",
        "is_secret": False,
        "is_persistent": False,
        "is_mutable": True,
        "precedence_rank": 50,
    }
    payload.update(overrides)
    source_type = str(payload["source_type"])
    source_path = str(payload["source_path"])
    raw_rank = payload["precedence_rank"]
    precedence_rank = raw_rank if isinstance(raw_rank, int) and not isinstance(raw_rank, bool) else 50
    return EnvRecord(
        source_type=source_type,
        source_id=f"{source_type}:{source_path}",
        source_path=source_path,
        context=str(payload["context"]),
        name=name,
        value=value,
        is_secret=bool(payload["is_secret"]),
        is_persistent=bool(payload["is_persistent"]),
        is_mutable=bool(payload["is_mutable"]),
        precedence_rank=precedence_rank,
        writable=True,
        requires_privilege=False,
    )


def test_toggle_sort_new_column():
    """Line 111: toggling to a new column should start ascending."""
    state = SortState(column="name", descending=True)
    toggled = toggle_sort(state, "value")
    ensure(toggled.column == "value")
    ensure(toggled.descending is False)


def test_sort_by_precedence_rank():
    """Lines 137-138: sort by precedence_rank column."""
    rows = build_display_rows(
        DisplayRowsRequest(
            records=[
                _rec("A", "v1", precedence_rank=100),
                _rec("B", "v2", precedence_rank=10),
            ],
            context="windows",
            query="",
            only_secrets=False,
            show_secrets=True,
        )
    )
    ordered = sort_display_rows(rows, SortState(column="precedence_rank", descending=False))
    ensure(ordered[0].record.name == "B")
    ensure(ordered[1].record.name == "A")


def test_sort_by_unknown_column_falls_back_to_name():
    """Lines 140: unknown column falls back to name sort key."""
    rows = build_display_rows(
        DisplayRowsRequest(
            records=[
                _rec("B", "v1"),
                _rec("A", "v2"),
            ],
            context="windows",
            query="",
            only_secrets=False,
            show_secrets=True,
        )
    )
    ordered = sort_display_rows(rows, SortState(column="nonexistent_column", descending=False))
    ensure(ordered[0].record.name == "A")
    ensure(ordered[1].record.name == "B")
