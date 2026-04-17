"""Test gui table logic module."""

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
    """Rec."""
    payload: Dict[str, object] = {
        "source_type": "dotenv",
        "source_path": "/workspace/.env",
        "context": "windows",
        "is_secret": False,  # nosec B105
        "is_persistent": False,
        "is_mutable": True,
        "precedence_rank": 50,
    }
    payload.update(overrides)
    source_type = str(payload["source_type"])
    source_path = str(payload["source_path"])
    raw_rank = payload["precedence_rank"]
    precedence_rank = (
        raw_rank if isinstance(raw_rank, int) and not isinstance(raw_rank, bool) else 50
    )
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


def test_build_display_rows_filters_context_and_only_secrets():
    """Test build display rows filters context and only secrets."""
    rows = build_display_rows(
        DisplayRowsRequest(
            records=[
                _rec("PUBLIC", "abc", context="windows", is_secret=False),
                _rec("TOKEN", "supersecretvalue", context="windows", is_secret=True),
                _rec(
                    "WSL_SECRET", "anothersecret", context="wsl:Ubuntu", is_secret=True
                ),
            ],
            context="windows",
            query="",
            only_secrets=True,
            show_secrets=False,
        )
    )

    ensure([row.record.name for row in rows] == ["TOKEN"])
    ensure(rows[0].visible_value != "supersecretvalue")


def test_hidden_secret_search_uses_masked_value_not_raw_secret():
    """Test hidden secret search uses masked value not raw secret."""
    record = _rec("API_TOKEN", "supersecretvalue", is_secret=True)

    hidden_rows = build_display_rows(
        DisplayRowsRequest(
            records=[record],
            context="windows",
            query="supersecretvalue",
            only_secrets=False,
            show_secrets=False,
        )
    )
    ensure(not hidden_rows)

    shown_rows = build_display_rows(
        DisplayRowsRequest(
            records=[record],
            context="windows",
            query="supersecretvalue",
            only_secrets=False,
            show_secrets=True,
        )
    )
    ensure(len(shown_rows) == 1)


def test_sort_toggle_and_stable_sort_behavior():
    """Test sort toggle and stable sort behavior."""
    rows = build_display_rows(
        DisplayRowsRequest(
            records=[
                _rec("A", "v2", source_path="/workspace/2.env"),
                _rec("A", "v1", source_path="/workspace/1.env"),
                _rec("B", "v3", source_path="/workspace/3.env"),
            ],
            context="windows",
            query="",
            only_secrets=False,
            show_secrets=True,
        )
    )

    state = SortState(column="name", descending=False)
    ordered = sort_display_rows(rows, state)
    ensure(
        [row.record.source_path for row in ordered[:2]]
        == ["/workspace/2.env", "/workspace/1.env"]
    )

    toggled = toggle_sort(state, "name")
    ensure(toggled.column == "name")
    ensure(toggled.descending is True)


def test_bool_sort_columns_use_yes_no_semantics():
    """Test bool sort columns use yes no semantics."""
    rows = build_display_rows(
        DisplayRowsRequest(
            records=[
                _rec("A", "1", is_secret=True),
                _rec("B", "2", is_secret=False),
            ],
            context="windows",
            query="",
            only_secrets=False,
            show_secrets=True,
        )
    )

    ordered = sort_display_rows(rows, SortState(column="secret", descending=False))
    ensure([row.record.name for row in ordered] == ["B", "A"])
