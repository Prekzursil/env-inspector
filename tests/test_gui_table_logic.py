from __future__ import absolute_import, division

from env_inspector_core.models import EnvRecord
from env_inspector_gui.models import SortState
from env_inspector_gui.table_logic import build_display_rows, sort_display_rows, toggle_sort

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



def _rec(
    name: str,
    value: str,
    *,
    context: str = "windows",
    source_type: str = "dotenv",
    source_path: str = "/workspace/.env",
    is_secret: bool = False,
    is_persistent: bool = False,
    is_mutable: bool = True,
    precedence_rank: int = 50,
) -> EnvRecord:
    return EnvRecord(
        source_type=source_type,
        source_id=f"{source_type}:{source_path}",
        source_path=source_path,
        context=context,
        name=name,
        value=value,
        is_secret=is_secret,
        is_persistent=is_persistent,
        is_mutable=is_mutable,
        precedence_rank=precedence_rank,
        writable=True,
        requires_privilege=False,
    )


def test_build_display_rows_filters_context_and_only_secrets():
    rows = build_display_rows(
        [
            _rec("PUBLIC", "abc", context="windows", is_secret=False),
            _rec("TOKEN", "supersecretvalue", context="windows", is_secret=True),
            _rec("WSL_SECRET", "anothersecret", context="wsl:Ubuntu", is_secret=True),
        ],
        context="windows",
        query="",
        only_secrets=True,
        show_secrets=False,
    )

    _expect([row.record.name for row in rows] == ["TOKEN"])

    _expect(rows[0].visible_value != "supersecretvalue")



def test_hidden_secret_search_uses_masked_value_not_raw_secret():
    record = _rec("API_TOKEN", "supersecretvalue", is_secret=True)

    hidden_rows = build_display_rows(
        [record],
        context="windows",
        query="supersecretvalue",
        only_secrets=False,
        show_secrets=False,
    )
    _expect(hidden_rows == [])


    shown_rows = build_display_rows(
        [record],
        context="windows",
        query="supersecretvalue",
        only_secrets=False,
        show_secrets=True,
    )
    _expect(len(shown_rows) == 1)



def test_sort_toggle_and_stable_sort_behavior():
    rows = build_display_rows(
        [
            _rec("A", "v2", source_path="/workspace/2.env"),
            _rec("A", "v1", source_path="/workspace/1.env"),
            _rec("B", "v3", source_path="/workspace/3.env"),
        ],
        context="windows",
        query="",
        only_secrets=False,
        show_secrets=True,
    )

    state = SortState(column="name", descending=False)
    ordered = sort_display_rows(rows, state)
    _expect([row.record.source_path for row in ordered[:2]] == ["/workspace/2.env", "/workspace/1.env"])


    toggled = toggle_sort(state, "name")
    _expect(toggled.column == "name")

    _expect(toggled.descending is True)



def test_bool_sort_columns_use_yes_no_semantics():
    rows = build_display_rows(
        [
            _rec("A", "1", is_secret=True),
            _rec("B", "2", is_secret=False),
        ],
        context="windows",
        query="",
        only_secrets=False,
        show_secrets=True,
    )

    ordered = sort_display_rows(rows, SortState(column="secret", descending=False))
    _expect([row.record.name for row in ordered] == ["B", "A"])


def test_expect_helper_raises_on_false():
    raised = False
    try:
        _expect(False, "expected")
    except AssertionError:
        raised = True
    _expect(raised is True)

