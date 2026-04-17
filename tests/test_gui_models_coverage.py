"""Coverage tests for env_inspector_gui.models."""

from __future__ import absolute_import, division

from datetime import datetime
from typing import Any, Dict

from env_inspector_core.models import EnvRecord
from env_inspector_gui.models import (
    PersistedUiState,
    build_effective_value_text,
    build_status_line,
    has_multiple_dotenv_matches,
    reconcile_selected_targets,
    resolve_context_selection,
    resolve_selected_targets,
    select_target_dialog_result,
    select_theme_name,
    summarize_operation_result,
)
from env_inspector_gui.models import (
    _coerce_text,
    _coerce_flag,
    _coerce_items,
    _coerce_number,
)

from tests.assertions import ensure


def _make_record(**overrides: object) -> EnvRecord:
    defaults: Dict[str, Any] = {
        "source_type": "dotenv",
        "source_id": "dotenv:/workspace/.env",
        "source_path": "/workspace/.env",
        "context": "windows",
        "name": "KEY",
        "value": "val",
        "is_secret": False,
        "is_persistent": False,
        "is_mutable": True,
        "precedence_rank": 50,
        "writable": True,
        "requires_privilege": False,
    }
    defaults.update(overrides)
    return EnvRecord(**defaults)


# --- _coerce_text ---
def test_coerce_text_returns_default_on_none():
    ensure(_coerce_text({}, "key", "fallback") == "fallback")


def test_coerce_text_returns_string_value():
    ensure(_coerce_text({"key": "hello"}, "key", "fallback") == "hello")


def test_coerce_text_coerces_non_string():
    ensure(_coerce_text({"key": 42}, "key", "fallback") == "42")


def test_coerce_text_uses_default_for_falsy():
    ensure(_coerce_text({"key": ""}, "key", "default") == "default")


# --- _coerce_flag ---
def test_coerce_flag_returns_false_by_default():
    ensure(_coerce_flag({}, "key") is False)


def test_coerce_flag_returns_true_for_truthy():
    ensure(_coerce_flag({"key": True}, "key") is True)


# --- _coerce_items ---
def test_coerce_items_returns_empty_for_missing():
    ensure(_coerce_items({}, "key") == [])


def test_coerce_items_returns_empty_for_non_list():
    ensure(_coerce_items({"key": "notalist"}, "key") == [])


def test_coerce_items_filters_non_strings():
    ensure(_coerce_items({"key": ["a", 1, "b"]}, "key") == ["a", "b"])


def test_coerce_items_handles_none():
    ensure(_coerce_items({"key": None}, "key") == [])


# --- _coerce_number ---
def test_coerce_number_returns_default_for_missing():
    ensure(_coerce_number({}, "key", 10) == 10)


def test_coerce_number_returns_int_value():
    ensure(_coerce_number({"key": 42}, "key", 0) == 42)


def test_coerce_number_returns_default_for_bool():
    ensure(_coerce_number({"key": True}, "key", 7) == 7)


def test_coerce_number_handles_float():
    ensure(_coerce_number({"key": 3.9}, "key", 0) == 3)


def test_coerce_number_parses_string_int():
    ensure(_coerce_number({"key": "  5  "}, "key", 0) == 5)


def test_coerce_number_returns_default_for_bad_string():
    ensure(_coerce_number({"key": "abc"}, "key", 9) == 9)


def test_coerce_number_returns_default_for_empty_string():
    ensure(_coerce_number({"key": "  "}, "key", 9) == 9)


def test_coerce_number_returns_default_for_other_types():
    """Branch: value is not bool, int, float, or str (e.g. a list)."""
    ensure(_coerce_number({"key": [1, 2]}, "key", 9) == 9)


def test_coerce_number_returns_default_for_none():
    ensure(_coerce_number({"key": None}, "key", 9) == 9)


# --- select_theme_name ---
def test_select_theme_name_nt_vista():
    ensure(select_theme_name("nt", ["clam", "vista", "default"]) == "vista")


def test_select_theme_name_nt_xpnative():
    ensure(select_theme_name("nt", ["clam", "xpnative", "default"]) == "xpnative")


def test_select_theme_name_nt_clam_fallback():
    ensure(select_theme_name("nt", ["clam", "default"]) == "clam")


def test_select_theme_name_nt_none():
    ensure(select_theme_name("nt", ["default", "alt"]) is None)


def test_select_theme_name_posix_clam():
    ensure(select_theme_name("posix", ["clam", "default"]) == "clam")


def test_select_theme_name_posix_none():
    ensure(select_theme_name("posix", ["default", "alt"]) is None)


# --- resolve_context_selection ---
def test_resolve_context_selection_current_in_contexts():
    result = resolve_context_selection(
        contexts=["linux", "windows"],
        current_context="windows",
        current_wsl_distro="",
        runtime_context="linux",
    )
    ensure(result.context == "windows")
    ensure(result.wsl_distro == "")
    ensure(result.distros == [])


def test_resolve_context_selection_fallback_to_first():
    result = resolve_context_selection(
        contexts=["linux", "windows"],
        current_context="missing",
        current_wsl_distro="",
        runtime_context="linux",
    )
    ensure(result.context == "linux")


def test_resolve_context_selection_fallback_to_runtime():
    result = resolve_context_selection(
        contexts=[],
        current_context="missing",
        current_wsl_distro="",
        runtime_context="linux",
    )
    ensure(result.context == "linux")


def test_resolve_context_selection_with_wsl_distros():
    result = resolve_context_selection(
        contexts=["linux", "wsl:Ubuntu", "wsl:Debian"],
        current_context="linux",
        current_wsl_distro="Ubuntu",
        runtime_context="linux",
    )
    ensure(result.distros == ["Ubuntu", "Debian"])
    ensure(result.wsl_distro == "Ubuntu")


def test_resolve_context_selection_wsl_distro_fallback_to_first():
    result = resolve_context_selection(
        contexts=["linux", "wsl:Ubuntu", "wsl:Debian"],
        current_context="linux",
        current_wsl_distro="Missing",
        runtime_context="linux",
    )
    ensure(result.wsl_distro == "Ubuntu")


def test_resolve_context_selection_wsl_distro_empty_when_none():
    result = resolve_context_selection(
        contexts=["linux"],
        current_context="linux",
        current_wsl_distro="Ubuntu",
        runtime_context="linux",
    )
    ensure(result.wsl_distro == "")


# --- reconcile_selected_targets ---
def test_reconcile_selected_targets_empty_selects_all():
    result = reconcile_selected_targets([], ["a", "b", "c"])
    ensure(result == ["a", "b", "c"])


def test_reconcile_selected_targets_prunes_unavailable():
    result = reconcile_selected_targets(["a", "d"], ["a", "b", "c"])
    ensure(result == ["a"])


def test_reconcile_selected_targets_all_gone_selects_all():
    result = reconcile_selected_targets(["x", "y"], ["a", "b"])
    ensure(result == ["a", "b"])


# --- has_multiple_dotenv_matches ---
def test_has_multiple_dotenv_matches_true():
    records = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="KEY", source_type="dotenv"),
    ]
    ensure(has_multiple_dotenv_matches(records, "KEY") is True)


def test_has_multiple_dotenv_matches_false_single():
    records = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="OTHER", source_type="dotenv"),
    ]
    ensure(has_multiple_dotenv_matches(records, "KEY") is False)


def test_has_multiple_dotenv_matches_ignores_non_dotenv():
    records = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="KEY", source_type="windows"),
    ]
    ensure(has_multiple_dotenv_matches(records, "KEY") is False)


def test_has_multiple_dotenv_matches_wsl_dotenv():
    records = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="KEY", source_type="wsl_dotenv"),
    ]
    ensure(has_multiple_dotenv_matches(records, "KEY") is True)


# --- build_status_line ---
def test_build_status_line_with_datetime():
    dt = datetime(2024, 1, 15, 10, 30, 45)
    line = build_status_line(5, 10, "linux", dt)
    ensure("5" in line)
    ensure("10" in line)
    ensure("linux" in line)
    ensure("10:30:45" in line)


def test_build_status_line_with_none():
    line = build_status_line(0, 0, "windows", None)
    ensure("-" in line)


# --- resolve_selected_targets ---
def test_resolve_selected_targets_with_existing_targets():
    result = resolve_selected_targets(
        selected_targets=["a", "b"],
        choose_targets=lambda: None,
        key="KEY",
        maybe_choose_dotenv_targets=lambda k, t: t,
    )
    ensure(result == ["a", "b"])


def test_resolve_selected_targets_empty_triggers_chooser():
    result = resolve_selected_targets(
        selected_targets=[],
        choose_targets=lambda: ["x"],
        key="KEY",
        maybe_choose_dotenv_targets=lambda k, t: t,
    )
    ensure(result == ["x"])


def test_resolve_selected_targets_chooser_returns_none():
    result = resolve_selected_targets(
        selected_targets=[],
        choose_targets=lambda: None,
        key="KEY",
        maybe_choose_dotenv_targets=lambda k, t: t,
    )
    ensure(result is None)


def test_resolve_selected_targets_chooser_returns_empty():
    result = resolve_selected_targets(
        selected_targets=[],
        choose_targets=lambda: [],
        key="KEY",
        maybe_choose_dotenv_targets=lambda k, t: t,
    )
    ensure(result is None)


def test_resolve_selected_targets_dotenv_scoping():
    result = resolve_selected_targets(
        selected_targets=["a"],
        choose_targets=lambda: None,
        key="KEY",
        maybe_choose_dotenv_targets=lambda k, t: ["scoped"],
    )
    ensure(result == ["scoped"])


# --- summarize_operation_result ---
def test_summarize_batch_success():
    result = summarize_operation_result(
        "set", {"results": [{"success": True}, {"success": True}]}
    )
    ensure(result.status_message is not None)
    ensure("2 targets" in result.status_message)
    ensure(result.error_message is None)


def test_summarize_batch_failures():
    result = summarize_operation_result(
        "set", {"results": [{"success": False, "error_message": "oops"}]}
    )
    ensure(result.error_message is not None)
    ensure("oops" in result.error_message)
    ensure(result.status_message is None)


def test_summarize_single_success():
    result = summarize_operation_result(
        "set", {"success": True, "operation_id": "op-1"}
    )
    ensure(result.status_message is not None)
    ensure("op-1" in result.status_message)
    ensure(result.error_message is None)


def test_summarize_single_failure():
    result = summarize_operation_result(
        "set", {"success": False, "error_message": "fail"}
    )
    ensure(result.error_message is not None)
    ensure("fail" in result.error_message)


# --- select_target_dialog_result ---
def test_select_target_dialog_result_none():
    result = select_target_dialog_result(None, messagebox=None, app_name="Test")
    ensure(result is None)


def test_select_target_dialog_result_empty():
    class FakeMsgBox:
        """Stub messagebox for testing dialog result helpers."""

        @staticmethod
        def showinfo(*_args: object) -> None:
            """Stub for testing."""

    result = select_target_dialog_result([], messagebox=FakeMsgBox(), app_name="Test")
    ensure(result is None)


def test_select_target_dialog_result_with_values():
    result = select_target_dialog_result(["a", "b"], messagebox=None, app_name="Test")
    ensure(result == ["a", "b"])


# --- build_effective_value_text ---
def test_build_effective_value_text_no_key():
    result = build_effective_value_text(
        None, context="linux", key="", show_secrets=False
    )
    ensure("select key" in result)


def test_build_effective_value_text_no_record():
    result = build_effective_value_text(
        None, context="linux", key="MISS", show_secrets=False
    )
    ensure("not found" in result)


def test_build_effective_value_text_with_record():
    rec = _make_record(name="K", value="v")
    result = build_effective_value_text(
        rec, context="linux", key="K", show_secrets=True
    )
    ensure("K=v" in result)
    ensure("linux" in result)


# --- PersistedUiState ---
def test_persisted_ui_state_to_dict_roundtrip():
    state = PersistedUiState(context="test", scan_depth=10)
    d = state.to_dict()
    restored = PersistedUiState.from_dict(d)
    ensure(restored.context == "test")
    ensure(restored.scan_depth == 10)
