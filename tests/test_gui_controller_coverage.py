"""Coverage tests for env_inspector_gui.controller — basic state and selection branches.

The operations / boot-state branches live in test_gui_controller_operations_coverage.py
to keep this file under Lizard's medium NLOC threshold. Both files share fixtures
from tests._gui_controller_fixtures.
"""

from __future__ import absolute_import, division

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller import EnvInspectorApp, EnvInspectorController
from env_inspector_gui.models import DisplayedRow, PersistedUiState

from tests._gui_controller_fixtures import (
    _BOOTSTRAP_TK_MODULE,
    _BootstrapRoot,
    _Harness,
    _MockView,
    _NEGATIVE_FLAG_TEXT,
    _Var,
    _make_record,
    _make_row,
)
from tests.assertions import ensure


# --- _record_flag ---
def test_record_flag():
    """Test record flag."""
    rec = _make_record(is_secret=True)
    ensure(EnvInspectorController._record_flag(rec, "is_secret") is True)
    ensure(EnvInspectorController._record_flag(rec, "nonexistent") is False)


# --- _selected_row ---
def test_selected_row_none():
    """Test selected row none."""
    ctrl = _Harness()
    ensure(ctrl._selected_row() is None)


def test_selected_row_with_item():
    """Test selected row with item."""
    ctrl = _Harness()
    rec = _make_record()
    row = _make_row(rec)
    ctrl.rows_by_item["item1"] = row
    ctrl.view.tree.selection.return_value = ("item1",)
    result = ctrl._selected_row()
    ensure(result is not None)
    ensure(result.record.name == "KEY")


# --- _on_row_selected_update_details ---
def test_on_row_selected_update_details_none():
    """Test on row selected update details none."""
    ctrl = _Harness()
    ctrl._on_row_selected_update_details(None)
    ensure(False in ctrl.view.details_enabled)


def test_on_row_selected_update_details_with_row():
    """Test on row selected update details with row."""
    ctrl = _Harness()
    rec = _make_record(name="MY_VAR", is_secret=True, is_persistent=True, is_mutable=False)
    row = _make_row(rec)
    ctrl._on_row_selected_update_details(row)
    ensure(True in ctrl.view.details_enabled)
    ensure(ctrl.view.details_vars["name"].get() == "MY_VAR")
    ensure(ctrl.view.details_vars["secret"].get() == "yes")
    ensure(ctrl.view.details_vars["persistent"].get() == "yes")
    ensure(ctrl.view.details_vars["mutable"].get() == "no")


# --- _clear_details ---
def test_clear_details():
    """Test clear details."""
    ctrl = _Harness()
    ctrl._clear_details()
    ensure(ctrl.view.details_vars["name"].get() == "")
    ensure(False in ctrl.view.details_enabled)


# --- _set_detail_values ---
def test_set_detail_values():
    """Test set detail values."""
    ctrl = _Harness()
    ctrl._set_detail_values({"name": "X", "context": "linux", "nonexistent_key": "ignored"})
    ensure(ctrl.view.details_vars["name"].get() == "X")
    ensure(ctrl.view.details_vars["context"].get() == "linux")


# --- _set_detail_pairs ---
def test_set_detail_pairs():
    """Test set detail pairs."""
    ctrl = _Harness()
    ctrl._set_detail_pairs((("name", "A"), ("source", "dotenv"), ("bad_key", "ignored")))
    ensure(ctrl.view.details_vars["name"].get() == "A")
    ensure(ctrl.view.details_vars["source"].get() == "dotenv")


# --- on_tree_selected ---
def test_on_tree_selected_with_row():
    """Test on tree selected with row."""
    ctrl = _Harness()
    rec = _make_record(name="FOUND")
    row = _make_row(rec)
    ctrl.rows_by_item["item1"] = row
    ctrl.view.tree.selection.return_value = ("item1",)
    ctrl.service = MagicMock()
    ctrl.service.resolve_effective = MagicMock(return_value=rec)
    ctrl.service.runtime_context = "linux"
    ctrl.on_tree_selected()
    ensure(ctrl.key_text.get() == "FOUND")


def test_on_tree_selected_no_row():
    """Test on tree selected no row."""
    ctrl = _Harness()
    ctrl.view.tree.selection.return_value = ()
    ctrl.on_tree_selected()
    # Should clear details
    ensure(False in ctrl.view.details_enabled)


# --- on_filter_changed ---
def test_on_filter_changed_with_key():
    """Test on filter changed with key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("TEST_KEY")
    ctrl.records_raw = []
    ctrl.service = MagicMock()
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.service.runtime_context = "linux"
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_filter_changed()


def test_on_filter_changed_no_key():
    """Test on filter changed no key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("")
    ctrl.records_raw = []
    ctrl.service = MagicMock()
    ctrl.service.runtime_context = "linux"
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_filter_changed()


# --- on_filter_escape ---
def test_on_filter_escape_with_text():
    """Test on filter escape with text."""
    ctrl = _Harness()
    ctrl.filter_text = _Var("something")
    ctrl.key_text = _Var("")
    ctrl.records_raw = []
    ctrl.service = MagicMock()
    ctrl.service.runtime_context = "linux"
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_filter_escape()
    ensure(ctrl.filter_text.get() == "")


def test_on_filter_escape_empty():
    """Test on filter escape empty."""
    ctrl = _Harness()
    ctrl.filter_text = _Var("")
    ctrl.on_filter_escape()
    # Should do nothing


# --- on_sort_column ---
def test_on_sort_column():
    """Test on sort column."""
    ctrl = _Harness()
    ctrl.records_raw = []
    ctrl.service = MagicMock()
    ctrl.service.runtime_context = "linux"
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_sort_column("value")
    ensure(ctrl.sort_state.column == "value")


# --- choose_folder ---
def test_choose_folder_cancelled():
    """Test choose folder cancelled."""
    ctrl = _Harness()
    ctrl.filedialog = MagicMock()
    ctrl.filedialog.askdirectory = MagicMock(return_value="")
    ctrl.choose_folder()
    # Should not change root_path


def test_choose_folder_selected(tmp_path: Path):
    """Test choose folder selected."""
    ctrl = _Harness()
    ctrl.filedialog = MagicMock()
    ctrl.filedialog.askdirectory = MagicMock(return_value=str(tmp_path))
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.service.runtime_context = "linux"
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.resolve_scan_root", return_value=tmp_path), \
         patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.choose_folder()
    ensure(str(ctrl.root_path) == str(tmp_path))


# --- _build_state ---
def test_build_state():
    """Test build state."""
    ctrl = _Harness()
    state = ctrl._build_state()
    ensure(isinstance(state, PersistedUiState))
    ensure(state.context == "linux")


# --- on_close ---
def test_on_close():
    """Test on close."""
    ctrl = _Harness()
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_close()


# --- run ---
def test_run():
    """Test run."""
    ctrl = _Harness()
    ctrl.tk = MagicMock()
    ctrl.run()
    ctrl.tk.mainloop.assert_called_once()


# --- _set_status with no view ---
def test_set_status_no_view():
    """Test set status no view."""
    ctrl = _Harness()
    ctrl.view = None
    ctrl._set_status("test")  # Should not raise


# --- _set_busy with no view ---
def test_set_busy_no_view():
    """Test set busy no view."""
    ctrl = _Harness()
    ctrl.view = None
    ctrl._set_busy(True)  # Should not raise


# --- _collect_dotenv_targets ---
def test_collect_dotenv_targets():
    """Test collect dotenv targets."""
    result = EnvInspectorController._collect_dotenv_targets(
        ["dotenv:/a", "windows:user", "wsl_dotenv:/b"]
    )
    ensure(result == ["dotenv:/a", "wsl_dotenv:/b"])


# --- _has_multiple_dotenv_matches ---
def test_has_multiple_dotenv_matches():
    """Test has multiple dotenv matches."""
    ctrl = _Harness()
    ctrl.records_raw = [
        _make_record(name="K", source_type="dotenv"),
        _make_record(name="K", source_type="dotenv"),
    ]
    ensure(ctrl._has_multiple_dotenv_matches("K") is True)


# --- choose_targets ---
def test_choose_targets_no_available():
    """Test choose targets no available."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.messagebox = MagicMock()
    result = ctrl.choose_targets()
    ensure(result is None)
    ctrl.messagebox.showinfo.assert_called_once()


def test_choose_targets_cancelled():
    """Test choose targets cancelled."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.available_targets = MagicMock(return_value=["a", "b"])
    ctrl.messagebox = MagicMock()
    ctrl.state_dir = Path("/var/state-fixture")

    with patch("env_inspector_gui.controller.TargetPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = None
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        result = ctrl.choose_targets()

    ensure(result is None)


def test_choose_targets_selected():
    """Test choose targets selected."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.available_targets = MagicMock(return_value=["a", "b"])
    ctrl.messagebox = MagicMock()
    ctrl.state_dir = Path("/var/state-fixture")
    ctrl.targets_summary_var = _Var("")

    with patch("env_inspector_gui.controller.TargetPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = ["a"]
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        with patch("env_inspector_gui.controller.save_ui_state"):
            result = ctrl.choose_targets()

    ensure(result == ["a"])
    ensure(ctrl.selected_targets == ["a"])


def test_choose_targets_empty_selection():
    """Test choose targets empty selection."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.available_targets = MagicMock(return_value=["a", "b"])
    ctrl.messagebox = MagicMock()
    ctrl.state_dir = Path("/var/state-fixture")

    with patch("env_inspector_gui.controller.TargetPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = []
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        result = ctrl.choose_targets()

    ensure(result is None)
    ctrl.messagebox.showinfo.assert_called()


# --- _maybe_choose_dotenv_targets ---
def test_maybe_choose_dotenv_targets_single():
    """Test maybe choose dotenv targets single."""
    ctrl = _Harness()
    ctrl.records_raw = []
    result = ctrl._maybe_choose_dotenv_targets("KEY", ["dotenv:/a"])
    ensure(result == ["dotenv:/a"])


def test_maybe_choose_dotenv_targets_multiple_cancelled():
    """Test maybe choose dotenv targets multiple cancelled."""
    ctrl = _Harness()
    ctrl.records_raw = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="KEY", source_type="dotenv"),
    ]

    with patch("env_inspector_gui.controller.DotenvTargetDialog") as MockDialog:
        instance = MagicMock()
        instance.result = None
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        result = ctrl._maybe_choose_dotenv_targets("KEY", ["dotenv:/a", "dotenv:/b"])

    ensure(result is None)


def test_maybe_choose_dotenv_targets_multiple_selected():
    """Test maybe choose dotenv targets multiple selected."""
    ctrl = _Harness()
    ctrl.records_raw = [
        _make_record(name="KEY", source_type="dotenv"),
        _make_record(name="KEY", source_type="dotenv"),
    ]

    with patch("env_inspector_gui.controller.DotenvTargetDialog") as MockDialog:
        instance = MagicMock()
        instance.result = ["dotenv:/a"]
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        result = ctrl._maybe_choose_dotenv_targets("KEY", ["dotenv:/a", "dotenv:/b", "windows:user"])

    ensure(result is not None)
    ensure("dotenv:/a" in result)
    ensure("windows:user" in result)
    ensure("dotenv:/b" not in result)


# --- _preview_operation ---
def test_preview_operation_set():
    """Test preview operation set."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(return_value=[{"success": True}])
    result = ctrl._preview_operation("set", "KEY", "val", ["t"])
    ensure(result == [{"success": True}])


def test_preview_operation_remove():
    """Test preview operation remove."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.preview_remove = MagicMock(return_value=[{"success": True}])
    result = ctrl._preview_operation("remove", "KEY", "", ["t"])
    ensure(result == [{"success": True}])


# --- _confirm_diff ---
def test_confirm_diff():
    """Test confirm diff."""
    ctrl = _Harness()
    with patch("env_inspector_gui.controller.DiffPreviewDialog") as MockDialog:
        instance = MagicMock()
        instance.confirmed = True
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk = MagicMock()
        result = ctrl._confirm_diff("set", [{"success": True}])
    ensure(result is True)


# --- _apply_operation ---
def test_apply_operation_set():
    """Test apply operation set."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.set_key = MagicMock(return_value={"success": True})
    result = ctrl._apply_operation("set", "KEY", "val", ["t"])
    ensure(result["success"] is True)


def test_apply_operation_remove():
    """Test apply operation remove."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.remove_key = MagicMock(return_value={"success": True})
    result = ctrl._apply_operation("remove", "KEY", "", ["t"])
    ensure(result["success"] is True)


# --- _resolve_operation_inputs ---
