"""Coverage tests for env_inspector_gui.controller — operations and boot-state branches.

Split out of test_gui_controller_coverage.py to keep each module under
Lizard's "medium" non-comment-LOC budget so the Codacy file-size lint
no longer fires on this file.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from env_inspector_gui.controller import EnvInspectorApp, EnvInspectorController
from env_inspector_gui.models import PersistedUiState
from tests._gui_controller_fixtures import (
    _Harness,
    _make_record,
    _Var,
)
from tests.assertions import ensure


def test_resolve_operation_inputs_no_key():
    """Test resolve operation inputs no key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("")
    ctrl.messagebox = MagicMock()
    result = ctrl._resolve_operation_inputs()
    ensure(result is None)
    ctrl.messagebox.showerror.assert_called_once()


def test_resolve_operation_inputs_with_key():
    """Test resolve operation inputs with key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("TEST")
    ctrl.value_text = _Var("val")
    ctrl.selected_targets = ["a"]
    ctrl.records_raw = []
    ctrl.messagebox = MagicMock()

    with patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]):
        result = ctrl._resolve_operation_inputs()

    ensure(result is not None)
    ensure(result[0] == "TEST")


def test_resolve_operation_inputs_scoped_none():
    """Test resolve operation inputs scoped none."""
    ctrl = _Harness()
    ctrl.key_text = _Var("TEST")
    ctrl.value_text = _Var("val")
    ctrl.selected_targets = ["a"]
    ctrl.records_raw = []
    ctrl.messagebox = MagicMock()

    with patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=None):
        result = ctrl._resolve_operation_inputs()

    ensure(result is None)


# --- _safe_preview ---
def test_safe_preview_success():
    """Test safe preview success."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(return_value=[{"success": True}])
    result = ctrl._safe_preview("set", "KEY", "val", ["t"])
    ensure(result is not None)


def test_safe_preview_error():
    """Test safe preview error."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(side_effect=OSError("disk full"))
    ctrl.messagebox = MagicMock()
    result = ctrl._safe_preview("set", "KEY", "val", ["t"])
    ensure(result is None)
    ctrl.messagebox.showerror.assert_called_once()


# --- _safe_apply ---
def test_safe_apply_success():
    """Test safe apply success."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.set_key = MagicMock(return_value={"success": True})
    result = ctrl._safe_apply("set", "KEY", "val", ["t"])
    ensure(result is not None)


def test_safe_apply_error():
    """Test safe apply error."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.set_key = MagicMock(side_effect=RuntimeError("fail"))
    ctrl.messagebox = MagicMock()
    result = ctrl._safe_apply("set", "KEY", "val", ["t"])
    ensure(result is None)
    ctrl.messagebox.showerror.assert_called_once()


# --- _report_operation_result ---
def test_report_operation_result_success():
    """Test report operation result success."""
    ctrl = _Harness()
    ctrl.messagebox = MagicMock()
    ctrl._report_operation_result("set", {"success": True, "operation_id": "op-1"})
    ensure(any("op-1" in t for t in ctrl.view.status_texts))


def test_report_operation_result_failure():
    """Test report operation result failure."""
    ctrl = _Harness()
    ctrl.messagebox = MagicMock()
    ctrl._report_operation_result("set", {"success": False, "error_message": "bad"})
    ctrl.messagebox.showerror.assert_called_once()


# --- _run_operation full flow ---
def test_run_operation_no_key():
    """Test run operation no key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("")
    ctrl.messagebox = MagicMock()
    ctrl._run_operation("set")
    ctrl.messagebox.showerror.assert_called_once()


def test_run_operation_preview_fails():
    """Test run operation preview fails."""
    ctrl = _Harness()
    ctrl.key_text = _Var("K")
    ctrl.value_text = _Var("v")
    ctrl.selected_targets = ["a"]
    ctrl.records_raw = []
    ctrl.messagebox = MagicMock()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(side_effect=OSError("fail"))

    with patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]):
        ctrl._run_operation("set")

    ctrl.messagebox.showerror.assert_called()


def test_run_operation_diff_rejected():
    """Test run operation diff rejected."""
    ctrl = _Harness()
    ctrl.key_text = _Var("K")
    ctrl.value_text = _Var("v")
    ctrl.selected_targets = ["a"]
    ctrl.records_raw = []
    ctrl.messagebox = MagicMock()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(return_value=[{"success": True}])

    with (
        patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]),
        patch.object(ctrl, "_confirm_diff", return_value=False),
    ):
        ctrl._run_operation("set")

    # Apply should NOT be called
    ctrl.service.set_key.assert_not_called()


def test_run_operation_apply_fails():
    """Test run operation apply fails."""
    ctrl = _Harness()
    ctrl.key_text = _Var("K")
    ctrl.value_text = _Var("v")
    ctrl.selected_targets = ["a"]
    ctrl.records_raw = []
    ctrl.messagebox = MagicMock()
    ctrl.service = MagicMock()
    ctrl.service.preview_set = MagicMock(return_value=[{"success": True}])
    ctrl.service.set_key = MagicMock(side_effect=RuntimeError("boom"))

    with (
        patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]),
        patch.object(ctrl, "_confirm_diff", return_value=True),
    ):
        ctrl._run_operation("set")

    ctrl.messagebox.showerror.assert_called()


# --- _update_context_values ---
def test_update_context_values():
    """Test update context values."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux", "wsl:Ubuntu"])
    ctrl.service.runtime_context = "linux"
    ctrl._update_context_values()
    ensure(ctrl.context_var.get() == "linux")


# --- _fetch_records ---
def test_fetch_records_basic():
    """Test fetch records basic."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl._fetch_records()
    ensure(ctrl.records_raw == [])


def test_fetch_records_with_wsl():
    """Test fetch records with wsl."""
    ctrl = _Harness()
    ctrl.wsl_distro_var = _Var("Ubuntu")
    ctrl.wsl_path_var = _Var("/home/user")
    ctrl.service = MagicMock()
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl._fetch_records()
    ensure(ctrl.records_raw == [])


# --- _reconcile_targets ---
def test_reconcile_targets():
    """Test reconcile targets."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.available_targets = MagicMock(return_value=["a", "b"])
    ctrl.records_raw = []
    ctrl.targets_summary_var = _Var("")
    ctrl._reconcile_targets()
    ensure(len(ctrl.selected_targets) > 0)


# --- _render_table ---
def test_render_table():
    """Test render table."""
    ctrl = _Harness()
    ctrl.records_raw = [_make_record(name="A", value="1")]
    ctrl.service = MagicMock()
    ctrl.service.runtime_context = "linux"
    ctrl._render_table()
    ensure(len(ctrl.displayed_rows) > 0)


# --- _update_effective ---
def test_update_effective():
    """Test update effective."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.service.runtime_context = "linux"
    ctrl._update_effective("KEY")
    ensure("not found" in ctrl.effective_value_var.get())


# --- _on_ctrl_f ---
def test_on_ctrl_f():
    """Test on ctrl f."""
    ctrl = _Harness()
    result = ctrl._on_ctrl_f(None)
    ensure(result == "break")


# --- _on_f5 ---
def test_on_f5():
    """Test on f5."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.service.runtime_context = "linux"
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.state_dir = Path("/var/state-fixture")
    with patch("env_inspector_gui.controller.save_ui_state"):
        result = ctrl._on_f5(None)
    ensure(result == "break")


# --- _on_ctrl_c ---
def test_on_ctrl_c_on_tree():
    """Test on ctrl c on tree."""
    ctrl = _Harness()
    ctrl.tk._focused = ctrl.view.tree
    ctrl.messagebox = MagicMock()
    # No row selected, should show message
    result = ctrl._on_ctrl_c(None)
    ensure(result == "break")


def test_on_ctrl_c_not_on_tree():
    """Test on ctrl c not on tree."""
    ctrl = _Harness()
    ctrl.tk._focused = None
    result = ctrl._on_ctrl_c(None)
    ensure(result is None)


# --- _resolve_root_path ---
def test_resolve_root_path_valid(tmp_path: Path):
    """Test resolve root path valid."""
    state = PersistedUiState(root_path=str(tmp_path))
    result = EnvInspectorController._resolve_root_path(state, tmp_path)
    ensure(str(result) == str(tmp_path))


def test_resolve_root_path_invalid():
    """Test resolve root path invalid."""
    state = PersistedUiState(root_path="/nonexistent/invalid/path/xxx")
    fallback = Path.cwd()
    result = EnvInspectorController._resolve_root_path(state, fallback)
    ensure(str(result) == str(fallback))


# --- EnvInspectorApp ---
def test_env_inspector_app():
    """Test env inspector app."""
    with (
        patch.object(EnvInspectorController, "__init__", return_value=None),
        patch.object(EnvInspectorController, "run"),
    ):
        app = EnvInspectorApp(Path.cwd())
        app._controller = MagicMock()
        app.run()
        app._controller.run.assert_called_once()


# --- Real method tests (not overridden) ---


def test_real_init_root_window():
    """Cover lines 72-73: _init_root_window with real implementation."""
    ctrl = _Harness()
    mock_tk = MagicMock()
    mock_root = MagicMock()
    mock_tk.Tk = MagicMock(return_value=mock_root)
    EnvInspectorController._init_root_window(ctrl, mock_tk)
    ensure(ctrl.tk is mock_root)
    mock_root.title.assert_called_once()


def test_real_load_boot_state():
    """Cover lines 76-84: _load_boot_state with real implementation."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.state_dir = Path("/var/nonexistent-state-dir-test")
    cwd = Path.cwd()
    with (
        patch(
            "env_inspector_gui.controller.load_ui_state",
            return_value=PersistedUiState(),
        ),
        patch("env_inspector_gui.controller.resolve_scan_root", return_value=cwd),
        patch(
            "env_inspector_gui.controller.sanitize_loaded_state",
            return_value=PersistedUiState(context="linux"),
        ),
    ):
        boot_state, _fallback = EnvInspectorController._load_boot_state(ctrl, cwd)
    ensure(isinstance(boot_state, PersistedUiState))
    ensure(boot_state.context == "linux")


def test_real_initialize_view():
    """Cover lines 114-117: _initialize_view with real implementation."""
    ctrl = _Harness()
    ctrl.root_path = Path.cwd()
    mock_boot = PersistedUiState(window_geometry="1200x800")
    mock_tk_mod = MagicMock()
    mock_ttk = MagicMock()
    with patch("env_inspector_gui.controller.EnvInspectorView") as MockView:
        mock_view_inst = MagicMock()
        MockView.return_value = mock_view_inst
        EnvInspectorController._initialize_view(ctrl, mock_tk_mod, mock_ttk, mock_boot)
    ensure(ctrl.view is mock_view_inst)
    mock_view_inst.set_root_label.assert_called_once()
    mock_view_inst.configure_row_styles.assert_called_once()


def test_real_apply_theme():
    """Cover lines 120-126: _apply_theme with real implementation."""
    ctrl = _Harness()
    ctrl.tk = MagicMock()
    mock_style = MagicMock()
    mock_style.theme_names = MagicMock(return_value=("clam", "default"))
    ctrl.ttk = MagicMock()
    ctrl.ttk.Style = MagicMock(return_value=mock_style)
    EnvInspectorController._apply_theme(ctrl)
    mock_style.theme_use.assert_called_with("clam")
    mock_style.configure.assert_called_with("Treeview", rowheight=24)


def test_real_apply_theme_no_matching():
    """Cover lines 120-126: _apply_theme when no theme matches."""
    ctrl = _Harness()
    ctrl.tk = MagicMock()
    mock_style = MagicMock()
    mock_style.theme_names = MagicMock(return_value=("default", "alt"))
    ctrl.ttk = MagicMock()
    ctrl.ttk.Style = MagicMock(return_value=mock_style)
    EnvInspectorController._apply_theme(ctrl)
    mock_style.theme_use.assert_not_called()
    mock_style.configure.assert_called_with("Treeview", rowheight=24)


def test_real_bind_shortcuts():
    """Cover lines 129-131: _bind_shortcuts with real implementation."""
    ctrl = _Harness()
    ctrl.tk = MagicMock()
    EnvInspectorController._bind_shortcuts(ctrl)
    ensure(ctrl.tk.bind.call_count == 3)


def test_real_load_tk_modules():
    """Cover lines 56-63: _load_tk_modules with mocked tkinter."""
    import sys

    mock_filedialog = MagicMock()
    mock_messagebox = MagicMock()
    mock_ttk = MagicMock()
    mock_tkinter = MagicMock()
    mock_tkinter.filedialog = mock_filedialog
    mock_tkinter.messagebox = mock_messagebox
    mock_tkinter.ttk = mock_ttk

    saved = {}
    for mod_name in (
        "tkinter",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "tkinter.ttk",
    ):
        saved[mod_name] = sys.modules.get(mod_name)

    sys.modules["tkinter"] = mock_tkinter
    sys.modules["tkinter.filedialog"] = mock_filedialog
    sys.modules["tkinter.messagebox"] = mock_messagebox
    sys.modules["tkinter.ttk"] = mock_ttk
    try:
        tk, _fd, _mb, _t = EnvInspectorController._load_tk_modules()
        ensure(tk is mock_tkinter)
    finally:
        for mod_name, original in saved.items():
            if original is None:
                sys.modules.pop(mod_name, None)
            else:
                sys.modules[mod_name] = original


# --- refresh_data with view present for _on_row_selected (line 359, 360) ---


def test_refresh_data_with_view_and_selected_row():
    """Cover lines 358-360: refresh_data when view exists and tree has selection."""
    ctrl = _Harness()
    rec = _make_record(name="SELECTED", context="linux")
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.service.runtime_context = "linux"
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.service.list_records_raw = MagicMock(return_value=[rec])
    ctrl.service.resolve_effective = MagicMock(return_value=rec)
    ctrl.key_text = _Var("TEST")
    ctrl.state_dir = Path("/var/state-fixture")
    # After _render_table, rows_by_item will have the new item
    ctrl.view.tree.selection.return_value = ("item1",)

    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.refresh_data()

    ensure(ctrl.last_refresh_at is not None)
    # The view's _on_row_selected_update_details was called (details_enabled list is non-empty)
    ensure(len(ctrl.view.details_enabled) > 0)


# --- _report_operation_result with no error and no status (line 485) ---


def test_report_operation_result_no_message():
    """Cover line 485: result with no error and no status message."""
    ctrl = _Harness()
    ctrl.messagebox = MagicMock()
    ctrl._report_operation_result("set", {"success": True, "operation_id": None})


# --- Partial branch coverage ---


def test_refresh_data_with_tk_none():
    """Cover branch 360->363: tk is None during refresh, skip _persist_state."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.service.runtime_context = "linux"
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.key_text = _Var("")
    ctrl.state_dir = Path("/var/state-fixture")

    # Let the refresh proceed normally but set tk to None just before _persist_state
    original_render_table = ctrl._render_table

    def render_then_clear_tk():
        """Handle render then clear tk."""
        original_render_table()
        ctrl.tk = None  # type: ignore[assignment]

    with (
        patch.object(ctrl, "_render_table", side_effect=render_then_clear_tk),
        patch("env_inspector_gui.controller.save_ui_state") as mock_save,
    ):
        ctrl.refresh_data()

    ensure(ctrl.last_refresh_at is not None)
    # _persist_state should NOT have been called since tk was None
    mock_save.assert_not_called()


def test_report_operation_result_both_none():
    """Cover branch 485->exit: both status_message and error_message are None."""
    ctrl = _Harness()
    ctrl.messagebox = MagicMock()
    # Manually construct a result that produces both None
    with patch(
        "env_inspector_gui.controller.summarize_operation_result"
    ) as mock_summary:
        from env_inspector_gui.models import OperationResultSummary

        mock_summary.return_value = OperationResultSummary(
            status_message=None, error_message=None
        )
        ctrl._report_operation_result("set", {"success": True})
    # Neither showerror nor _set_status should be called
    ctrl.messagebox.showerror.assert_not_called()


# --- refresh_data full flow ---
def test_refresh_data_full():
    """Test refresh data full."""
    ctrl = _Harness()
    ctrl.service = MagicMock()
    ctrl.service.list_contexts = MagicMock(return_value=["linux"])
    ctrl.service.runtime_context = "linux"
    ctrl.service.available_targets = MagicMock(return_value=[])
    ctrl.service.list_records_raw = MagicMock(return_value=[])
    ctrl.service.resolve_effective = MagicMock(return_value=None)
    ctrl.key_text = _Var("TEST")
    ctrl.state_dir = Path("/var/state-fixture")

    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.refresh_data()

    ensure(ctrl.last_refresh_at is not None)
