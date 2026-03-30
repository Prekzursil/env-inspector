"""Coverage tests for env_inspector_gui.controller — expand on existing harness patterns."""

from __future__ import absolute_import, division

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple, cast
from unittest.mock import MagicMock, patch

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller import EnvInspectorController, EnvInspectorApp
from env_inspector_gui.models import DisplayedRow, PersistedUiState

from tests.assertions import ensure


class _Var:
    """Minimal tkinter variable stub for testing."""

    def __init__(self, value: Any = "") -> None:
        """Handle   init  ."""
        self._value = value

    def get(self) -> Any:
        """Handle get."""
        return self._value

    def set(self, value: Any) -> None:
        """Handle set."""
        self._value = value


class _BootstrapRoot:
    """Minimal Tk root window stub for controller tests."""

    def __init__(self) -> None:
        """Handle   init  ."""
        self._geometry = "1480x860"
        self._focused = None

    @staticmethod
    def title(_title: str) -> None:
        """Stub for testing."""

    @staticmethod
    def protocol(*_args: object) -> None:
        """Stub for testing."""

    @staticmethod
    def after_idle(_callback: Any) -> None:
        """Stub for testing."""

    def geometry(self, value: str | None = None) -> str:
        """Handle geometry."""
        if value is not None:
            self._geometry = value
        return self._geometry

    @staticmethod
    def bind(*_args: object) -> None:
        """Stub for testing."""

    def focus_get(self) -> Any:
        """Handle focus get."""
        return self._focused

    @staticmethod
    def destroy() -> None:
        """Stub for testing."""

    @staticmethod
    def mainloop() -> None:
        """Stub for testing."""

    @staticmethod
    def clipboard_clear() -> None:
        """Stub for testing."""

    @staticmethod
    def clipboard_append(_text: str) -> None:
        """Stub for testing."""


_BOOTSTRAP_TK_MODULE = SimpleNamespace(
    Tk=_BootstrapRoot,
    StringVar=_Var,
    BooleanVar=_Var,
    IntVar=_Var,
)


class _MockView:
    """Stub view recording method calls for controller tests."""

    def __init__(self) -> None:
        """Handle   init  ."""
        self.enabled_states: List[bool] = []
        self.busy_states: List[bool] = []
        self.status_texts: List[str] = []
        self.root_labels: List[str] = []
        self.details_values: List[str] = []
        self.details_enabled: List[bool] = []
        self.context_values: List[List[str]] = []
        self.tree = MagicMock()
        self.tree.selection = MagicMock(return_value=())
        self.tree.get_children = MagicMock(return_value=[])
        self.tree.insert = MagicMock(return_value="item1")
        self.tree.delete = MagicMock()
        self.tree.tag_configure = MagicMock()
        self.details_vars: Dict[str, _Var] = {
            "name": _Var(""),
            "context": _Var(""),
            "source": _Var(""),
            "source_path": _Var(""),
            "secret": _Var(""),
            "persistent": _Var(""),
            "mutable": _Var(""),
            "writable": _Var(""),
            "requires_privilege": _Var(""),
            "precedence_rank": _Var(""),
        }
        self.detail_open_button = MagicMock()
        self.filter_entry = MagicMock()

    def set_mutation_actions_enabled(self, enabled: bool) -> None:
        """Handle set mutation actions enabled."""
        self.enabled_states.append(enabled)

    def set_refresh_busy(self, busy: bool) -> None:
        """Handle set refresh busy."""
        self.busy_states.append(busy)

    def set_status(self, text: str) -> None:
        """Handle set status."""
        self.status_texts.append(text)

    def set_root_label(self, text: str) -> None:
        """Handle set root label."""
        self.root_labels.append(text)

    def set_context_values(self, contexts: List[str]) -> None:
        """Handle set context values."""
        self.context_values.append(contexts)

    def set_wsl_distros(self, distros: List[str], *, enabled: bool) -> None:
        """Stub for testing."""

    def configure_row_styles(self) -> None:
        """Stub for testing."""

    def clear_table(self) -> None:
        """Stub for testing."""

    def insert_table_row(self, values: Tuple[Any, ...], *, striped: bool) -> str:
        """Handle insert table row."""
        return "item1"

    def update_details_value(self, text: str) -> None:
        """Handle update details value."""
        self.details_values.append(text)

    def set_details_enabled(self, enabled: bool) -> None:
        """Handle set details enabled."""
        self.details_enabled.append(enabled)

    def focus_filter(self) -> None:
        """Stub for testing."""


class _Harness(EnvInspectorController):
    """Full harness with mocked internals."""

    def __init__(self) -> None:
        """Handle   init  ."""
        self._during_bootstrap = True
        super().__init__(Path.cwd())
        self._during_bootstrap = False

    @staticmethod
    def _load_tk_modules() -> Tuple[Any, Any, Any, Any]:
        """Handle  load tk modules."""
        return (
            _BOOTSTRAP_TK_MODULE,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        )

    def _init_root_window(self, _tk: Any) -> None:
        """Handle  init root window."""
        self.tk = _BootstrapRoot()

    def _apply_theme(self) -> None:
        """Stub for testing."""

    def _load_boot_state(self, _root_path: Path) -> Tuple[PersistedUiState, Path]:
        """Handle  load boot state."""
        return PersistedUiState(context="linux"), Path.cwd()

    def _initialize_view(self, _tk: Any, _ttk: Any, _boot_state: PersistedUiState) -> None:
        """Handle  initialize view."""
        self.view = cast(Any, _MockView())

    def _bind_shortcuts(self) -> None:
        """Stub for testing."""

    def refresh_data(self) -> None:
        """Handle refresh data."""
        if getattr(self, "_during_bootstrap", False):
            return
        super().refresh_data()


def _make_record(**overrides: object) -> EnvRecord:
    """Handle  make record."""
    defaults: Dict[str, Any] = {
        "source_type": "dotenv",
        "source_id": "dotenv:/workspace/.env",
        "source_path": "/workspace/.env",
        "context": "linux",
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


def _make_row(rec: EnvRecord) -> DisplayedRow:
    """Handle  make row."""
    return DisplayedRow(
        record=rec,
        visible_value=rec.value,
        search_value="",
        source_label=rec.source_type,
        secret_text="no",
        persistent_text="no",
        mutable_text="no",
        writable_text="no",
        requires_privilege_text="no",
        original_index=0,
    )


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
    ctrl.state_dir = Path("/tmp/test_state")
    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.on_filter_changed()


def test_on_filter_changed_no_key():
    """Test on filter changed no key."""
    ctrl = _Harness()
    ctrl.key_text = _Var("")
    ctrl.records_raw = []
    ctrl.service = MagicMock()
    ctrl.service.runtime_context = "linux"
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")

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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")

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

    with patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]), \
         patch.object(ctrl, "_confirm_diff", return_value=False):
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

    with patch.object(ctrl, "_maybe_choose_dotenv_targets", return_value=["a"]), \
         patch.object(ctrl, "_confirm_diff", return_value=True):
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    with patch.object(EnvInspectorController, "__init__", return_value=None), \
         patch.object(EnvInspectorController, "run"):
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
    ctrl.state_dir = Path("/tmp/nonexistent_state_dir_test")
    cwd = Path.cwd()
    with patch("env_inspector_gui.controller.load_ui_state", return_value=PersistedUiState()), \
         patch("env_inspector_gui.controller.resolve_scan_root", return_value=cwd), \
         patch("env_inspector_gui.controller.sanitize_loaded_state", return_value=PersistedUiState(context="linux")):
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
    for mod_name in ("tkinter", "tkinter.filedialog", "tkinter.messagebox", "tkinter.ttk"):
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
    ctrl.state_dir = Path("/tmp/test_state")
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
    ctrl.state_dir = Path("/tmp/test_state")

    # Let the refresh proceed normally but set tk to None just before _persist_state
    original_render_table = ctrl._render_table

    def render_then_clear_tk():
        """Handle render then clear tk."""
        original_render_table()
        ctrl.tk = None  # type: ignore[assignment]

    with patch.object(ctrl, "_render_table", side_effect=render_then_clear_tk), \
         patch("env_inspector_gui.controller.save_ui_state") as mock_save:
        ctrl.refresh_data()

    ensure(ctrl.last_refresh_at is not None)
    # _persist_state should NOT have been called since tk was None
    mock_save.assert_not_called()


def test_report_operation_result_both_none():
    """Cover branch 485->exit: both status_message and error_message are None."""
    ctrl = _Harness()
    ctrl.messagebox = MagicMock()
    # Manually construct a result that produces both None
    with patch("env_inspector_gui.controller.summarize_operation_result") as mock_summary:
        from env_inspector_gui.models import OperationResultSummary
        mock_summary.return_value = OperationResultSummary(status_message=None, error_message=None)
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
    ctrl.state_dir = Path("/tmp/test_state")

    with patch("env_inspector_gui.controller.save_ui_state"):
        ctrl.refresh_data()

    ensure(ctrl.last_refresh_at is not None)
