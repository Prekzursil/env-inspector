"""Coverage tests for env_inspector_gui.view — full coverage via mocked tkinter."""

from __future__ import absolute_import, division

from typing import Any, List
from unittest.mock import MagicMock

from tests.assertions import ensure


def _make_mock_widget(**extras: Any) -> MagicMock:
    """Create a mock widget that supports common tk/ttk methods."""
    w = MagicMock()
    w.pack = MagicMock()
    w.grid = MagicMock()
    w.configure = MagicMock()
    w.config = MagicMock()
    for k, v in extras.items():
        setattr(w, k, v)
    return w


class _MockTkModule:
    """Mock for the `tkinter` module (tkmod)."""

    def __init__(self) -> None:
        self._vars: List[MagicMock] = []

    def StringVar(self, value: str = "") -> MagicMock:
        var = MagicMock()
        var.get = MagicMock(return_value=value)
        var.set = MagicMock()
        self._vars.append(var)
        return var

    def Text(self, parent: Any, **kwargs: Any) -> MagicMock:
        t = _make_mock_widget()
        t.delete = MagicMock()
        t.insert = MagicMock()
        t.xview = MagicMock()
        return t


class _MockTtk:
    """Mock for tkinter.ttk module."""

    def Frame(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def Label(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def Button(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def Entry(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.bind = MagicMock()
        w.focus_set = MagicMock()
        w.selection_range = MagicMock()
        return w

    def Combobox(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.bind = MagicMock()
        return w

    def Checkbutton(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def Scrollbar(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def LabelFrame(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.columnconfigure = MagicMock()
        w.rowconfigure = MagicMock()
        return w

    def PanedWindow(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.add = MagicMock()
        return w

    def Treeview(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.heading = MagicMock()
        w.column = MagicMock()
        w.bind = MagicMock()
        w.get_children = MagicMock(return_value=[])
        w.delete = MagicMock()
        w.insert = MagicMock(return_value="item1")
        w.tag_configure = MagicMock()
        w.selection = MagicMock(return_value=())
        w.yview = MagicMock()
        w.xview = MagicMock()
        w.set = MagicMock()
        return w

    def Spinbox(self, parent: Any, **kwargs: Any) -> MagicMock:
        return _make_mock_widget()

    def Progressbar(self, parent: Any, **kwargs: Any) -> MagicMock:
        w = _make_mock_widget()
        w.start = MagicMock()
        w.stop = MagicMock()
        return w


class _MockController:
    """Stub controller with all attributes the view expects."""

    def __init__(self, tk_root: MagicMock) -> None:
        self.tk = tk_root
        self.root_path = "/workspace"
        self.context_var = MagicMock()
        self.show_secrets = MagicMock()
        self.only_secrets = MagicMock()
        self.filter_text = MagicMock()
        self.wsl_distro_var = MagicMock()
        self.wsl_path_var = MagicMock()
        self.scan_depth_var = MagicMock()
        self.key_text = MagicMock()
        self.value_text = MagicMock()
        self.targets_summary_var = MagicMock()
        self.effective_value_var = MagicMock()

    def choose_folder(self) -> None:
        """Stub for testing."""

    def refresh_data(self) -> None:
        """Stub for testing."""

    def on_context_selected(self) -> None:
        """Stub for testing."""

    def on_filter_changed(self) -> None:
        """Stub for testing."""

    def on_filter_escape(self) -> None:
        """Stub for testing."""

    def on_sort_column(self, col: str) -> None:
        """Stub for testing."""

    def on_tree_selected(self) -> None:
        """Stub for testing."""

    def copy_selected_name(self) -> None:
        """Stub for testing."""

    def copy_selected_value(self) -> None:
        """Stub for testing."""

    def copy_selected_pair(self) -> None:
        """Stub for testing."""

    def copy_selected_source_path(self) -> None:
        """Stub for testing."""

    def open_selected_source(self) -> None:
        """Stub for testing."""

    def load_selected(self) -> None:
        """Stub for testing."""

    def choose_targets(self) -> None:
        """Stub for testing."""

    def _run_operation(self, action: str) -> None:
        """Stub for testing."""

    def export_records(self, fmt: str) -> None:
        """Stub for testing."""

    def restore_backup(self) -> None:
        """Stub for testing."""


def _build_view():
    """Build an EnvInspectorView with fully mocked tkinter."""
    from env_inspector_gui.view import EnvInspectorView

    tk_root = _make_mock_widget()
    tk_root.columnconfigure = MagicMock()
    tk_root.rowconfigure = MagicMock()

    tkmod = _MockTkModule()
    ttk = _MockTtk()
    controller = _MockController(tk_root)

    view = EnvInspectorView(tkmod, ttk, controller)
    return view


def test_view_builds_without_error():
    view = _build_view()
    ensure(view.tree is not None)
    ensure(view.status is not None)
    ensure(view.progress is not None)
    ensure(view.filter_entry is not None)
    ensure(view.root_label is not None)
    ensure(view.context_combo is not None)
    ensure(view.wsl_distro_combo is not None)
    ensure(view.wsl_path_entry is not None)
    ensure(view.wsl_depth_spinbox is not None)
    ensure(view.wsl_scan_button is not None)
    ensure(view.key_entry is not None)
    ensure(view.value_entry is not None)
    ensure(view.refresh_button is not None)
    ensure(view.load_button is not None)
    ensure(view.choose_targets_button is not None)
    ensure(view.set_button is not None)
    ensure(view.remove_button is not None)
    ensure(view.copy_name_button is not None)
    ensure(view.copy_value_button is not None)
    ensure(view.copy_pair_button is not None)
    ensure(view.copy_source_path_button is not None)
    ensure(view.detail_open_button is not None)


def test_view_details_vars_created():
    view = _build_view()
    expected_keys = {
        "name", "context", "source", "source_path",
        "secret", "persistent", "mutable", "writable",
        "requires_privilege", "precedence_rank",
    }
    ensure(set(view.details_vars.keys()) == expected_keys)


def test_set_context_values():
    view = _build_view()
    view.set_context_values(["linux", "windows"])
    view.context_combo.configure.assert_called_with(values=["linux", "windows"])


def test_set_wsl_distros_enabled():
    view = _build_view()
    view.set_wsl_distros(["Ubuntu", "Debian"], enabled=True)
    view.wsl_distro_combo.configure.assert_any_call(values=["Ubuntu", "Debian"])
    view.wsl_distro_combo.configure.assert_any_call(state="readonly")


def test_set_wsl_distros_disabled():
    view = _build_view()
    view.set_wsl_distros([], enabled=False)
    view.wsl_distro_combo.configure.assert_any_call(state="disabled")
    view.wsl_path_entry.configure.assert_called_with(state="disabled")
    view.wsl_depth_spinbox.configure.assert_called_with(state="disabled")
    view.wsl_scan_button.configure.assert_called_with(state="disabled")


def test_set_root_label():
    view = _build_view()
    view.set_root_label("/new/path")
    view.root_label.configure.assert_called_with(text="/new/path")


def test_set_status():
    view = _build_view()
    view.set_status("Ready")
    view.status.configure.assert_called_with(text="Ready")


def test_set_refresh_busy_true():
    view = _build_view()
    view.set_refresh_busy(True)
    view.progress.start.assert_called_with(10)


def test_set_refresh_busy_false():
    view = _build_view()
    view.set_refresh_busy(False)
    view.progress.stop.assert_called_once()


def test_set_mutation_actions_enabled():
    view = _build_view()
    view.set_mutation_actions_enabled(True)
    for widget in (view.refresh_button, view.load_button, view.choose_targets_button, view.set_button, view.remove_button):
        widget.configure.assert_called_with(state="normal")


def test_set_mutation_actions_disabled():
    view = _build_view()
    view.set_mutation_actions_enabled(False)
    for widget in (view.refresh_button, view.load_button, view.choose_targets_button, view.set_button, view.remove_button):
        widget.configure.assert_called_with(state="disabled")


def test_clear_table():
    view = _build_view()
    view.tree.get_children.return_value = ["item1", "item2"]
    view.clear_table()
    ensure(view.tree.delete.call_count == 2)


def test_insert_table_row():
    view = _build_view()
    view.tree.insert.return_value = "new_item"
    result = view.insert_table_row(("a", "b", "c"), striped=True)
    ensure(result == "new_item")
    view.tree.insert.assert_called_with("", "end", values=("a", "b", "c"), tags=("row_even",))


def test_insert_table_row_odd():
    view = _build_view()
    view.tree.insert.return_value = "new_item"
    view.insert_table_row(("a",), striped=False)
    view.tree.insert.assert_called_with("", "end", values=("a",), tags=("row_odd",))


def test_configure_row_styles():
    view = _build_view()
    view.configure_row_styles()
    view.tree.tag_configure.assert_any_call("row_even", background="#f8f8f8")
    view.tree.tag_configure.assert_any_call("row_odd", background="#ffffff")


def test_update_details_value():
    view = _build_view()
    view.update_details_value("hello world")
    view.details_value_text.configure.assert_any_call(state="normal")
    view.details_value_text.delete.assert_called_with("1.0", "end")
    view.details_value_text.insert.assert_called_with("1.0", "hello world")
    view.details_value_text.configure.assert_any_call(state="disabled")


def test_set_details_enabled():
    view = _build_view()
    view.set_details_enabled(True)
    for widget in (view.copy_name_button, view.copy_value_button, view.copy_pair_button,
                   view.copy_source_path_button, view.detail_open_button):
        widget.configure.assert_called_with(state="normal")


def test_set_details_disabled():
    view = _build_view()
    view.set_details_enabled(False)
    for widget in (view.copy_name_button, view.copy_value_button, view.copy_pair_button,
                   view.copy_source_path_button, view.detail_open_button):
        widget.configure.assert_called_with(state="disabled")


def test_focus_filter():
    view = _build_view()
    view.focus_filter()
    view.filter_entry.focus_set.assert_called_once()
    view.filter_entry.selection_range.assert_called_with(0, "end")
