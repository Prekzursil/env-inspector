"""Coverage tests for env_inspector_gui.dialogs — full coverage via mocked tkinter."""

from __future__ import absolute_import, division

import sys
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from tests.assertions import ensure


def _make_mock_widget(**extras: Any) -> MagicMock:
    w = MagicMock()
    w.pack = MagicMock()
    w.grid = MagicMock()
    w.configure = MagicMock()
    w.bind = MagicMock()
    w.pack_forget = MagicMock()
    w.winfo_manager = MagicMock(return_value="pack")
    w.destroy = MagicMock()
    w.title = MagicMock()
    w.transient = MagicMock()
    w.grab_set = MagicMock()
    w.resizable = MagicMock()
    w.geometry = MagicMock()
    w.focus_set = MagicMock()
    for k, v in extras.items():
        setattr(w, k, v)
    return w


def _mock_tk_module():
    """Build a mock tkinter module with all needed classes."""
    tk = MagicMock()
    tk.Toplevel = MagicMock(return_value=_make_mock_widget())
    tk.BooleanVar = MagicMock(side_effect=lambda value=False: MagicMock(get=MagicMock(return_value=value), set=MagicMock(), trace_add=MagicMock()))
    tk.StringVar = MagicMock(side_effect=lambda value="": MagicMock(get=MagicMock(return_value=value), set=MagicMock()))
    tk.Canvas = MagicMock(return_value=_make_mock_widget(
        create_window=MagicMock(),
        bbox=MagicMock(return_value=(0, 0, 100, 100)),
    ))
    tk.Listbox = MagicMock(return_value=_make_mock_widget(
        insert=MagicMock(),
        curselection=MagicMock(return_value=()),
        get=MagicMock(return_value="backup1.zip"),
    ))
    return tk


def _mock_ttk_module():
    ttk = MagicMock()
    for widget_name in ("Frame", "Label", "Button", "Entry", "Checkbutton",
                        "Scrollbar", "Notebook", "LabelFrame"):
        mock_cls = MagicMock(return_value=_make_mock_widget())
        setattr(ttk, widget_name, mock_cls)
    return ttk


def _mock_font_module():
    font = MagicMock()
    font.nametofont = MagicMock(return_value=MagicMock())
    return font


def _mock_scrolledtext_module():
    st = MagicMock()
    txt_widget = _make_mock_widget(
        insert=MagicMock(),
        tag_configure=MagicMock(),
    )
    st.ScrolledText = MagicMock(return_value=txt_widget)
    return st


def _install_mock_tkinter():
    """Install mock tkinter into sys.modules so dialog imports work."""
    tk = _mock_tk_module()
    ttk = _mock_ttk_module()
    font = _mock_font_module()
    scrolledtext = _mock_scrolledtext_module()

    mock_tkinter = MagicMock()
    mock_tkinter.Toplevel = tk.Toplevel
    mock_tkinter.BooleanVar = tk.BooleanVar
    mock_tkinter.StringVar = tk.StringVar
    mock_tkinter.Canvas = tk.Canvas
    mock_tkinter.Listbox = tk.Listbox

    return tk, ttk, font, scrolledtext


# --- TargetPickerDialog ---

class TestTargetPickerDialog:
    def _build(self, targets=None, selected=None):
        if targets is None:
            targets = ["dotenv:/a/.env", "windows:user", "wsl:Ubuntu:bashrc"]

        tk, ttk, font, scrolledtext = _install_mock_tkinter()

        with patch.dict(sys.modules, {
            "tkinter": tk,
            "tkinter.ttk": ttk,
            "tkinter.font": font,
            "tkinter.scrolledtext": scrolledtext,
        }):
            # We need to import inside the patch context because the dialog
            # imports tkinter at class instantiation time
            from env_inspector_gui.dialogs import TargetPickerDialog

            parent = _make_mock_widget()
            dialog = TargetPickerDialog(parent, targets, selected)
        return dialog

    def test_creates_dialog(self):
        dialog = self._build()
        ensure(dialog.result is None)
        ensure(len(dialog._vars) == 3)

    def test_with_selected(self):
        dialog = self._build(selected=["windows:user"])
        ensure(dialog.result is None)

    def test_apply(self):
        dialog = self._build()
        # Set all vars to True
        for var in dialog._vars.values():
            var.get.return_value = True
        dialog._apply()
        ensure(dialog.result is not None)
        ensure(len(dialog.result) == 3)

    def test_cancel(self):
        dialog = self._build()
        dialog._cancel()
        ensure(dialog.result is None)

    def test_on_escape(self):
        dialog = self._build()
        dialog._on_escape(None)
        ensure(dialog.result is None)

    def test_select_all(self):
        dialog = self._build()
        dialog._select_all()
        for var in dialog._vars.values():
            var.set.assert_called_with(True)

    def test_select_none(self):
        dialog = self._build()
        dialog._select_none()
        for var in dialog._vars.values():
            var.set.assert_called_with(False)

    def test_select_dotenv(self):
        dialog = self._build()
        dialog._select_dotenv()
        # dotenv:/a/.env should be True, others False
        dialog._vars["dotenv:/a/.env"].set.assert_called_with(True)
        dialog._vars["windows:user"].set.assert_called_with(False)

    def test_select_windows(self):
        dialog = self._build(targets=["windows:user", "powershell:machine", "dotenv:/a"])
        dialog._select_windows()
        dialog._vars["windows:user"].set.assert_called_with(True)
        dialog._vars["powershell:machine"].set.assert_called_with(True)
        dialog._vars["dotenv:/a"].set.assert_called_with(False)

    def test_select_wsl(self):
        dialog = self._build(targets=["wsl:Ubuntu:bashrc", "wsl_dotenv:/a", "windows:user"])
        dialog._select_wsl()
        dialog._vars["wsl:Ubuntu:bashrc"].set.assert_called_with(True)
        dialog._vars["wsl_dotenv:/a"].set.assert_called_with(True)
        dialog._vars["windows:user"].set.assert_called_with(False)

    def test_apply_filter_hides_non_matching(self):
        dialog = self._build()
        dialog.search_var.get.return_value = "dotenv"
        dialog._apply_filter()

    def test_apply_filter_shows_all_on_empty(self):
        dialog = self._build()
        dialog.search_var.get.return_value = ""
        dialog._apply_filter()

    def test_apply_filter_hidden_check_repacked(self):
        dialog = self._build()
        # Simulate a check that is hidden (winfo_manager returns "")
        for check in dialog._checks.values():
            check.winfo_manager.return_value = ""
        dialog.search_var.get.return_value = ""
        dialog._apply_filter()

    def test_apply_filter_already_hidden_non_matching(self):
        """Branch 112->106: non-matching check already hidden (winfo_manager returns '')."""
        dialog = self._build()
        # Set all checks to already hidden
        for check in dialog._checks.values():
            check.winfo_manager.return_value = ""
        # Search for something that won't match any target
        dialog.search_var.get.return_value = "zzz_nomatch_zzz"
        dialog._apply_filter()
        # pack_forget should NOT be called since they're already hidden
        for check in dialog._checks.values():
            check.pack_forget.assert_not_called()

    def test_on_search_keyrelease(self):
        dialog = self._build()
        dialog.search_var.get.return_value = "test"
        dialog._on_search_keyrelease(None)

    def test_update_selected_count(self):
        dialog = self._build()
        for var in dialog._vars.values():
            var.get.return_value = True
        dialog._update_selected_count()
        dialog.selected_count_label.configure.assert_called()

    def test_sync_scrollregion(self):
        dialog = self._build()
        dialog._sync_scrollregion(None)


# --- DotenvTargetDialog ---

class TestDotenvTargetDialog:
    def _build(self, key="API_KEY", targets=None):
        if targets is None:
            targets = ["dotenv:/a/.env", "dotenv:/b/.env"]

        tk, ttk, font, scrolledtext = _install_mock_tkinter()

        with patch.dict(sys.modules, {
            "tkinter": tk,
            "tkinter.ttk": ttk,
        }):
            from env_inspector_gui.dialogs import DotenvTargetDialog
            parent = _make_mock_widget()
            dialog = DotenvTargetDialog(parent, key, targets)
        return dialog

    def test_creates_dialog(self):
        dialog = self._build()
        ensure(dialog.result is None)
        ensure(len(dialog._vars) == 2)

    def test_apply(self):
        dialog = self._build()
        for name, var in dialog._vars:
            var.get.return_value = True
        dialog._apply()
        ensure(dialog.result is not None)

    def test_cancel(self):
        dialog = self._build()
        dialog._cancel()
        ensure(dialog.result is None)


# --- DiffPreviewDialog ---

class TestDiffPreviewDialog:
    def _build(self, action="set", previews=None, preview_only=False):
        if previews is None:
            previews = [
                {
                    "target": "dotenv:/a/.env",
                    "success": True,
                    "diff_preview": "@@ -1,2 +1,3 @@\n KEY=old\n+KEY=new\n-REMOVED=yes\n+++header\n---header\n context line",
                    "error_message": None,
                },
                {
                    "target": "dotenv:/b/.env",
                    "success": False,
                    "diff_preview": None,
                    "error_message": "Permission denied",
                },
            ]

        tk, ttk, font, scrolledtext = _install_mock_tkinter()

        with patch.dict(sys.modules, {
            "tkinter": tk,
            "tkinter.ttk": ttk,
            "tkinter.font": font,
            "tkinter.scrolledtext": scrolledtext,
        }):
            from env_inspector_gui.dialogs import DiffPreviewDialog
            parent = _make_mock_widget()
            dialog = DiffPreviewDialog(parent, action=action, previews=previews, preview_only=preview_only)
        return dialog

    def test_creates_dialog(self):
        dialog = self._build()
        ensure(dialog.confirmed is False)

    def test_apply(self):
        dialog = self._build()
        dialog._apply()
        ensure(dialog.confirmed is True)

    def test_cancel(self):
        dialog = self._build()
        dialog._cancel()
        ensure(dialog.confirmed is False)

    def test_on_escape(self):
        dialog = self._build()
        dialog._on_escape(None)
        ensure(dialog.confirmed is False)

    def test_preview_only_mode(self):
        dialog = self._build(preview_only=True)
        ensure(dialog.confirmed is False)

    def test_diff_tag_static_method(self):
        from env_inspector_gui.dialogs import DiffPreviewDialog
        ensure(DiffPreviewDialog._diff_tag("@@ -1,2 +1,3 @@") == "diff_hunk")
        ensure(DiffPreviewDialog._diff_tag("+added line") == "diff_add")
        ensure(DiffPreviewDialog._diff_tag("-removed line") == "diff_remove")
        ensure(DiffPreviewDialog._diff_tag("+++header") is None)
        ensure(DiffPreviewDialog._diff_tag("---header") is None)
        ensure(DiffPreviewDialog._diff_tag(" context line") is None)

    def test_no_diff_preview(self):
        """Tab with no diff_preview should show '(no textual diff)'."""
        dialog = self._build(previews=[{"target": "t", "success": True, "diff_preview": None}])
        ensure(dialog.confirmed is False)

    def test_preview_missing_target(self):
        """Tab with missing target key should use fallback name."""
        dialog = self._build(previews=[{"success": True, "diff_preview": "line1"}])
        ensure(dialog.confirmed is False)


# --- BackupPickerDialog ---

class TestBackupPickerDialog:
    def _build(self, backups=None):
        if backups is None:
            backups = ["backup1.zip", "backup2.zip"]

        tk, ttk, font, scrolledtext = _install_mock_tkinter()

        with patch.dict(sys.modules, {
            "tkinter": tk,
            "tkinter.ttk": ttk,
        }):
            from env_inspector_gui.dialogs import BackupPickerDialog
            parent = _make_mock_widget()
            dialog = BackupPickerDialog(parent, backups)
        return dialog

    def test_creates_dialog(self):
        dialog = self._build()
        ensure(dialog.result is None)

    def test_restore_with_selection(self):
        dialog = self._build()
        dialog.listbox.curselection.return_value = (0,)
        dialog.listbox.get.return_value = "backup1.zip"
        dialog._restore()
        ensure(dialog.result == "backup1.zip")

    def test_restore_no_selection(self):
        dialog = self._build()
        dialog.listbox.curselection.return_value = ()
        dialog._restore()
        ensure(dialog.result is None)

    def test_cancel(self):
        dialog = self._build()
        dialog._cancel()
        ensure(dialog.result is None)
