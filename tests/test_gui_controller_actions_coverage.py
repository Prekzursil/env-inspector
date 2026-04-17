"""Coverage tests for env_inspector_gui.controller_actions."""

from pathlib import Path
from typing import Any, Dict, List, Optional, cast
from unittest.mock import MagicMock, patch

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller_actions import (
    APP_NAME,
    MSG_SELECT_ROW_FIRST,
    EnvInspectorControllerActionsMixin,
)
from env_inspector_gui.models import DisplayedRow
from tests.assertions import ensure

_NEGATIVE_FLAG_TEXT = "no"  # avoid Bandit B106 false-positive on _text="no" literals


def _make_record(**overrides: object) -> EnvRecord:
    """Make record."""
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


def _make_row(rec: EnvRecord) -> DisplayedRow:
    """Make row."""
    return DisplayedRow(
        record=rec,
        visible_value=rec.value,
        search_value="",
        source_label=rec.source_type,
        secret_text=_NEGATIVE_FLAG_TEXT,
        persistent_text=_NEGATIVE_FLAG_TEXT,
        mutable_text=_NEGATIVE_FLAG_TEXT,
        writable_text=_NEGATIVE_FLAG_TEXT,
        requires_privilege_text=_NEGATIVE_FLAG_TEXT,
        original_index=0,
    )


class _Var:
    """Minimal tkinter variable stub for testing."""

    def __init__(self, value: Any = "") -> None:
        self._value = value

    def get(self) -> Any:
        """Get."""
        return self._value

    def set(self, value: Any) -> None:
        """Set."""
        self._value = value


class _ActionTestMixin(EnvInspectorControllerActionsMixin):
    """Concrete implementation of the mixin for testing."""

    def __init__(self) -> None:
        self.tk = MagicMock()
        self.messagebox = MagicMock()
        self.filedialog = MagicMock()
        self.service = MagicMock()
        self.show_secrets = _Var(False)
        self.key_text = _Var("")
        self.value_text = _Var("")
        self.context_var = _Var("windows")
        self.wsl_distro_var = _Var("")
        self.wsl_path_var = _Var("")
        self.scan_depth_var = _Var(5)
        self.root_path = Path("/workspace")

        self._selected: DisplayedRow | None = None
        self._status_calls: List[str] = []
        self._effective_calls: List[str] = []
        self._refresh_calls: int = 0

    def _selected_row(self) -> Any:
        """Selected row."""
        return self._selected

    def _set_status(self, text: str) -> None:
        """Set status."""
        self._status_calls.append(text)

    def _update_effective(self, key: str) -> None:
        """Update effective."""
        self._effective_calls.append(key)

    def refresh_data(self) -> None:
        """Refresh data."""
        self._refresh_calls += 1


# --- abstract method stubs (NotImplementedError) ---


def test_abstract_selected_row():
    """Test abstract selected row."""
    import pytest

    mixin = EnvInspectorControllerActionsMixin()
    with pytest.raises(NotImplementedError):
        mixin._selected_row()


def test_abstract_set_status():
    """Test abstract set status."""
    import pytest

    mixin = EnvInspectorControllerActionsMixin()
    with pytest.raises(NotImplementedError):
        mixin._set_status("test")


def test_abstract_update_effective():
    """Test abstract update effective."""
    import pytest

    mixin = EnvInspectorControllerActionsMixin()
    with pytest.raises(NotImplementedError):
        mixin._update_effective("key")


def test_abstract_refresh_data():
    """Test abstract refresh data."""
    import pytest

    mixin = EnvInspectorControllerActionsMixin()
    with pytest.raises(NotImplementedError):
        mixin.refresh_data()


# --- load_selected ---


def test_load_selected_no_row():
    """Test load selected no row."""
    ctrl = _ActionTestMixin()
    ctrl.load_selected()
    ctrl.messagebox.showinfo.assert_called_once_with(APP_NAME, MSG_SELECT_ROW_FIRST)


def test_load_selected_non_secret():
    """Test load selected non secret."""
    ctrl = _ActionTestMixin()
    rec = _make_record(name="PUBLIC", value="hello")
    ctrl._selected = _make_row(rec)
    ctrl.load_selected()
    ensure(ctrl.key_text.get() == "PUBLIC")
    ensure(ctrl.value_text.get() == "hello")
    ensure(any("Loaded value" in s for s in ctrl._status_calls))
    ensure("PUBLIC" in ctrl._effective_calls)


def test_load_selected_secret_show_secrets_true():
    """Test load selected secret show secrets true."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(True)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.load_selected()
    ensure(ctrl.value_text.get() == "secret123")


def test_load_selected_secret_hidden_confirm_yes():
    """Test load selected secret hidden confirm yes."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(False)
    ctrl.messagebox.askyesno = MagicMock(return_value=True)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.load_selected()
    ensure(ctrl.value_text.get() == "secret123")


def test_load_selected_secret_hidden_confirm_no():
    """Test load selected secret hidden confirm no."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(False)
    ctrl.messagebox.askyesno = MagicMock(return_value=False)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.load_selected()
    ensure(any("Skipped" in s for s in ctrl._status_calls))


# --- copy_selected_name ---


def test_copy_selected_name_no_row():
    """Test copy selected name no row."""
    ctrl = _ActionTestMixin()
    ctrl.copy_selected_name()
    ctrl.messagebox.showinfo.assert_called_once()


def test_copy_selected_name():
    """Test copy selected name."""
    ctrl = _ActionTestMixin()
    rec = _make_record(name="MY_VAR")
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_name()
    ctrl.tk.clipboard_clear.assert_called_once()
    ctrl.tk.clipboard_append.assert_called_once_with("MY_VAR")
    ensure(any("MY_VAR" in s for s in ctrl._status_calls))


# --- copy_selected_value ---


def test_copy_selected_value_no_row():
    """Test copy selected value no row."""
    ctrl = _ActionTestMixin()
    ctrl.copy_selected_value()
    ctrl.messagebox.showinfo.assert_called_once()


def test_copy_selected_value_non_secret():
    """Test copy selected value non secret."""
    ctrl = _ActionTestMixin()
    rec = _make_record(name="KEY", value="plainvalue")
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_value()
    ctrl.tk.clipboard_append.assert_called_once_with("plainvalue")


def test_copy_selected_value_secret_hidden_masked():
    """Test copy selected value secret hidden masked."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(False)
    ctrl.messagebox.askyesno = MagicMock(return_value=False)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_value()
    # Should copy masked value
    ensure(any("masked" in s for s in ctrl._status_calls))


def test_copy_selected_value_secret_shown():
    """Test copy selected value secret shown."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(True)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_value()
    ctrl.tk.clipboard_append.assert_called_once_with("secret123")


# --- copy_selected_pair ---


def test_copy_selected_pair_no_row():
    """Test copy selected pair no row."""
    ctrl = _ActionTestMixin()
    ctrl.copy_selected_pair()
    ctrl.messagebox.showinfo.assert_called_once()


def test_copy_selected_pair_non_secret():
    """Test copy selected pair non secret."""
    ctrl = _ActionTestMixin()
    rec = _make_record(name="KEY", value="val")
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_pair()
    ctrl.tk.clipboard_append.assert_called_once_with("KEY=val")


def test_copy_selected_pair_secret_masked():
    """Test copy selected pair secret masked."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(False)
    ctrl.messagebox.askyesno = MagicMock(return_value=False)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_pair()
    ensure(any("masked" in s for s in ctrl._status_calls))


# --- copy_selected_source_path ---


def test_copy_selected_source_path_no_row():
    """Test copy selected source path no row."""
    ctrl = _ActionTestMixin()
    ctrl.copy_selected_source_path()
    ctrl.messagebox.showinfo.assert_called_once()


def test_copy_selected_source_path():
    """Test copy selected source path."""
    ctrl = _ActionTestMixin()
    rec = _make_record(source_path="/workspace/.env")
    ctrl._selected = _make_row(rec)
    ctrl.copy_selected_source_path()
    ctrl.tk.clipboard_append.assert_called_once_with("/workspace/.env")


# --- open_selected_source ---


def test_open_selected_source_no_row():
    """Test open selected source no row."""
    ctrl = _ActionTestMixin()
    ctrl.open_selected_source()
    ctrl.messagebox.showinfo.assert_called_once()


def test_open_selected_source_non_local():
    """Test open selected source non local."""
    ctrl = _ActionTestMixin()
    rec = _make_record(source_path="registry:HKCU\\Environment")
    ctrl._selected = _make_row(rec)
    ctrl.open_selected_source()
    ctrl.messagebox.showinfo.assert_called_once()


def test_open_selected_source_success(tmp_path: Path):
    """Test open selected source success."""
    ctrl = _ActionTestMixin()
    f = tmp_path / "test.env"
    f.write_text("A=1\n", encoding="utf-8")
    rec = _make_record(source_path=str(f))
    ctrl._selected = _make_row(rec)

    with patch(
        "env_inspector_gui.controller_actions.open_source_path",
        return_value=(True, None),
    ):
        ctrl.open_selected_source()
    ensure(any("Opened" in s for s in ctrl._status_calls))


# --- export_records ---


def test_export_records_json():
    """Test export records json."""
    ctrl = _ActionTestMixin()
    ctrl.service.export_records = MagicMock(return_value='{"data": []}')
    ctrl.filedialog.asksaveasfilename = MagicMock(return_value="")
    ctrl.export_records("json")
    # No file selected, should return early
    ensure(len(ctrl._status_calls) == 0)


def test_export_records_saves_file(tmp_path: Path):
    """Test export records saves file."""
    ctrl = _ActionTestMixin()
    ctrl.service.export_records = MagicMock(return_value='{"data": []}')
    out = tmp_path / "export.json"
    ctrl.filedialog.asksaveasfilename = MagicMock(return_value=str(out))
    ctrl.export_records("json")
    ensure(out.exists())
    ensure(any("Exported" in s for s in ctrl._status_calls))


def test_export_records_csv(tmp_path: Path):
    """Test export records csv."""
    ctrl = _ActionTestMixin()
    ctrl.service.export_records = MagicMock(return_value="name,value\nA,1")
    out = tmp_path / "export.csv"
    ctrl.filedialog.asksaveasfilename = MagicMock(return_value=str(out))
    ctrl.export_records("csv")
    ensure(out.exists())


def test_export_records_unknown_format(tmp_path: Path):
    """Test export records unknown format."""
    ctrl = _ActionTestMixin()
    ctrl.service.export_records = MagicMock(return_value="data")
    out = tmp_path / "export.txt"
    ctrl.filedialog.asksaveasfilename = MagicMock(return_value=str(out))
    ctrl.export_records("yaml")
    ensure(out.exists())


def test_export_records_with_wsl_params(tmp_path: Path):
    """Test export records with wsl params."""
    ctrl = _ActionTestMixin()
    ctrl.wsl_distro_var = _Var("Ubuntu")
    ctrl.wsl_path_var = _Var("/home/user")
    ctrl.service.export_records = MagicMock(return_value="data")
    out = tmp_path / "export.json"
    ctrl.filedialog.asksaveasfilename = MagicMock(return_value=str(out))
    ctrl.export_records("json")
    ensure(out.exists())


# --- restore_backup ---


def test_restore_backup_no_backups():
    """Test restore backup no backups."""
    ctrl = _ActionTestMixin()
    ctrl.service.list_backups = MagicMock(return_value=[])
    ctrl.restore_backup()
    ctrl.messagebox.showinfo.assert_called_once()


def test_restore_backup_cancelled():
    """Test restore backup cancelled."""
    ctrl = _ActionTestMixin()
    ctrl.service.list_backups = MagicMock(return_value=["backup1.zip"])

    with patch("env_inspector_gui.controller_actions.BackupPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = None
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk.wait_window = MagicMock()
        ctrl.restore_backup()

    ensure(ctrl._refresh_calls == 0)


def test_restore_backup_success():
    """Test restore backup success."""
    ctrl = _ActionTestMixin()
    ctrl.service.list_backups = MagicMock(return_value=["backup1.zip"])
    ctrl.service.restore_backup = MagicMock(
        return_value={"success": True, "operation_id": "op-1"}
    )

    with patch("env_inspector_gui.controller_actions.BackupPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = "backup1.zip"
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk.wait_window = MagicMock()
        ctrl.restore_backup()

    ensure(ctrl._refresh_calls == 1)
    ensure(any("Restored" in s for s in ctrl._status_calls))


def test_restore_backup_failure():
    """Test restore backup failure."""
    ctrl = _ActionTestMixin()
    ctrl.service.list_backups = MagicMock(return_value=["backup1.zip"])
    ctrl.service.restore_backup = MagicMock(
        return_value={"success": False, "error_message": "corrupt"}
    )

    with patch("env_inspector_gui.controller_actions.BackupPickerDialog") as MockDialog:
        instance = MagicMock()
        instance.result = "backup1.zip"
        instance.win = MagicMock()
        MockDialog.return_value = instance
        ctrl.tk.wait_window = MagicMock()
        ctrl.restore_backup()

    ctrl.messagebox.showerror.assert_called_once()


# --- load_selected: secret loaded as masked (line 64 branch) ---


def test_load_selected_secret_loaded_but_masked():
    """Line 64: record_is_secret and not raw — patched resolve_load_value returns (masked, False)."""
    ctrl = _ActionTestMixin()
    ctrl.show_secrets = _Var(False)
    rec = _make_record(name="TOKEN", value="secret123", is_secret=True)
    ctrl._selected = _make_row(rec)

    with patch(
        "env_inspector_gui.controller_actions.resolve_load_value",
        return_value=("***", False),
    ):
        ctrl.load_selected()
    ensure(ctrl.value_text.get() == "***")
    ensure(any("Loaded masked" in s for s in ctrl._status_calls))


# --- _confirm_hidden_secret ---


def test_confirm_hidden_secret():
    """Test confirm hidden secret."""
    ctrl = _ActionTestMixin()
    ctrl.messagebox.askyesno = MagicMock(return_value=True)
    ensure(ctrl._confirm_hidden_secret("Test prompt?") is True)
    ctrl.messagebox.askyesno.assert_called_once()


# --- _selected_record ---


def test_selected_record_none():
    """Test selected record none."""
    ctrl = _ActionTestMixin()
    ensure(ctrl._selected_record() is None)


def test_selected_record_returns_record():
    """Test selected record returns record."""
    ctrl = _ActionTestMixin()
    rec = _make_record(name="X")
    ctrl._selected = _make_row(rec)
    selected_record = ctrl._selected_record()
    ensure(selected_record is not None)
    # Pyright/Sonar see the prior assertion as proof selected_record is non-None,
    # so accessing .name directly is safe and avoids the always-true tautology.
    ensure(cast(EnvRecord, selected_record).name == "X")
