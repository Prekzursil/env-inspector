from __future__ import annotations

from tests.conftest import ensure
from pathlib import Path

from env_inspector_gui.controller import EnvInspectorController
from env_inspector_gui.models import PersistedUiState, _coerce_number
from env_inspector_gui.state_store import load_ui_state
from env_inspector_gui.view import EnvInspectorView


class _Var:
    def __init__(self, value=None) -> None:
        self._value = value

    def get(self):
        return self._value

    def set(self, value) -> None:
        self._value = value


class _TkVars:
    StringVar = _Var
    BooleanVar = _Var
    IntVar = _Var


class _MessageBox:
    def __init__(self) -> None:
        self.errors: list[tuple[str, str]] = []

    def showerror(self, title: str, message: str) -> None:
        self.errors.append((title, message))


class _ControllerStub:
    def __init__(self) -> None:
        self.tk = object()


def test_view_init_covers_placeholder_assignments(monkeypatch):
    monkeypatch.setattr(EnvInspectorView, "_build_ui", lambda self: None)

    view = EnvInspectorView(tkmod=object(), ttk=object(), controller=_ControllerStub())

    ensure(view.filter_entry is None)
    ensure(view.tree is None)
    ensure(view.progress is None)


def test_initialize_runtime_state_sets_collections_and_timestamp(tmp_path: Path):
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    ctrl._resolve_root_path = lambda _state, fallback: fallback

    boot = PersistedUiState(
        root_path=str(tmp_path),
        context="windows",
        show_secrets=True,
        only_secrets=False,
        filter_text="abc",
        selected_targets=["windows:user"],
        sort_column="name",
        sort_descending=False,
        wsl_distro="Ubuntu",
        wsl_path="/home/user/project",
        scan_depth=6,
    )

    EnvInspectorController._initialize_runtime_state(ctrl, _TkVars, boot, tmp_path)

    ensure(ctrl.records_raw == [])
    ensure(ctrl.displayed_rows == [])
    ensure(ctrl.rows_by_item == {})
    ensure(ctrl.last_refresh_at is None)


def test_safe_preview_and_apply_handle_expected_exceptions():
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    ctrl.messagebox = _MessageBox()
    ctrl._preview_operation = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("preview boom"))
    ctrl._apply_operation = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("apply boom"))

    preview = EnvInspectorController._safe_preview(ctrl, "set", "K", "V", ["windows:user"])
    applied = EnvInspectorController._safe_apply(ctrl, "set", "K", "V", ["windows:user"])

    ensure(preview is None)
    ensure(applied is None)
    ensure(any(("preview boom" in msg for _title, msg in ctrl.messagebox.errors)))
    ensure(any(("apply boom" in msg for _title, msg in ctrl.messagebox.errors)))


def test_coerce_number_covers_bool_int_float_and_string_paths():
    payload = {
        "bool": True,
        "int": 7,
        "float": 2.8,
        "str_ok": "11",
        "str_empty": "   ",
        "str_bad": "bad",
        "other": object(),
    }

    ensure(_coerce_number(payload, "bool", 5) == 1)
    ensure(_coerce_number(payload, "int", 5) == 7)
    ensure(_coerce_number(payload, "float", 5) == 2)
    ensure(_coerce_number(payload, "str_ok", 5) == 11)
    ensure(_coerce_number(payload, "str_empty", 5) == 5)
    ensure(_coerce_number(payload, "str_bad", 5) == 5)
    ensure(_coerce_number(payload, "other", 5) == 5)


def test_load_ui_state_handles_from_dict_type_error(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / ".env-inspector-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "env_inspector_gui.state_store.PersistedUiState.from_dict",
        lambda _payload: (_ for _ in ()).throw(TypeError("bad payload")),
    )

    loaded = load_ui_state(state_dir)

    ensure(isinstance(loaded, PersistedUiState))
    ensure(loaded.sort_column == "name")
