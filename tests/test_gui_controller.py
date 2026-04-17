"""Controller-focused GUI regression tests."""

from __future__ import absolute_import, division

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple, cast

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller import EnvInspectorController
from env_inspector_gui.models import PersistedUiState

from tests.assertions import ensure


class _Var:
    """Minimal Tk-style variable stub used by controller tests."""

    def __init__(self, value: Any = "") -> None:
        self._value = value

    def get(self) -> Any:
        """Return the current stored value."""
        return self._value

    def set(self, value: Any) -> None:
        """Update the stored value."""
        self._value = value


class _View:
    """Minimal view stub used for busy-state assertions."""

    def __init__(self) -> None:
        self.enabled_states: List[bool] = []
        self.busy_states: List[bool] = []

    def set_mutation_actions_enabled(self, enabled: bool) -> None:
        """Record whether mutation actions were enabled."""
        self.enabled_states.append(enabled)

    def set_refresh_busy(self, busy: bool) -> None:
        """Record whether refresh was marked busy."""
        self.busy_states.append(busy)


class _BootstrapRoot:
    """Minimal root-window stub for controller bootstrap."""

    def __init__(self) -> None:
        self._geometry = "1480x860"

    @staticmethod
    def title(_title: str) -> None:
        """Accept a window-title update."""

    @staticmethod
    def protocol(*_args: object) -> None:
        """Accept a protocol binding."""

    @staticmethod
    def after_idle(_callback: Any) -> None:
        """Ignore idle callbacks during tests."""

    def geometry(self, value: str | None = None) -> str:
        """Store or return the current geometry string."""
        if value is not None:
            self._geometry = value
        return self._geometry

    @staticmethod
    def bind(*_args: object) -> None:
        """Accept shortcut bindings."""

    @staticmethod
    def focus_get() -> None:
        """Return no focused widget in tests."""
        return None

    @staticmethod
    def destroy() -> None:
        """Accept window-destroy requests."""

    @staticmethod
    def mainloop() -> None:
        """Skip the GUI main loop in tests."""


_BOOTSTRAP_TK_MODULE = SimpleNamespace(
    Tk=_BootstrapRoot,
    StringVar=_Var,
    BooleanVar=_Var,
    IntVar=_Var,
)


class _BootstrapView:
    """Minimal view stub used only during controller bootstrap."""

    def focus_filter(self) -> None:
        """Skip focus changes during tests."""

    def set_root_label(self, _label: str) -> None:
        """Accept root-label updates."""

    def configure_row_styles(self) -> None:
        """Skip row-style configuration during tests."""


class _ControllerHarness(EnvInspectorController):
    """Base harness that exposes public wrappers around controller internals."""

    def __init__(self) -> None:
        self._during_bootstrap = True
        super().__init__(Path.cwd())
        self._during_bootstrap = False

    @staticmethod
    def _load_tk_modules() -> Tuple[Any, Any, Any, Any]:
        """Provide stub Tk modules for controller bootstrap."""
        return (
            _BOOTSTRAP_TK_MODULE,
            cast(Any, object()),
            cast(Any, object()),
            cast(Any, object()),
        )

    def _init_root_window(self, _tk: Any) -> None:
        """Install a stub root window for controller bootstrap."""
        self.tk = _BootstrapRoot()

    def _apply_theme(self) -> None:
        """Skip theme configuration during tests."""

    def _load_boot_state(self, _root_path: Path) -> Tuple[PersistedUiState, Path]:
        """Provide a deterministic boot state for controller tests."""
        return PersistedUiState(context="linux"), Path.cwd()

    def _initialize_view(
        self, _tk: Any, _ttk: Any, _boot_state: PersistedUiState
    ) -> None:
        """Install a stub view for controller bootstrap."""
        self.view = cast(Any, _BootstrapView())

    def _bind_shortcuts(self) -> None:
        """Skip shortcut binding during tests."""

    def refresh_data(self) -> None:
        """Skip bootstrap refreshes but preserve the real method afterward."""
        if getattr(self, "_during_bootstrap", False):
            return
        super().refresh_data()

    def select_context(self) -> None:
        """Run the context-selection flow through the real controller method."""
        super().on_context_selected()

    def set_busy_state(self, busy: bool) -> None:
        """Run the busy-state helper through the real controller method."""
        super()._set_busy(busy)

    def refresh_controller_data(self) -> None:
        """Run the refresh flow through the real controller method."""
        super().refresh_data()

    def run_operation(self, action: str) -> None:
        """Run a mutation flow through the real controller method."""
        super()._run_operation(action)


class _ContextSelectionHarness(_ControllerHarness):
    """Harness for context-selection behavior."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: List[str] = []

    def refresh_data(self) -> None:
        """Record explicit refresh calls after bootstrap."""
        if getattr(self, "_during_bootstrap", False):
            return
        self.calls.append("refresh")


class _BusyStateHarness(_ControllerHarness):
    """Harness for busy-state behavior."""

    def __init__(self) -> None:
        super().__init__()
        self.busy_view = _View()
        self.view = cast(Any, self.busy_view)


class _RefreshHarness(_ControllerHarness):
    """Harness for refresh-data behavior."""

    def __init__(self) -> None:
        super().__init__()
        self.key_text = _Var("API_TOKEN")
        self.effective_value_var = _Var("")
        self.view = None
        self.events: List[Tuple[str, Optional[object]]] = []

    def _set_busy(self, busy: bool) -> None:
        """Record busy-state updates."""
        self.events.append(("busy", busy))

    def _set_status(self, text: str) -> None:
        """Record status updates."""
        self.events.append(("status", text))

    def _update_context_values(self) -> None:
        """Record context updates."""
        self.events.append(("contexts", None))

    def _fetch_records(self) -> None:
        """Record record-fetch calls."""
        self.events.append(("fetch", None))

    def _reconcile_targets(self) -> None:
        """Record target reconciliation."""
        self.events.append(("targets", None))

    def _render_table(self) -> None:
        """Record table renders."""
        self.events.append(("render", None))

    def _update_effective(self, key: str) -> None:
        """Record effective-value recalculation."""
        self.events.append(("effective", key))


class _MessageBox:
    """Minimal messagebox stub for mutation-flow tests."""

    @staticmethod
    def showerror(*_args: object) -> None:
        """Ignore error dialogs during tests."""
        return None


class _OperationHarness(_ControllerHarness):
    """Harness for mutation preview and apply flows."""

    def __init__(self) -> None:
        super().__init__()
        self.key_text = _Var("API_TOKEN")
        self.value_text = _Var("abc")
        self.selected_targets = ["windows:user"]
        self.records_raw: List[EnvRecord] = []
        self.calls: List[Tuple[str, Optional[object]]] = []
        self.messagebox = cast(Any, _MessageBox())

    def _set_status(self, _text: str) -> None:
        """Ignore status updates during mutation tests."""
        return None

    def choose_targets(self) -> List[str]:
        """Return the current target selection."""
        return list(self.selected_targets)

    def _maybe_choose_dotenv_targets(self, _key: str, targets: List[str]) -> List[str]:
        """Keep dotenv targets unchanged during tests."""
        return list(targets)

    def _preview_operation(
        self,
        action: str,
        key: str,
        value: str,
        targets: List[str],
    ) -> List[Dict[str, object]]:
        """Record preview calls and return a successful preview payload."""
        self.calls.append(("preview", action))
        return [{"target": "windows:user", "success": True, "diff_preview": ""}]

    def _confirm_diff(
        self,
        action: str,
        previews: List[Dict[str, object]],
        preview_only: bool = False,
    ) -> bool:
        """Record confirmation requests and always accept them."""
        self.calls.append(("confirm", preview_only))
        return True

    def _apply_operation(
        self,
        action: str,
        key: str,
        value: str,
        targets: List[str],
    ) -> Dict[str, object]:
        """Record apply calls and return a successful result payload."""
        self.calls.append(("apply", action))
        return {"success": True, "operation_id": "op-1"}

    def refresh_data(self) -> None:
        """Record explicit refresh calls after bootstrap."""
        if getattr(self, "_during_bootstrap", False):
            return
        self.calls.append(("refresh", None))


def test_var_roundtrip_set_get():
    """Variables should round-trip updated values."""
    var = _Var("initial")
    var.set("updated")
    ensure(var.get() == "updated")


def test_context_change_triggers_full_refresh():
    """Selecting a context should trigger a refresh."""
    ctrl = _ContextSelectionHarness()

    ctrl.select_context()

    ensure(ctrl.calls == ["refresh"])


def test_busy_state_disable_enable_around_refresh():
    """Busy state should disable and then re-enable refresh controls."""
    ctrl = _BusyStateHarness()

    ctrl.set_busy_state(True)
    ctrl.set_busy_state(False)

    ensure(ctrl.busy_view.enabled_states == [False, True])
    ensure(ctrl.busy_view.busy_states == [True, False])


def test_refresh_updates_effective_value_when_key_present():
    """Refresh should update the effective value and busy markers."""
    ctrl = _RefreshHarness()

    ctrl.refresh_controller_data()

    ensure(("effective", "API_TOKEN") in ctrl.events)
    ensure(
        next(((kind, value) for kind, value in ctrl.events if kind == "busy"), None)
        == ("busy", True)
    )
    ensure(
        next(
            ((kind, value) for kind, value in reversed(ctrl.events) if kind == "busy"),
            None,
        )
        == ("busy", False)
    )


def test_set_remove_operations_always_preview_before_apply():
    """Mutations should preview before applying changes."""
    ctrl = _OperationHarness()

    ctrl.run_operation("set")
    ctrl.run_operation("remove")

    ensure(
        next(((kind, value) for kind, value in ctrl.calls if kind == "preview"), None)
        == ("preview", "set")
    )
    ensure(("confirm", False) in ctrl.calls)
    ensure(("apply", "set") in ctrl.calls)
    ensure(("preview", "remove") in ctrl.calls)
    ensure(("apply", "remove") in ctrl.calls)
