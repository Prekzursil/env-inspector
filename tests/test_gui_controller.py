from __future__ import absolute_import, division

from typing import Any, Dict, List, Optional, Tuple, cast

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller import EnvInspectorController

from tests.assertions import ensure


class _Var:
    def __init__(self, value: str = "") -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def set(self, value: str) -> None:
        self._value = value


class _View:
    def __init__(self) -> None:
        self.enabled_states: List[bool] = []
        self.busy_states: List[bool] = []

    def set_mutation_actions_enabled(self, enabled: bool) -> None:
        self.enabled_states.append(enabled)

    def set_refresh_busy(self, busy: bool) -> None:
        self.busy_states.append(busy)


class _ControllerHarness(EnvInspectorController):
    def __init__(self) -> None:
        # Tests bypass the real GUI/service bootstrap and provide only the
        # attributes required by the controller path under test.
        pass


class _ContextSelectionHarness(_ControllerHarness):
    def __init__(self) -> None:
        super().__init__()
        self.calls: List[str] = []

    def refresh_data(self) -> None:
        self.calls.append("refresh")


class _BusyStateHarness(_ControllerHarness):
    def __init__(self) -> None:
        super().__init__()
        self.busy_view = _View()
        self.view = cast(Any, self.busy_view)


class _RefreshHarness(_ControllerHarness):
    def __init__(self) -> None:
        super().__init__()
        self.key_text = _Var("API_TOKEN")
        self.effective_value_var = _Var("")
        self.events: List[Tuple[str, Optional[object]]] = []

    def _set_busy(self, busy: bool) -> None:
        self.events.append(("busy", busy))

    def _set_status(self, text: str) -> None:
        self.events.append(("status", text))

    def _update_context_values(self) -> None:
        self.events.append(("contexts", None))

    def _fetch_records(self) -> None:
        self.events.append(("fetch", None))

    def _reconcile_targets(self) -> None:
        self.events.append(("targets", None))

    def _render_table(self) -> None:
        self.events.append(("render", None))

    def _update_effective(self, key: str) -> None:
        self.events.append(("effective", key))


class _OperationHarness(_ControllerHarness):
    def __init__(self) -> None:
        super().__init__()
        self.key_text = _Var("API_TOKEN")
        self.value_text = _Var("abc")
        self.selected_targets = ["windows:user"]
        self.records_raw: List[EnvRecord] = []
        self.calls: List[Tuple[str, Optional[object]]] = []

    def _set_status(self, _text: str) -> None:
        return None

    def _preview_operation(
        self, action: str, key: str, value: str, targets: List[str]
    ) -> List[Dict[str, object]]:
        self.calls.append(("preview", action))
        return [{"target": "windows:user", "success": True, "diff_preview": ""}]

    def _confirm_diff(
        self, action: str, previews: List[Dict[str, object]], preview_only: bool = False
    ) -> bool:
        self.calls.append(("confirm", preview_only))
        return True

    def _apply_operation(
        self, action: str, key: str, value: str, targets: List[str]
    ) -> Dict[str, object]:
        self.calls.append(("apply", action))
        return {"success": True, "operation_id": "op-1"}

    def refresh_data(self) -> None:
        self.calls.append(("refresh", None))


def test_var_roundtrip_set_get():
    var = _Var("initial")
    var.set("updated")
    ensure(var.get() == "updated")


def test_context_change_triggers_full_refresh():
    ctrl = _ContextSelectionHarness()

    EnvInspectorController.on_context_selected(ctrl)

    ensure(ctrl.calls == ["refresh"])


def test_busy_state_disable_enable_around_refresh():
    ctrl = _BusyStateHarness()

    EnvInspectorController._set_busy(ctrl, True)
    EnvInspectorController._set_busy(ctrl, False)

    ensure(ctrl.busy_view.enabled_states == [False, True])
    ensure(ctrl.busy_view.busy_states == [True, False])


def test_refresh_updates_effective_value_when_key_present():
    ctrl = _RefreshHarness()

    EnvInspectorController.refresh_data(ctrl)

    ensure(("effective", "API_TOKEN") in ctrl.events)
    ensure(next(((kind, value) for kind, value in ctrl.events if kind == "busy"), None) == ("busy", True))
    ensure(next(((kind, value) for kind, value in reversed(ctrl.events) if kind == "busy"), None) == ("busy", False))


def test_set_remove_operations_always_preview_before_apply():
    ctrl = _OperationHarness()

    EnvInspectorController._run_operation(ctrl, "set")
    EnvInspectorController._run_operation(ctrl, "remove")

    ensure(next(((kind, value) for kind, value in ctrl.calls if kind == "preview"), None) == ("preview", "set"))
    ensure(("confirm", False) in ctrl.calls)
    ensure(("apply", "set") in ctrl.calls)
    ensure(("preview", "remove") in ctrl.calls)
    ensure(("apply", "remove") in ctrl.calls)
