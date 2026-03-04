from __future__ import annotations

from tests.conftest import ensure
from env_inspector_gui.controller import EnvInspectorController


class _Var:
    def __init__(self, value: str = "") -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def set(self, value: str) -> None:
        self._value = value


class _View:
    def __init__(self) -> None:
        self.enabled_states: list[bool] = []
        self.busy_states: list[bool] = []

    def set_mutation_actions_enabled(self, enabled: bool) -> None:
        self.enabled_states.append(enabled)

    def set_refresh_busy(self, busy: bool) -> None:
        self.busy_states.append(busy)


def test_var_roundtrip_set_get():
    var = _Var("initial")
    var.set("updated")
    ensure(var.get() == 'updated')


def test_context_change_triggers_full_refresh():
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    calls: list[str] = []
    ctrl.refresh_data = lambda: calls.append("refresh")

    EnvInspectorController.on_context_selected(ctrl)

    ensure(calls == ['refresh'])


def test_busy_state_disable_enable_around_refresh():
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    ctrl.view = _View()

    EnvInspectorController._set_busy(ctrl, True)
    EnvInspectorController._set_busy(ctrl, False)

    ensure(ctrl.view.enabled_states == [False, True])
    ensure(ctrl.view.busy_states == [True, False])


def test_refresh_updates_effective_value_when_key_present():
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    ctrl.key_text = _Var("API_TOKEN")

    events: list[tuple[str, object]] = []
    ctrl._set_busy = lambda busy: events.append(("busy", busy))
    ctrl._update_context_values = lambda: events.append(("contexts", None))
    ctrl._fetch_records = lambda: events.append(("fetch", None))
    ctrl._reconcile_targets = lambda: events.append(("targets", None))
    ctrl._render_table = lambda: events.append(("render", None))
    ctrl._update_effective = lambda key: events.append(("effective", key))

    EnvInspectorController.refresh_data(ctrl)

    ensure(('effective', 'API_TOKEN') in events)
    ensure(next(((kind, value) for kind, value in events if kind == 'busy'), None) == ('busy', True))
    ensure(next(((kind, value) for kind, value in reversed(events) if kind == 'busy'), None) == ('busy', False))


def test_set_remove_operations_always_preview_before_apply():
    ctrl = EnvInspectorController.__new__(EnvInspectorController)
    ctrl.key_text = _Var("API_TOKEN")
    ctrl.value_text = _Var("abc")
    ctrl.selected_targets = ["windows:user"]
    ctrl._set_status = lambda _text: None

    calls: list[tuple[str, object]] = []
    ctrl._preview_operation = lambda action, key, value, targets: calls.append(("preview", action)) or [
        {"target": "windows:user", "success": True, "diff_preview": ""}
    ]
    ctrl._confirm_diff = lambda action, previews, preview_only=False: calls.append(("confirm", preview_only)) or True
    ctrl._apply_operation = lambda action, key, value, targets: calls.append(("apply", action)) or {
        "success": True,
        "operation_id": "op-1",
    }
    ctrl.refresh_data = lambda: calls.append(("refresh", None))

    EnvInspectorController._run_operation(ctrl, "set")
    EnvInspectorController._run_operation(ctrl, "remove")

    ensure(next(((kind, value) for kind, value in calls if kind == 'preview'), None) == ('preview', 'set'))
    ensure(('confirm', False) in calls)
    ensure(('apply', 'set') in calls)
    ensure(('preview', 'remove') in calls)
    ensure(('apply', 'remove') in calls)
