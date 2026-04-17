"""Shared fixtures for env_inspector_gui.controller test suites.

Holding the harness, mock view, and row/record builders here lets the
controller coverage tests stay split into two focused files (basic state
methods vs. operations + boot state) without cloning ~250 lines of fixture
code in each. Importing from a non-test module also keeps pytest from
collecting these definitions twice.
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple, cast
from unittest.mock import MagicMock

from env_inspector_core.models import EnvRecord
from env_inspector_gui.controller import EnvInspectorController
from env_inspector_gui.models import DisplayedRow, PersistedUiState

_NEGATIVE_FLAG_TEXT = "no"  # avoid Bandit B106 false-positive on _text="no" literals


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

    @staticmethod
    def clear_table() -> None:
        """Stub for testing."""

    def insert_table_row(  # pylint: disable=no-self-use
        self, values: Tuple[Any, ...], *, striped: bool
    ) -> str:
        """Handle insert table row.

        Captures call args so production code matches our test surface; the
        return value is the Treeview iid we hand back for selection assertions.
        """
        # values + striped intentionally unused — stub mirrors view protocol
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

    def _initialize_view(
        self, _tk: Any, _ttk: Any, _boot_state: PersistedUiState
    ) -> None:
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
        "is_secret": False,  # nosec B105
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
        secret_text=_NEGATIVE_FLAG_TEXT,
        persistent_text=_NEGATIVE_FLAG_TEXT,
        mutable_text=_NEGATIVE_FLAG_TEXT,
        writable_text=_NEGATIVE_FLAG_TEXT,
        requires_privilege_text=_NEGATIVE_FLAG_TEXT,
        original_index=0,
    )


__all__ = [
    "_BOOTSTRAP_TK_MODULE",
    "_BootstrapRoot",
    "_Harness",
    "_MockView",
    "_NEGATIVE_FLAG_TEXT",
    "_Var",
    "_make_record",
    "_make_row",
]
