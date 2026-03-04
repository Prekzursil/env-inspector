from __future__ import absolute_import, division

from pathlib import Path

from env_inspector_gui.models import PersistedUiState
from env_inspector_gui.state_store import load_ui_state, save_ui_state, sanitize_loaded_state

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



def test_state_store_roundtrip(tmp_path: Path):
    state_dir = tmp_path / ".env-inspector-state"
    state = PersistedUiState(
        window_geometry="1300x900",
        root_path=str(tmp_path),
        context="windows",
        show_secrets=True,
        only_secrets=False,
        filter_text="token",
        selected_targets=["windows:user", "dotenv:/tmp/.env"],
        sort_column="name",
        sort_descending=True,
        wsl_distro="Ubuntu",
        wsl_path="/home/user/project",
        scan_depth=7,
    )

    save_ui_state(state_dir, state)
    loaded = load_ui_state(state_dir)

    _expect(loaded.window_geometry == "1300x900")

    _expect(loaded.selected_targets == ["windows:user", "dotenv:/tmp/.env"])

    _expect(loaded.sort_descending is True)



def test_invalid_json_falls_back_to_defaults(tmp_path: Path):
    state_dir = tmp_path / ".env-inspector-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "config.json").write_text("{invalid json", encoding="utf-8")

    loaded = load_ui_state(state_dir)

    _expect(isinstance(loaded, PersistedUiState))

    _expect(loaded.filter_text == "")

    _expect(loaded.selected_targets == [])



def test_sanitize_loaded_state_prunes_context_and_targets(tmp_path: Path):
    state = PersistedUiState(
        root_path=str(tmp_path / "missing-root"),
        context="wsl:NotInstalled",
        selected_targets=["windows:user", "wsl:Ghost:bashrc"],
    )

    sanitized = sanitize_loaded_state(
        state,
        available_contexts=["windows", "wsl:Ubuntu"],
        available_targets=["windows:user", "dotenv:/tmp/.env"],
        fallback_root=tmp_path,
    )

    _expect(sanitized.root_path == str(tmp_path))

    _expect(sanitized.context == "windows")

    _expect(sanitized.selected_targets == ["windows:user"])
