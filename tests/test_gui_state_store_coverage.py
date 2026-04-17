"""Coverage tests for env_inspector_gui.state_store — missing lines 43, 51, 55-56, 59, 105, 107, 119."""

import json
from pathlib import Path

from env_inspector_core.path_policy import PathPolicyError
from env_inspector_gui import state_store as state_store_mod
from env_inspector_gui.models import PersistedUiState
from env_inspector_gui.state_store import (
    _sanitize_context,
    _sanitize_root,
    _sanitize_scan_depth,
    _sanitize_sort_column,
    _sanitize_targets,
    load_ui_state,
)
from tests.assertions import ensure


def test_load_ui_state_missing_directory(tmp_path: Path):
    """Line 43: config file does not exist, returns default."""
    loaded = load_ui_state(tmp_path / "nonexistent")
    ensure(isinstance(loaded, PersistedUiState))
    ensure(loaded.filter_text == "")


def test_load_ui_state_non_dict_json(tmp_path: Path):
    """Line 51: JSON parses but is not a dict (e.g. a list)."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "config.json").write_text("[1, 2, 3]", encoding="utf-8")
    loaded = load_ui_state(state_dir)
    ensure(isinstance(loaded, PersistedUiState))
    ensure(loaded.filter_text == "")


def test_load_ui_state_from_dict_raises(tmp_path: Path):
    """Lines 55-56: PersistedUiState.from_dict raises TypeError/ValueError/KeyError."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    # Write a dict that would cause from_dict to fail if coerce functions
    # can't handle it — but actually from_dict is quite robust with coerce helpers.
    # We need to test the except clause. Let's monkey-patch from_dict temporarily.
    original_from_dict = PersistedUiState.from_dict

    def bad_from_dict(payload):
        """Bad from dict."""
        raise TypeError("forced error")

    PersistedUiState.from_dict = classmethod(lambda cls, p: bad_from_dict(p))
    try:
        (state_dir / "config.json").write_text('{"version": 1}', encoding="utf-8")
        loaded = load_ui_state(state_dir)
        ensure(isinstance(loaded, PersistedUiState))
        ensure(loaded.filter_text == "")
    finally:
        PersistedUiState.from_dict = original_from_dict


def test_load_ui_state_invalid_sort_column(tmp_path: Path):
    """Line 59: loaded state has invalid sort_column, reset to 'name'."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    data = PersistedUiState(sort_column="bogus_column").to_dict()
    (state_dir / "config.json").write_text(json.dumps(data), encoding="utf-8")
    loaded = load_ui_state(state_dir)
    ensure(loaded.sort_column == "name")


def test_sanitize_context_empty_available():
    """Line 105: empty available contexts returns empty string."""
    ensure(_sanitize_context("anything", []) == "")


def test_sanitize_context_in_available():
    """Line 107: context IS in available, returns it directly."""
    ensure(_sanitize_context("a", ["a", "b"]) == "a")


def test_sanitize_context_not_in_available():
    """Line 108: context not in available, falls back to first."""
    ensure(_sanitize_context("missing", ["a", "b"]) == "a")


def test_sanitize_sort_column_invalid():
    """Line 119: invalid sort column falls back to 'name'."""
    ensure(_sanitize_sort_column("invalid_col") == "name")


def test_sanitize_sort_column_valid():
    """Test sanitize sort column valid."""
    ensure(_sanitize_sort_column("context") == "context")


def test_sanitize_scan_depth_clamps():
    # 0 triggers the `or 5` fallback, so int(0 or 5) == 5
    """Test sanitize scan depth clamps."""
    ensure(_sanitize_scan_depth(0) == 5)
    ensure(_sanitize_scan_depth(100) == 20)
    ensure(_sanitize_scan_depth(10) == 10)


def test_sanitize_targets_prunes():
    """Test sanitize targets prunes."""
    result = _sanitize_targets(["a", "b", "c"], ["a", "c", "d"])
    ensure(result == ["a", "c"])


def test_sanitize_root_fallback(tmp_path: Path):
    """Lines in _sanitize_root: bad root_path falls through to fallback_root."""
    result = _sanitize_root("", tmp_path)
    ensure(str(result) == str(tmp_path))


def test_sanitize_root_double_failure_returns_fallback_path(
    tmp_path: Path, monkeypatch
):
    """Lines 97-100: when both resolve attempts raise, return Path(fallback_root) verbatim.

    Mocking the resolver isolates this branch from pytest tmp layout —
    callers may pass fallback paths that still fail policy checks (e.g. if
    cwd changes mid-flight), and we must not crash.
    """

    def _always_raise(_value):
        """Always raise."""
        raise PathPolicyError("forced for coverage")

    monkeypatch.setattr(state_store_mod, "resolve_scan_root", _always_raise)
    result = _sanitize_root("any-bad-input", tmp_path)
    ensure(result == Path(tmp_path))
