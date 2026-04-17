from __future__ import absolute_import, division

from typing import List
import json
import os
from pathlib import Path

from env_inspector_core.path_policy import PathPolicyError, resolve_scan_root

from .models import PersistedUiState

CONFIG_FILENAME = "config.json"
SUPPORTED_SORT_COLUMNS = {
    "context",
    "source",
    "name",
    "value",
    "secret",
    "persistent",
    "mutable",
    "source_path",
    "precedence_rank",
}


def _path_exists(path: Path) -> bool:
    return os.path.exists(path)


def _read_text(path: Path) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _write_text(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def load_ui_state(state_dir: Path) -> PersistedUiState:
    cfg = Path(state_dir) / CONFIG_FILENAME
    if not _path_exists(cfg):
        return PersistedUiState()

    try:
        payload = json.loads(_read_text(cfg))
    except (OSError, TypeError, ValueError):
        return PersistedUiState()

    if not isinstance(payload, dict):
        return PersistedUiState()

    try:
        state = PersistedUiState.from_dict(payload)
    except (TypeError, ValueError, KeyError):
        return PersistedUiState()

    if state.sort_column not in SUPPORTED_SORT_COLUMNS:
        state.sort_column = "name"
    state.scan_depth = min(max(int(state.scan_depth or 5), 1), 20)
    return state


def save_ui_state(state_dir: Path, state: PersistedUiState) -> Path:
    base = Path(state_dir)
    os.makedirs(base, exist_ok=True)
    cfg = base / CONFIG_FILENAME
    _write_text(cfg, json.dumps(state.to_dict(), ensure_ascii=True, indent=2))
    return cfg


def sanitize_loaded_state(
    state: PersistedUiState,
    *,
    available_contexts: List[str],
    available_targets: List[str],
    fallback_root: Path,
) -> PersistedUiState:
    clean = PersistedUiState.from_dict(state.to_dict())
    clean.root_path = str(_sanitize_root(clean.root_path, fallback_root))
    clean.context = _sanitize_context(clean.context, available_contexts)
    clean.selected_targets = _sanitize_targets(
        clean.selected_targets, available_targets
    )
    clean.sort_column = _sanitize_sort_column(clean.sort_column)
    clean.scan_depth = _sanitize_scan_depth(clean.scan_depth)
    return clean


def _sanitize_root(root_path: str, fallback_root: Path) -> Path:
    candidate = root_path if root_path else str(fallback_root)
    try:
        return resolve_scan_root(candidate)
    except PathPolicyError:
        pass

    try:
        return resolve_scan_root(fallback_root)
    except PathPolicyError:
        pass

    return Path(fallback_root)


def _sanitize_context(context: str, available_contexts: List[str]) -> str:
    if not available_contexts:
        return ""
    if context in available_contexts:
        return context
    return available_contexts[0]


def _sanitize_targets(
    selected_targets: List[str], available_targets: List[str]
) -> List[str]:
    available_set = set(available_targets)
    return [target for target in selected_targets if target in available_set]


def _sanitize_sort_column(sort_column: str) -> str:
    if sort_column in SUPPORTED_SORT_COLUMNS:
        return sort_column
    return "name"


def _sanitize_scan_depth(scan_depth: int) -> int:
    return min(max(int(scan_depth or 5), 1), 20)
