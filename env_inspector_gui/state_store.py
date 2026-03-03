from __future__ import annotations

import json
from pathlib import Path

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


def load_ui_state(state_dir: Path) -> PersistedUiState:
    cfg = Path(state_dir) / CONFIG_FILENAME
    if not cfg.exists():
        return PersistedUiState()

    try:
        payload = json.loads(cfg.read_text(encoding="utf-8"))
    except Exception:
        return PersistedUiState()

    if not isinstance(payload, dict):
        return PersistedUiState()

    try:
        state = PersistedUiState.from_dict(payload)
    except Exception:
        return PersistedUiState()

    if state.sort_column not in SUPPORTED_SORT_COLUMNS:
        state.sort_column = "name"
    state.scan_depth = min(max(int(state.scan_depth or 5), 1), 20)
    return state


def save_ui_state(state_dir: Path, state: PersistedUiState) -> Path:
    base = Path(state_dir)
    base.mkdir(parents=True, exist_ok=True)
    cfg = base / CONFIG_FILENAME
    cfg.write_text(json.dumps(state.to_dict(), ensure_ascii=True, indent=2), encoding="utf-8")
    return cfg


def sanitize_loaded_state(
    state: PersistedUiState,
    *,
    available_contexts: list[str],
    available_targets: list[str],
    fallback_root: Path,
) -> PersistedUiState:
    clean = PersistedUiState(**state.to_dict())
    clean.root_path = str(_sanitize_root(clean.root_path, fallback_root))
    clean.context = _sanitize_context(clean.context, available_contexts)
    clean.selected_targets = _sanitize_targets(clean.selected_targets, available_targets)
    clean.sort_column = _sanitize_sort_column(clean.sort_column)
    clean.scan_depth = _sanitize_scan_depth(clean.scan_depth)
    return clean


def _sanitize_root(root_path: str, fallback_root: Path) -> Path:
    candidate = Path(root_path).expanduser() if root_path else Path(fallback_root)
    if candidate.exists() and candidate.is_dir():  # codeql[py/path-injection] user-approved local persisted path validation
        return candidate
    return Path(fallback_root)


def _sanitize_context(context: str, available_contexts: list[str]) -> str:
    if not available_contexts:
        return ""
    if context in available_contexts:
        return context
    return available_contexts[0]


def _sanitize_targets(selected_targets: list[str], available_targets: list[str]) -> list[str]:
    available_set = set(available_targets)
    return [target for target in selected_targets if target in available_set]


def _sanitize_sort_column(sort_column: str) -> str:
    if sort_column in SUPPORTED_SORT_COLUMNS:
        return sort_column
    return "name"


def _sanitize_scan_depth(scan_depth: int) -> int:
    return min(max(int(scan_depth or 5), 1), 20)
