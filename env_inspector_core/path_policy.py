from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class PathPolicyError(ValueError):
    """Raised when a user-provided path violates security policy."""


@dataclass(frozen=True)
class ScopedPath:
    path: Path
    roots: tuple[Path, ...]


def _contains_null(raw: str) -> bool:
    return "\x00" in raw


def _as_raw_text(value: str | Path, *, field_name: str) -> str:
    raw = str(value)
    if not raw:
        raise PathPolicyError(f"{field_name} must not be empty.")
    if _contains_null(raw):
        raise PathPolicyError(f"{field_name} contains an invalid null byte.")
    return raw


def _resolve_path(value: str | Path, *, field_name: str) -> Path:
    raw = _as_raw_text(value, field_name=field_name)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return Path(os.path.normpath(str(path)))


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def normalize_scope_roots(roots: Iterable[str | Path]) -> list[Path]:
    normalized: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        path = _resolve_path(root, field_name="scope root")
        if not path.exists() or not path.is_dir():
            raise PathPolicyError(f"Scope root must exist as a directory: {path}")
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(path)
    if not normalized:
        raise PathPolicyError("At least one scope root is required.")
    return normalized


def resolve_scan_root(root: str | Path) -> Path:
    path = _resolve_path(root, field_name="scan root")
    if not path.exists() or not path.is_dir():
        raise PathPolicyError(f"Scan root must exist as a directory: {path}")
    return path


def _validate_dotenv_name(path: Path) -> None:
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return
    raise PathPolicyError("dotenv target must point to a file named '.env' or '.env.*'.")


def parse_scoped_dotenv_target(target: str, *, roots: list[Path]) -> ScopedPath:
    if not target.startswith("dotenv:"):
        raise PathPolicyError("Expected target with 'dotenv:' prefix.")
    raw = target[len("dotenv:") :]
    path = _resolve_path(raw, field_name="dotenv target path")
    _validate_dotenv_name(path)

    if not any(_is_within(root, path) for root in roots):
        raise PathPolicyError(
            "dotenv target path is outside approved roots. "
            "Re-run with --root <parent> or choose that folder in GUI."
        )
    return ScopedPath(path=path, roots=tuple(roots))


def validate_backup_path(backup: str | Path, *, backups_dir: Path) -> Path:
    backup_path = _resolve_path(backup, field_name="backup path")
    backups_root = resolve_scan_root(backups_dir)
    if not _is_within(backups_root, backup_path):
        raise PathPolicyError("Backup path is outside managed backup directory.")
    if not backup_path.exists() or not backup_path.is_file():
        raise PathPolicyError(f"Backup file does not exist: {backup_path}")
    return backup_path
