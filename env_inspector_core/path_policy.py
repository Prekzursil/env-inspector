from __future__ import absolute_import

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


def _normalize_path_text(value: str | Path, *, field_name: str) -> str:
    raw = _as_raw_text(value, field_name=field_name)
    return os.path.normpath(os.path.abspath(os.path.expanduser(raw)))


def normalize_scope_roots(roots: Iterable[str | Path]) -> list[Path]:
    normalized: list[Path] = []
    seen: set[str] = set()
    workspace_root = Path.cwd()
    workspace_text = str(workspace_root)
    for root in roots:
        path = Path(_normalize_path_text(root, field_name="scope root"))
        path_text = str(path)
        if path_text != workspace_text and not path_text.startswith(workspace_text + os.sep):
            raise PathPolicyError(f"Scope root must be inside the current working directory: {path}")
        if not path.exists() or not path.is_dir():  # codeql[py/path-injection] user-approved local path validation
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
    path = Path(_normalize_path_text(root, field_name="scan root"))
    workspace_root = Path.cwd()
    workspace_text = str(workspace_root)
    path_text = str(path)
    if path_text != workspace_text and not path_text.startswith(workspace_text + os.sep):
        raise PathPolicyError(f"Scan root must be inside the current working directory: {path}")
    if not path.exists() or not path.is_dir():  # codeql[py/path-injection] user-approved local path validation
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
    path = Path(_normalize_path_text(raw, field_name="dotenv target path"))
    _validate_dotenv_name(path)

    in_scope = False
    path_text = str(path)
    for root in roots:
        root_text = str(root)
        if path_text == root_text or path_text.startswith(root_text + os.sep):
            in_scope = True
            break
    if not in_scope:
        raise PathPolicyError(
            "dotenv target path is outside approved roots. "
            "Re-run with --root <parent> or choose that folder in GUI."
        )
    return ScopedPath(path=path, roots=tuple(roots))


def validate_backup_path(backup: str | Path, *, backups_dir: Path) -> Path:
    backup_path = Path(_normalize_path_text(backup, field_name="backup path"))
    backups_root = resolve_scan_root(backups_dir)
    backup_text = str(backup_path)
    backups_text = str(backups_root)
    if backup_text != backups_text and not backup_text.startswith(backups_text + os.sep):
        raise PathPolicyError("Backup path is outside managed backup directory.")
    if not backup_path.exists() or not backup_path.is_file():  # codeql[py/path-injection] validated backup scope guard
        raise PathPolicyError(f"Backup file does not exist: {backup_path}")
    return backup_path
