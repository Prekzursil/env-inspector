"""Path policy module."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Tuple
from collections.abc import Iterable


class PathPolicyError(ValueError):
    """Raised when a user-provided path violates security policy."""


@dataclass(frozen=True)
class ScopedPath:
    """A filesystem path constrained to approved scope roots."""

    path: Path
    roots: Tuple[Path, ...]


def _contains_null(raw: str) -> bool:
    """Contains null."""
    return "\x00" in raw


def _as_raw_text(value: str | Path, *, field_name: str) -> str:
    """As raw text."""
    raw = str(value)
    if not raw:
        raise PathPolicyError(f"{field_name} must not be empty.")
    if _contains_null(raw):
        raise PathPolicyError(f"{field_name} contains an invalid null byte.")
    return raw


def _normalize_path_text(value: str | Path, *, field_name: str) -> str:
    """Normalize path text."""
    raw = _as_raw_text(value, field_name=field_name)
    return os.path.normpath(os.path.abspath(os.path.expanduser(raw)))


def _root_prefix(root: str | Path) -> str:
    """Return ``root`` as text without a trailing separator ('/' becomes '')."""
    return str(root).rstrip(os.sep)


def _continues_at_separator(path_text: str, prefix: str) -> bool:
    """Return True if ``path_text`` is ``prefix`` itself or continues with a separator.

    Callers have already checked ``path_text.startswith(prefix)``. This second
    step rejects a sibling that merely shares the prefix, such as ``/work2``
    for the root ``/work``.
    """
    rest = path_text[len(prefix) :]
    return not rest or rest.startswith(os.sep)


def normalize_scope_roots(roots: Iterable[str | Path]) -> List[Path]:
    """Normalize scope roots."""
    normalized: List[Path] = []
    seen: Set[str] = set()
    workspace_prefix = _root_prefix(Path.cwd())
    for root in roots:
        root_text = _normalize_path_text(root, field_name="scope root")
        # Containment is decided on the normalized text before a Path is built
        # from it, so only checked text ever reaches the filesystem calls below.
        if not root_text.startswith(workspace_prefix) or not _continues_at_separator(
            root_text, workspace_prefix
        ):
            raise PathPolicyError(
                f"Scope root must be inside the current working directory: {root_text}"
            )
        path = Path(root_text)
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
    """Resolve scan root."""
    root_text = _normalize_path_text(root, field_name="scan root")
    workspace_prefix = _root_prefix(Path.cwd())
    # Containment is decided on the normalized text before a Path is built from
    # it, so only checked text ever reaches the filesystem calls below.
    if not root_text.startswith(workspace_prefix) or not _continues_at_separator(
        root_text, workspace_prefix
    ):
        raise PathPolicyError(
            f"Scan root must be inside the current working directory: {root_text}"
        )
    path = Path(root_text)
    if not path.exists() or not path.is_dir():
        raise PathPolicyError(f"Scan root must exist as a directory: {path}")
    return path


def _validate_dotenv_name(path: Path) -> None:
    """Validate dotenv name."""
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return
    raise PathPolicyError(
        "dotenv target must point to a file named '.env' or '.env.*'."
    )


def parse_scoped_dotenv_target(target: str, *, roots: List[Path]) -> ScopedPath:
    """Parse scoped dotenv target."""
    if not target.startswith("dotenv:"):
        raise PathPolicyError("Expected target with 'dotenv:' prefix.")
    raw = target[len("dotenv:") :]
    path_text = _normalize_path_text(raw, field_name="dotenv target path")
    path = Path(path_text)
    _validate_dotenv_name(path)

    in_scope = False
    for root in roots:
        # Same rule as resolve_scan_root, so a filesystem-root scope (POSIX
        # "/" or a Windows drive root) contains everything below it instead
        # of turning into a "//" prefix that matches nothing.
        root_prefix = _root_prefix(root)
        if path_text.startswith(root_prefix) and _continues_at_separator(
            path_text, root_prefix
        ):
            in_scope = True
            break
    if not in_scope:
        raise PathPolicyError(
            "dotenv target path is outside approved roots. "
            "Re-run with --root <parent> or choose that folder in GUI."
        )
    return ScopedPath(path=path, roots=tuple(roots))


def validate_backup_path(backup: str | Path, *, backups_dir: Path) -> Path:
    """Validate backup path."""
    backup_text = _normalize_path_text(backup, field_name="backup path")
    backups_prefix = _root_prefix(resolve_scan_root(backups_dir))
    # Same rule as resolve_scan_root: check the normalized text, then build
    # the Path that touches the filesystem from the checked text only.
    if not backup_text.startswith(backups_prefix) or not _continues_at_separator(
        backup_text, backups_prefix
    ):
        raise PathPolicyError("Backup path is outside managed backup directory.")
    backup_path = Path(backup_text)
    if not backup_path.exists() or not backup_path.is_file():
        raise PathPolicyError(f"Backup file does not exist: {backup_path}")
    return backup_path
