"""Coverage tests for path_policy.py — edge cases for path validation."""

from __future__ import absolute_import, division

from pathlib import Path

import pytest

from env_inspector_core.path_policy import (
    PathPolicyError,
    _as_raw_text,
    _contains_null,
    normalize_scope_roots,
    resolve_scan_root,
    validate_backup_path,
    parse_scoped_dotenv_target,
)


# Line 26: _as_raw_text empty string
def test_as_raw_text_rejects_empty() -> None:
    """_as_raw_text raises PathPolicyError for empty string."""
    with pytest.raises(PathPolicyError, match="must not be empty"):
        _as_raw_text("", field_name="test")


# Line 46: normalize_scope_roots outside cwd
def test_normalize_scope_roots_rejects_outside_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """normalize_scope_roots raises when root is outside cwd."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(workspace)
    with pytest.raises(PathPolicyError, match="inside the current working directory"):
        normalize_scope_roots([str(outside)])


# Line 48: normalize_scope_roots non-existent directory
def test_normalize_scope_roots_rejects_nonexistent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """normalize_scope_roots raises when root does not exist."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(PathPolicyError, match="must exist as a directory"):
        normalize_scope_roots([str(tmp_path / "nonexistent")])


# Line 55: normalize_scope_roots empty list
def test_normalize_scope_roots_rejects_empty() -> None:
    """normalize_scope_roots raises when no roots are provided."""
    with pytest.raises(PathPolicyError, match="At least one scope root"):
        normalize_scope_roots([])


# Line 80: parse_scoped_dotenv_target without dotenv: prefix
def test_parse_scoped_dotenv_target_rejects_non_dotenv_prefix(tmp_path: Path) -> None:
    """parse_scoped_dotenv_target raises when target lacks 'dotenv:' prefix."""
    with pytest.raises(PathPolicyError, match="Expected target with 'dotenv:' prefix"):
        parse_scoped_dotenv_target("linux:bashrc", roots=[tmp_path])


# parse_scoped_dotenv_target outside scope
def test_parse_scoped_dotenv_target_rejects_outside_roots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """parse_scoped_dotenv_target raises when path is outside approved roots."""
    monkeypatch.chdir(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target_dir = tmp_path / "other"
    target_dir.mkdir()
    env_file = target_dir / ".env"
    env_file.touch()

    with pytest.raises(PathPolicyError, match="outside approved roots"):
        parse_scoped_dotenv_target(f"dotenv:{env_file}", roots=[allowed])


# Line 108: validate_backup_path non-existent file
def test_validate_backup_path_rejects_nonexistent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """validate_backup_path raises when backup file does not exist."""
    monkeypatch.chdir(tmp_path)
    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    with pytest.raises(PathPolicyError, match="does not exist"):
        validate_backup_path(str(backups_dir / "missing.json"), backups_dir=backups_dir)
