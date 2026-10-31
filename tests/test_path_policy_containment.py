"""Containment rules in path_policy: decided on normalized text, sibling-safe."""

import os
from pathlib import Path

import pytest

from env_inspector_core.path_policy import (
    PathPolicyError,
    _continues_at_separator,
    _root_prefix,
    normalize_scope_roots,
    parse_scoped_dotenv_target,
    resolve_scan_root,
    validate_backup_path,
)
from tests.assertions import ensure


def test_root_prefix_strips_trailing_separators() -> None:
    """The filesystem root becomes '' so every absolute path is inside it."""
    ensure(_root_prefix(os.sep) == "")
    ensure(_root_prefix(f"{os.sep}work{os.sep}") == f"{os.sep}work")
    ensure(_root_prefix(Path("relative") / "dir") == f"relative{os.sep}dir")


def test_continues_at_separator() -> None:
    """Only the prefix itself or a child continues at a separator."""
    root = f"{os.sep}work"
    ensure(_continues_at_separator(root, root))
    ensure(_continues_at_separator(f"{root}{os.sep}sub", root))
    ensure(not _continues_at_separator(f"{root}2", root))


@pytest.fixture(name="workspace")
def _workspace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A cwd with a child, plus a sibling that shares its name as a prefix."""
    work = tmp_path / "work"
    (work / "sub").mkdir(parents=True)
    (tmp_path / "work2").mkdir()
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(work)
    return work


def test_resolve_scan_root_accepts_the_workspace_and_its_children(
    workspace: Path,
) -> None:
    """The cwd itself and a directory below it are accepted."""
    ensure(resolve_scan_root(workspace) == workspace)
    ensure(resolve_scan_root(workspace / "sub") == workspace / "sub")


@pytest.mark.parametrize("name", ["work2", "elsewhere"])
def test_resolve_scan_root_rejects_siblings_and_outside_paths(
    workspace: Path, name: str
) -> None:
    """A sibling sharing the cwd's name as a prefix is outside, like any other path."""
    with pytest.raises(PathPolicyError, match="inside the current working directory"):
        resolve_scan_root(workspace.parent / name)


def test_resolve_scan_root_rejects_a_missing_directory(workspace: Path) -> None:
    """A path inside the cwd must still exist as a directory."""
    with pytest.raises(PathPolicyError, match="must exist as a directory"):
        resolve_scan_root(workspace / "missing")


def test_normalize_scope_roots_dedupes_and_rejects_siblings(workspace: Path) -> None:
    """Duplicates collapse; a prefix-sharing sibling is rejected."""
    roots = normalize_scope_roots([workspace, workspace / "sub", workspace])
    ensure(roots == [workspace, workspace / "sub"])
    with pytest.raises(PathPolicyError, match="inside the current working directory"):
        normalize_scope_roots([workspace.parent / "work2"])


def test_validate_backup_path_stays_inside_the_backup_directory(
    workspace: Path,
) -> None:
    """A backup file must sit inside the managed directory, not a lookalike sibling."""
    backups = workspace / "backups"
    backups.mkdir()
    backup = backups / "state.json"
    backup.write_text("{}", encoding="utf-8")
    lookalike = workspace / "backups2"
    lookalike.mkdir()
    stray = lookalike / "state.json"
    stray.write_text("{}", encoding="utf-8")

    ensure(validate_backup_path(backup, backups_dir=backups) == backup)
    with pytest.raises(PathPolicyError, match="outside managed backup directory"):
        validate_backup_path(stray, backups_dir=backups)
    with pytest.raises(PathPolicyError, match="does not exist"):
        validate_backup_path(backups, backups_dir=backups)


def test_parse_scoped_dotenv_target_scope_rules(tmp_path: Path) -> None:
    """A filesystem-root scope contains everything; a prefix-sharing sibling does not."""
    project = tmp_path / "proj"
    sibling = tmp_path / "proj2"
    project.mkdir()
    sibling.mkdir()
    inside = project / ".env"
    stray = sibling / ".env"

    from_root = parse_scoped_dotenv_target(
        f"dotenv:{stray}", roots=[Path(stray.anchor)]
    )
    ensure(from_root.path == stray)
    ensure(
        parse_scoped_dotenv_target(f"dotenv:{inside}", roots=[project]).path == inside
    )
    with pytest.raises(PathPolicyError, match="outside approved roots"):
        parse_scoped_dotenv_target(f"dotenv:{stray}", roots=[project])
