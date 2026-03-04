from pathlib import Path

import pytest

from env_inspector_core.path_policy import (
    PathPolicyError,
    normalize_scope_roots,
    parse_scoped_dotenv_target,
    resolve_scan_root,
)


def test_resolve_scan_root_rejects_null_byte(tmp_path: Path):
    bad = str(tmp_path) + "\x00suffix"
    with pytest.raises(PathPolicyError):
        resolve_scan_root(bad)


def test_parse_scoped_dotenv_target_allows_path_inside_scope(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    env_file = project / ".env.local"
    env_file.write_text("A=1\n", encoding="utf-8")

    roots = normalize_scope_roots([tmp_path])
    scoped = parse_scoped_dotenv_target(f"dotenv:{env_file}", roots=roots)

    ensure(scoped.path == env_file.resolve())


def test_parse_scoped_dotenv_target_rejects_outside_scope(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    env_file = outside / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    roots = normalize_scope_roots([allowed])
    with pytest.raises(PathPolicyError):
        parse_scoped_dotenv_target(f"dotenv:{env_file}", roots=roots)


def test_parse_scoped_dotenv_target_rejects_non_dotenv_filename(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "folder"
    folder.mkdir()
    bad_file = folder / "settings.txt"
    bad_file.write_text("A=1\n", encoding="utf-8")

    roots = normalize_scope_roots([tmp_path])
    with pytest.raises(PathPolicyError):
        parse_scoped_dotenv_target(f"dotenv:{bad_file}", roots=roots)
