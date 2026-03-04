from __future__ import annotations

from pathlib import Path

from env_inspector_core.providers import discover_dotenv_files


def test_discover_dotenv_files_rejects_outside_workspace_root(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    (outside / ".env").write_text("A=1\n", encoding="utf-8")

    monkeypatch.chdir(workspace)

    assert discover_dotenv_files(outside, max_depth=2) == []


def test_discover_dotenv_files_accepts_workspace_root(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / ".env").write_text("A=1\n", encoding="utf-8")
    nested = workspace / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / ".env.local").write_text("B=2\n", encoding="utf-8")

    monkeypatch.chdir(workspace)

    rows = discover_dotenv_files(workspace, max_depth=2)

    assert workspace / ".env" in rows
    assert nested / ".env.local" in rows
