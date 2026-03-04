from __future__ import annotations

from pathlib import Path

from env_inspector_core import providers as providers_mod
from env_inspector_core.providers import (
    WslProvider,
    _append_wsl_bashrc_records,
    _append_wsl_etc_records,
    _normalize_powershell_value,
    _resolve_scoped_root,
    collect_wsl_records,
    discover_dotenv_files,
)


def test_resolve_scoped_root_requires_existing_directory(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    assert _resolve_scoped_root(workspace / "missing", workspace) is None


def test_discover_dotenv_files_honors_depth_limit(tmp_path: Path, monkeypatch):
    root = tmp_path / "workspace"
    nested = root / "nested" / "deep"
    nested.mkdir(parents=True, exist_ok=True)
    (root / ".env").write_text("A=1\n", encoding="utf-8")
    (nested / ".env.local").write_text("B=2\n", encoding="utf-8")

    monkeypatch.chdir(root)

    rows = discover_dotenv_files(root, max_depth=1)

    assert root / ".env" in rows
    assert nested / ".env.local" not in rows


def test_wsl_scan_dotenv_files_filters_blank_lines(monkeypatch):
    provider = WslProvider(wsl_exe="wsl")
    monkeypatch.setattr(provider, "_run", lambda *_args, **_kwargs: "\n/tmp/.env\n\n/tmp/.env.local\n")

    rows = provider.scan_dotenv_files("Ubuntu", "/tmp", 2)

    assert rows == ["/tmp/.env", "/tmp/.env.local"]


def test_normalize_powershell_value_handles_semicolon_and_unquoted_values():
    assert _normalize_powershell_value("'abc';") == "abc"
    assert _normalize_powershell_value("raw-value") == "raw-value"


def test_append_wsl_helpers_and_collect_records_include_and_exclude(monkeypatch):
    rows = []
    _append_wsl_bashrc_records(rows, distro="Ubuntu", context="wsl:Ubuntu", bash_text="export A='1'\n")
    _append_wsl_etc_records(rows, distro="Ubuntu", context="wsl:Ubuntu", etc_text="B=2\n")

    assert any(item.source_type == "wsl_bashrc" and item.name == "A" for item in rows)
    assert any(item.source_type == "wsl_etc_environment" and item.name == "B" for item in rows)

    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> list[str]:
            return ["Ubuntu", "Debian"]

        def read_file(self, distro: str, path: str) -> str:
            if path == "~/.bashrc":
                return "export A='1'\n"
            return "B=2\n"

    collected = collect_wsl_records(_FakeWsl(), include_etc=True, exclude_distros={"ubuntu"})

    assert all(item.source_id == "Debian" for item in collected)
    assert any(item.source_type == "wsl_etc_environment" for item in collected)


def test_collect_wsl_records_returns_empty_when_unavailable():
    class _FakeUnavailable:
        def available(self) -> bool:
            return False

    assert collect_wsl_records(_FakeUnavailable(), include_etc=True, exclude_distros=None) == []
