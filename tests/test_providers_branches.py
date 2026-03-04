from __future__ import annotations

from pathlib import Path
from typing import cast

from env_inspector_core.providers import (
    WslProvider,
    _append_wsl_bashrc_records,
    _append_wsl_etc_records,
    _normalize_powershell_value,
    _resolve_scoped_root,
    collect_wsl_records,
    discover_dotenv_files,
)


def test_resolve_scoped_root_requires_existing_directory(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)

    ensure(_resolve_scoped_root(workspace / 'missing', workspace) is None)


def test_resolve_scoped_root_rejects_path_outside_workspace_root(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    sibling = tmp_path / "sibling"
    workspace.mkdir(parents=True, exist_ok=True)
    sibling.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)

    ensure(_resolve_scoped_root(sibling, workspace) is None)


def test_discover_dotenv_files_honors_depth_limit(tmp_path: Path, monkeypatch):
    root = tmp_path / "workspace"
    nested = root / "nested" / "deep"
    nested.mkdir(parents=True, exist_ok=True)
    (root / ".env").write_text("A=1\n", encoding="utf-8")
    (nested / ".env.local").write_text("B=2\n", encoding="utf-8")

    monkeypatch.chdir(root)

    rows = discover_dotenv_files(root, max_depth=1)

    ensure(root / '.env' in rows)
    ensure(nested / '.env.local' not in rows)


def test_wsl_scan_dotenv_files_filters_blank_lines(monkeypatch):
    provider = WslProvider(wsl_exe="wsl")
    monkeypatch.setattr(provider, "_run", lambda *_args, **_kwargs: "\n/opt/env/.env\n\n/opt/env/.env.local\n")

    rows = provider.scan_dotenv_files("Ubuntu", "/opt/env", 2)

    ensure(rows == ['/opt/env/.env', '/opt/env/.env.local'])


def test_normalize_powershell_value_handles_semicolon_and_unquoted_values():
    ensure(_normalize_powershell_value("'abc';") == 'abc')
    ensure(_normalize_powershell_value('raw-value') == 'raw-value')


def test_append_wsl_helpers_and_collect_records_include_and_exclude():
    rows = []
    _append_wsl_bashrc_records(rows, distro="Ubuntu", context="wsl:Ubuntu", bash_text="export A='1'\n")
    _append_wsl_etc_records(rows, distro="Ubuntu", context="wsl:Ubuntu", etc_text="B=2\n")

    ensure(any((item.source_type == 'wsl_bashrc' and item.name == 'A' for item in rows)))
    ensure(any((item.source_type == 'wsl_etc_environment' and item.name == 'B' for item in rows)))

    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> list[str]:
            return ["Ubuntu", "Debian"]

        def read_file(self, distro: str, path: str) -> str:
            if path == "~/.bashrc":
                return "export A='1'\n"
            return "B=2\n"

    collected = collect_wsl_records(cast(WslProvider, _FakeWsl()), include_etc=True, exclude_distros={"ubuntu"})

    ensure(all((item.source_id == 'Debian' for item in collected)))
    ensure(any((item.source_type == 'wsl_etc_environment' for item in collected)))


def test_collect_wsl_records_returns_empty_when_unavailable():
    class _FakeUnavailable:
        def available(self) -> bool:
            return False

    ensure(collect_wsl_records(cast(WslProvider, _FakeUnavailable()), include_etc=True, exclude_distros=None) == [])
