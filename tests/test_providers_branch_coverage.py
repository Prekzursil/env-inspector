from __future__ import annotations

from pathlib import Path

import pytest

import env_inspector_core.providers as providers
from env_inspector_core.constants import SOURCE_WSL_BASHRC, SOURCE_WSL_ETC_ENV
from env_inspector_core.path_policy import PathPolicyError


def test_is_workspace_scoped_path_checks_exact_and_descendant(tmp_path: Path):
    root = tmp_path / "workspace"
    root.mkdir()
    nested = root / "inner" / "file.txt"

    assert providers._is_workspace_scoped_path(root, root) is True
    assert providers._is_workspace_scoped_path(nested, root) is True
    assert providers._is_workspace_scoped_path(tmp_path / "other", root) is False


def test_discover_dotenv_files_returns_empty_when_root_rejected(monkeypatch, tmp_path: Path):
    def _raise(_root):
        raise PathPolicyError("rejected")

    monkeypatch.setattr(providers, "resolve_scan_root", _raise)

    assert providers.discover_dotenv_files(tmp_path) == []


def test_wsl_decode_falls_back_on_invalid_utf16_bytes():
    raw = b"\x00\x00\x00"

    decoded = providers.WslProvider._decode(raw)

    assert isinstance(decoded, str)


def test_parse_powershell_assignment_rejects_invalid_shapes():
    assert providers._parse_powershell_assignment("$env:PATH") is None
    assert providers._parse_powershell_assignment("$env:1INVALID = 'x'") is None
    assert providers._parse_powershell_assignment("# $env:IGNORED = 'x'") is None


def test_normalize_and_validate_powershell_values_and_keys():
    assert providers._normalize_powershell_assignment_value(" 'value'; ") == "value"
    assert providers._normalize_powershell_assignment_value("plain") == "plain"
    assert providers._is_valid_powershell_env_key("") is False
    assert providers._is_valid_powershell_env_key("1BAD") is False
    assert providers._is_valid_powershell_env_key("GOOD_1") is True


def test_collect_wsl_records_includes_bashrc_and_etc_pairs():
    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> list[str]:
            return ["Ubuntu"]

        def read_file(self, distro: str, path: str) -> str:
            if path == "~/.bashrc":
                return "export API_TOKEN='abc'\n"
            if path == "/etc/environment":
                return "LANG=en_US.UTF-8\n"
            raise AssertionError(f"Unexpected read path: {path}")

    rows = providers.collect_wsl_records(_FakeWsl(), include_etc=True)

    assert any(r.source_type == SOURCE_WSL_BASHRC and r.name == "API_TOKEN" for r in rows)
    assert any(r.source_type == SOURCE_WSL_ETC_ENV and r.name == "LANG" for r in rows)


def test_collect_wsl_records_respects_excluded_distros():
    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> list[str]:
            return ["Ubuntu", "Debian"]

        def read_file(self, distro: str, path: str) -> str:
            return ""

    rows = providers.collect_wsl_records(_FakeWsl(), include_etc=False, exclude_distros={"ubuntu"})

    assert all(r.source_id != "Ubuntu" for r in rows)
