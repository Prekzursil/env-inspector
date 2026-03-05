from __future__ import absolute_import

from pathlib import Path
from typing import List
import unittest

import pytest

import env_inspector_core.providers as providers
from env_inspector_core.constants import SOURCE_WSL_BASHRC, SOURCE_WSL_ETC_ENV
from env_inspector_core.path_policy import PathPolicyError


def _case() -> unittest.TestCase:
    return unittest.TestCase()



def test_is_workspace_scoped_path_checks_exact_and_descendant(tmp_path: Path):
    root = tmp_path.joinpath("workspace")
    root.mkdir()
    nested = root.joinpath("inner", "file.txt")

    case = _case()
    case.assertTrue(providers._is_workspace_scoped_path(root, root))
    case.assertTrue(providers._is_workspace_scoped_path(nested, root))
    case.assertFalse(providers._is_workspace_scoped_path(tmp_path.joinpath("other"), root))


def test_discover_dotenv_files_returns_empty_when_root_rejected(monkeypatch, tmp_path: Path):
    def _raise(_root):
        raise PathPolicyError("rejected")

    monkeypatch.setattr(providers, "resolve_scan_root", _raise)

    _case().assertEqual(providers.discover_dotenv_files(tmp_path), [])


def test_iter_dotenv_candidates_prunes_dirs_when_depth_exceeds_limit(tmp_path: Path):
    root = tmp_path.joinpath("workspace")
    nested = root.joinpath("nested")
    nested.mkdir(parents=True)
    nested.joinpath(".env").write_text("A=1\n", encoding="utf-8")

    rows = providers._iter_dotenv_candidates(root, max_depth=0)

    _case().assertEqual(rows, [])


def test_windows_registry_provider_guard_and_invalid_scope(monkeypatch):
    monkeypatch.setattr(providers, "is_windows", lambda: False)
    with pytest.raises(RuntimeError):
        providers.WindowsRegistryProvider()

    with pytest.raises(ValueError):
        providers.WindowsRegistryProvider._scope_to_key("unsupported-scope")


def test_wsl_decode_falls_back_on_invalid_utf16_bytes():
    raw = b"\x00\x00\x00"

    decoded = providers.WslProvider._decode(raw)

    _case().assertIsInstance(decoded, str)


def test_parse_powershell_assignment_rejects_invalid_shapes():
    case = _case()
    case.assertIsNone(providers._parse_powershell_assignment("$env:PATH"))
    case.assertIsNone(providers._parse_powershell_assignment("$env:1INVALID = 'x'"))
    case.assertIsNone(providers._parse_powershell_assignment("# $env:IGNORED = 'x'"))


def test_normalize_and_validate_powershell_values_and_keys():
    case = _case()
    case.assertEqual(providers._normalize_powershell_assignment_value(" 'value'; "), "value")
    case.assertEqual(providers._normalize_powershell_assignment_value("plain"), "plain")
    case.assertFalse(providers._is_valid_powershell_env_key(""))
    case.assertFalse(providers._is_valid_powershell_env_key("1BAD"))
    case.assertTrue(providers._is_valid_powershell_env_key("GOOD_1"))


def test_collect_wsl_records_includes_bashrc_and_etc_pairs():
    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> List[str]:
            return ["Ubuntu"]

        def read_file(self, distro: str, path: str) -> str:
            mapping = {
                "~/.bashrc": "export API_TOKEN='abc'\n",
                "/etc/environment": "LANG=en_US.UTF-8\n",
            }
            return mapping.get(path, "")

        def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> List[str]:
            return getattr(self, "_dotenv_paths", [])

    fake = _FakeWsl()
    rows = providers.collect_wsl_records(fake, include_etc=True)
    _case().assertEqual(fake.scan_dotenv_files("Ubuntu", "/workspace", 1), [])

    case = _case()
    case.assertTrue(any(r.source_type == SOURCE_WSL_BASHRC and r.name == "API_TOKEN" for r in rows))
    case.assertTrue(any(r.source_type == SOURCE_WSL_ETC_ENV and r.name == "LANG" for r in rows))


def test_collect_wsl_records_respects_excluded_distros():
    class _FakeWsl:
        def available(self) -> bool:
            return True

        def list_distros(self) -> List[str]:
            return ["Ubuntu", "Debian"]

        def read_file(self, distro: str, path: str) -> str:
            return ""

        def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> List[str]:
            return getattr(self, "_dotenv_paths", [])

    fake = _FakeWsl()
    rows = providers.collect_wsl_records(fake, include_etc=False, exclude_distros={"ubuntu"})
    _case().assertEqual(fake.scan_dotenv_files("Ubuntu", "/workspace", 1), [])

    _case().assertTrue(all(r.source_id != "Ubuntu" for r in rows))


def test_collect_wsl_helpers_return_empty_when_wsl_unavailable():
    class _FakeWsl:
        def available(self) -> bool:
            return False

        def list_distros(self) -> List[str]:
            return []

        def read_file(self, distro: str, path: str) -> str:
            return ""

        def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> List[str]:
            return getattr(self, "_dotenv_paths", [])

    fake = _FakeWsl()
    _case().assertEqual(fake.list_distros(), [])
    _case().assertEqual(fake.read_file("Ubuntu", "~/.bashrc"), "")
    _case().assertEqual(fake.scan_dotenv_files("Ubuntu", "/workspace", 2), [])
    _case().assertEqual(providers.collect_wsl_records(fake), [])
    _case().assertEqual(
        providers.collect_wsl_dotenv_records(fake, "Ubuntu", "/workspace", 2),
        [],
    )


def test_collect_wsl_dotenv_records_builds_records_from_scanned_env_files():
    class _FakeWsl:
        def available(self) -> bool:
            return True

        def scan_dotenv_files(self, distro: str, root_path: str, max_depth: int) -> List[str]:
            return ["/workspace/.env"]

        def read_file(self, distro: str, path: str) -> str:
            return "A=1\n"

        def list_distros(self) -> List[str]:
            return ["Ubuntu"]

    fake = _FakeWsl()
    _case().assertEqual(fake.list_distros(), ["Ubuntu"])
    rows = providers.collect_wsl_dotenv_records(fake, "Ubuntu", "/workspace", 2)

    case = _case()
    case.assertEqual(len(rows), 1)
    case.assertEqual(rows[0].name, "A")
    case.assertEqual(rows[0].value, "1")

