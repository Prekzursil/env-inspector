"""Branch-coverage tests for provider edge paths and WSL helpers."""

import unittest
from pathlib import Path
from typing import List, cast

import pytest

import env_inspector_core.providers as providers
from env_inspector_core.constants import SOURCE_WSL_BASHRC, SOURCE_WSL_ETC_ENV
from env_inspector_core.path_policy import PathPolicyError


def _case() -> unittest.TestCase:
    """Return a unittest case helper for assertion coverage."""
    return unittest.TestCase()


def _as_wsl_provider(value: object) -> providers.WslProvider:
    """Cast a stub object to the WSL provider interface used by collectors."""
    return cast(providers.WslProvider, value)


def test_is_workspace_scoped_path_checks_exact_and_descendant(
    tmp_path: Path,
) -> None:
    """Workspace scoping should accept the root and descendants only."""
    root = tmp_path.joinpath("workspace")
    root.mkdir()
    nested = root.joinpath("inner", "file.txt")

    case = _case()
    case.assertTrue(providers._is_workspace_scoped_path(root, root))
    case.assertTrue(providers._is_workspace_scoped_path(nested, root))
    case.assertFalse(
        providers._is_workspace_scoped_path(tmp_path.joinpath("other"), root)
    )


def test_discover_dotenv_files_returns_empty_when_root_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Dotenv discovery should swallow root-policy rejections."""

    def _raise(_root: Path) -> Path:
        """Raise the path-policy error used by the discovery guard."""
        raise PathPolicyError("rejected")

    monkeypatch.setattr(providers, "resolve_scan_root", _raise)

    _case().assertEqual(providers.discover_dotenv_files(tmp_path), [])


def test_iter_dotenv_candidates_prunes_dirs_when_depth_exceeds_limit(
    tmp_path: Path,
) -> None:
    """Candidate iteration should prune nested directories beyond the max depth."""
    root = tmp_path.joinpath("workspace")
    nested = root.joinpath("nested")
    nested.mkdir(parents=True)
    nested.joinpath(".env").write_text("A=1\n", encoding="utf-8")

    rows = providers._iter_dotenv_candidates(root, max_depth=0)

    _case().assertEqual(rows, [])


def test_windows_registry_provider_guard_and_invalid_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registry providers should reject non-Windows hosts and bad scopes."""
    monkeypatch.setattr(providers, "is_windows", lambda: False)
    with pytest.raises(RuntimeError):
        providers.WindowsRegistryProvider()

    with pytest.raises(ValueError):
        providers.WindowsRegistryProvider._scope_to_key("unsupported-scope")


def test_wsl_decode_falls_back_on_invalid_utf16_bytes() -> None:
    """WSL decoding should fall back to a permissive string result."""
    raw = b"\x00\x00\x00"

    decoded = providers.WslProvider._decode(raw)

    _case().assertIsInstance(decoded, str)


def test_parse_powershell_assignment_rejects_invalid_shapes() -> None:
    """PowerShell assignment parsing should reject malformed input shapes."""
    case = _case()
    case.assertIsNone(providers._parse_powershell_assignment("$env:PATH"))
    case.assertIsNone(providers._parse_powershell_assignment("$env:1INVALID = 'x'"))
    case.assertIsNone(providers._parse_powershell_assignment("# $env:IGNORED = 'x'"))


def test_normalize_and_validate_powershell_values_and_keys() -> None:
    """PowerShell value normalization and key validation should match expectations."""
    case = _case()
    case.assertEqual(
        providers._normalize_powershell_assignment_value(" 'value'; "),
        "value",
    )
    case.assertEqual(providers._normalize_powershell_assignment_value("plain"), "plain")
    case.assertFalse(providers._is_valid_powershell_env_key(""))
    case.assertFalse(providers._is_valid_powershell_env_key("1BAD"))
    case.assertTrue(providers._is_valid_powershell_env_key("GOOD_1"))


def test_collect_wsl_records_includes_bashrc_and_etc_pairs() -> None:
    """WSL collection should include both bashrc and `/etc/environment` sources."""

    class _FakeWsl:
        """WSL stub that exposes bashrc and etc-environment content."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is available."""
            return True

        @staticmethod
        def list_distros() -> list[str]:
            """Return a single distro for collection."""
            return ["Ubuntu"]

        @staticmethod
        def read_file(_distro: str, path: str) -> str:
            """Return canned WSL file contents for collection tests."""
            mapping = {
                "~/.bashrc": "export API_TOKEN='abc'\n",
                "/etc/environment": "LANG=en_US.UTF-8\n",
            }
            return mapping.get(path, "")

    rows = providers.collect_wsl_records(_as_wsl_provider(_FakeWsl()), include_etc=True)

    case = _case()
    case.assertTrue(
        any(r.source_type == SOURCE_WSL_BASHRC and r.name == "API_TOKEN" for r in rows)
    )
    case.assertTrue(
        any(r.source_type == SOURCE_WSL_ETC_ENV and r.name == "LANG" for r in rows)
    )


def test_collect_wsl_records_respects_excluded_distros() -> None:
    """Excluded WSL distros should not emit any collected rows."""

    class _FakeWsl:
        """WSL stub that exposes two distros for exclusion filtering."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is available."""
            return True

        @staticmethod
        def list_distros() -> list[str]:
            """Return two distros so one can be excluded."""
            return ["Ubuntu", "Debian"]

        @staticmethod
        def read_file(_distro: str, _path: str) -> str:
            """Return an empty payload for all WSL file reads."""
            return ""

    rows = providers.collect_wsl_records(
        _as_wsl_provider(_FakeWsl()),
        include_etc=False,
        exclude_distros={"ubuntu"},
    )

    _case().assertTrue(all(r.source_id != "Ubuntu" for r in rows))


def test_collect_wsl_helpers_return_empty_when_wsl_unavailable() -> None:
    """WSL helper collectors should short-circuit when WSL is unavailable."""

    class _FakeWsl:
        """WSL stub that reports itself as unavailable."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is unavailable."""
            return False

    _case().assertEqual(providers.collect_wsl_records(_as_wsl_provider(_FakeWsl())), [])
    _case().assertEqual(
        providers.collect_wsl_dotenv_records(
            _as_wsl_provider(_FakeWsl()),
            "Ubuntu",
            "/workspace",
            2,
        ),
        [],
    )


def test_collect_wsl_dotenv_records_builds_records_from_scanned_env_files() -> None:
    """WSL dotenv scanning should build records from discovered env files."""

    class _FakeWsl:
        """WSL stub that returns one dotenv file with one key."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is available."""
            return True

        @staticmethod
        def scan_dotenv_files(
            _distro: str,
            _root_path: str,
            _max_depth: int,
        ) -> list[str]:
            """Return the dotenv files that should be scanned."""
            return ["/workspace/.env"]

        @staticmethod
        def read_file(_distro: str, _path: str) -> str:
            """Return the dotenv file content for collection tests."""
            return "A=1\n"

    rows = providers.collect_wsl_dotenv_records(
        _as_wsl_provider(_FakeWsl()),
        "Ubuntu",
        "/workspace",
        2,
    )

    case = _case()
    case.assertEqual(len(rows), 1)
    case.assertEqual(rows[0].name, "A")
    case.assertEqual(rows[0].value, "1")
