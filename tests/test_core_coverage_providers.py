"""Coverage tests for providers.py — Windows registry, Linux paths, and edge cases."""

from __future__ import absolute_import, division
from tests.assertions import ensure

import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import env_inspector_core.providers as providers
from env_inspector_core.constants import (
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_WINDOWS_MACHINE,
    SOURCE_WINDOWS_USER,
)


def _case() -> unittest.TestCase:
    """Handle  case."""
    return unittest.TestCase()


# ---------------------------------------------------------------------------
# _require_winreg (lines 70-72)
# ---------------------------------------------------------------------------

def test_require_winreg_raises_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """_require_winreg raises RuntimeError when winreg is None."""
    monkeypatch.setattr(providers, "_winreg", None)
    with pytest.raises(RuntimeError, match="Windows registry provider only available on Windows"):
        providers._require_winreg()


def test_require_winreg_returns_module_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """_require_winreg returns the module when it is not None."""
    fake = types.SimpleNamespace()
    monkeypatch.setattr(providers, "_winreg", fake)
    ensure(providers._require_winreg() is fake)


# ---------------------------------------------------------------------------
# WindowsRegistryProvider.__init__ (line 161->exit)
# Already tested for non-Windows, but we need the Windows+winreg path.
# ---------------------------------------------------------------------------

def test_windows_registry_provider_init_succeeds_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """WindowsRegistryProvider init succeeds when is_windows() and _winreg are both truthy."""
    monkeypatch.setattr(providers, "is_windows", lambda: True)
    fake_winreg = types.SimpleNamespace()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    provider = providers.WindowsRegistryProvider()
    ensure(isinstance(provider, providers.WindowsRegistryProvider))


# ---------------------------------------------------------------------------
# WindowsRegistryProvider._scope_details (lines 169-181)
# ---------------------------------------------------------------------------

def _make_fake_winreg() -> types.SimpleNamespace:
    """Build a fake winreg module with all needed attributes."""
    return types.SimpleNamespace(
        HKEY_CURRENT_USER="HKCU",
        HKEY_LOCAL_MACHINE="HKLM",
        KEY_READ=0x20019,
        KEY_SET_VALUE=0x0002,
        KEY_WOW64_64KEY=0x0100,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        OpenKey=MagicMock(),
        EnumValue=MagicMock(),
        QueryInfoKey=MagicMock(),
        SetValueEx=MagicMock(),
        DeleteValue=MagicMock(),
    )


def test_scope_details_user_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """_scope_details returns correct root/path/access for User scope."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)

    root, path, access = providers.WindowsRegistryProvider._scope_details("User", fake_winreg.KEY_READ)
    ensure(root == "HKCU")
    ensure(path == r"Environment")
    ensure(access == fake_winreg.KEY_READ)


def test_scope_details_machine_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """_scope_details returns correct root/path/access for Machine scope including WOW64."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)

    root, path, access = providers.WindowsRegistryProvider._scope_details("Machine", fake_winreg.KEY_READ)
    ensure(root == "HKLM")
    ensure("Session Manager" in path)
    ensure(access == (fake_winreg.KEY_READ | fake_winreg.KEY_WOW64_64KEY))


def test_scope_details_invalid_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """_scope_details raises ValueError for an unsupported scope."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)

    with pytest.raises(ValueError, match="Unsupported scope"):
        providers.WindowsRegistryProvider._scope_details("BadScope", 0)


# ---------------------------------------------------------------------------
# WindowsRegistryProvider._scope_to_key (line 186)
# ---------------------------------------------------------------------------

def test_scope_to_key_returns_root_and_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """_scope_to_key returns (root, path) for a valid scope."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)

    root, path = providers.WindowsRegistryProvider._scope_to_key("User")
    assert root == "HKCU"
    assert path == r"Environment"


# ---------------------------------------------------------------------------
# WindowsRegistryProvider.list_scope (lines 189-197)
# ---------------------------------------------------------------------------

def test_list_scope_returns_registry_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """list_scope reads values from the fake registry."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    # Set up the mock to simulate a registry key with 2 values
    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)
    fake_winreg.QueryInfoKey = MagicMock(return_value=(0, 2, 0))
    fake_winreg.EnumValue = MagicMock(side_effect=[
        ("PATH", "C:\\Windows", 1),
        ("HOME", "C:\\Users\\test", 1),
    ])

    provider = providers.WindowsRegistryProvider()
    result = provider.list_scope("User")
    ensure(result == {"PATH": "C:\\Windows", "HOME": "C:\\Users\\test"})


# ---------------------------------------------------------------------------
# WindowsRegistryProvider.set_scope_value (lines 200-204)
# ---------------------------------------------------------------------------

def test_set_scope_value_reg_sz(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_scope_value uses REG_SZ for values without %."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)

    provider = providers.WindowsRegistryProvider()
    provider.set_scope_value("User", "MY_KEY", "my_value")
    fake_winreg.SetValueEx.assert_called_once_with(mock_key, "MY_KEY", 0, fake_winreg.REG_SZ, "my_value")


def test_set_scope_value_reg_expand_sz(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_scope_value uses REG_EXPAND_SZ for values containing %."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)

    provider = providers.WindowsRegistryProvider()
    provider.set_scope_value("User", "PATH", "%SystemRoot%\\bin")
    fake_winreg.SetValueEx.assert_called_once_with(mock_key, "PATH", 0, fake_winreg.REG_EXPAND_SZ, "%SystemRoot%\\bin")


# ---------------------------------------------------------------------------
# WindowsRegistryProvider.remove_scope_value (lines 207-211)
# ---------------------------------------------------------------------------

def test_remove_scope_value_deletes_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """remove_scope_value calls DeleteValue on the registry key."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)

    provider = providers.WindowsRegistryProvider()
    provider.remove_scope_value("User", "MY_KEY")
    fake_winreg.DeleteValue.assert_called_once_with(mock_key, "MY_KEY")


def test_remove_scope_value_suppresses_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """remove_scope_value suppresses FileNotFoundError."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)
    fake_winreg.DeleteValue = MagicMock(side_effect=FileNotFoundError("not found"))

    provider = providers.WindowsRegistryProvider()
    # Should not raise
    provider.remove_scope_value("User", "NONEXISTENT")


# ---------------------------------------------------------------------------
# build_registry_records (lines 215-252)
# ---------------------------------------------------------------------------

def test_build_registry_records_creates_records(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_registry_records creates EnvRecord entries from both User and Machine scopes."""
    fake_winreg = _make_fake_winreg()
    monkeypatch.setattr(providers, "_winreg", fake_winreg)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    # Make the provider init succeed
    mock_key = MagicMock()
    fake_winreg.OpenKey = MagicMock(return_value=mock_key)
    mock_key.__enter__ = MagicMock(return_value=mock_key)
    mock_key.__exit__ = MagicMock(return_value=False)
    fake_winreg.QueryInfoKey = MagicMock(return_value=(0, 1, 0))
    fake_winreg.EnumValue = MagicMock(return_value=("MY_VAR", "val", 1))

    provider = providers.WindowsRegistryProvider()
    records = providers.build_registry_records(provider)

    case = _case()
    # Should have records from both User and Machine scopes
    user_records = [r for r in records if r.source_type == SOURCE_WINDOWS_USER]
    machine_records = [r for r in records if r.source_type == SOURCE_WINDOWS_MACHINE]
    case.assertTrue(len(user_records) >= 1)
    case.assertTrue(len(machine_records) >= 1)
    case.assertFalse(user_records[0].requires_privilege)
    case.assertTrue(machine_records[0].requires_privilege)


# ---------------------------------------------------------------------------
# collect_dotenv_records UnicodeDecodeError branch (lines 295-296)
# ---------------------------------------------------------------------------

def test_collect_dotenv_records_falls_back_to_latin1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """collect_dotenv_records falls back to latin-1 when UTF-8 decoding fails."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    # Write bytes that are valid latin-1 but invalid UTF-8
    env_file.write_bytes(b"KEY=caf\xe9\n")

    monkeypatch.setattr(providers, "resolve_scan_root", Path)

    records = providers.collect_dotenv_records(tmp_path, max_depth=0)
    case = _case()
    case.assertEqual(len(records), 1)
    case.assertEqual(records[0].name, "KEY")
    case.assertIn("caf", records[0].value)


# ---------------------------------------------------------------------------
# collect_powershell_profile_records (lines 319-343)
# ---------------------------------------------------------------------------

def test_collect_powershell_profile_records_reads_profiles(tmp_path: Path) -> None:
    """collect_powershell_profile_records reads PS profiles and builds records."""
    profile = tmp_path / "profile.ps1"
    profile.write_text("$env:MY_SETTING = 'hello'\n", encoding="utf-8")

    records = providers.collect_powershell_profile_records([profile])
    case = _case()
    case.assertEqual(len(records), 1)
    case.assertEqual(records[0].name, "MY_SETTING")
    case.assertEqual(records[0].value, "hello")
    case.assertEqual(records[0].source_type, SOURCE_POWERSHELL_PROFILE)
    case.assertFalse(records[0].requires_privilege)


def test_collect_powershell_profile_records_requires_privilege_for_program_files(tmp_path: Path) -> None:
    """collect_powershell_profile_records sets requires_privilege for 'program files' paths."""
    program_files = tmp_path / "program files" / "powershell"
    program_files.mkdir(parents=True)
    profile = program_files / "profile.ps1"
    profile.write_text("$env:GLOBAL_SETTING = 'value'\n", encoding="utf-8")

    records = providers.collect_powershell_profile_records([profile])
    case = _case()
    case.assertEqual(len(records), 1)
    case.assertTrue(records[0].requires_privilege)


def test_collect_powershell_profile_records_skips_missing_files(tmp_path: Path) -> None:
    """collect_powershell_profile_records skips paths that don't exist."""
    missing = tmp_path / "nonexistent.ps1"
    records = providers.collect_powershell_profile_records([missing])
    ensure(records == [])


# ---------------------------------------------------------------------------
# collect_linux_records (lines 346-383 — exercises the Linux provider paths)
# ---------------------------------------------------------------------------

def test_collect_linux_records_reads_bashrc_and_etc_environment(tmp_path: Path) -> None:
    """collect_linux_records reads both bashrc and /etc/environment when they exist."""
    bashrc = tmp_path / ".bashrc"
    etc_env = tmp_path / "environment"
    bashrc.write_text("export API_KEY='secret123'\n", encoding="utf-8")
    etc_env.write_text("LANG=en_US.UTF-8\n", encoding="utf-8")

    records = providers.collect_linux_records(
        bashrc_path=bashrc,
        etc_environment_path=etc_env,
    )
    case = _case()
    bashrc_records = [r for r in records if r.source_type == SOURCE_LINUX_BASHRC]
    etc_records = [r for r in records if r.source_type == SOURCE_LINUX_ETC_ENV]
    case.assertTrue(len(bashrc_records) >= 1)
    case.assertTrue(len(etc_records) >= 1)
    case.assertEqual(bashrc_records[0].name, "API_KEY")
    case.assertEqual(etc_records[0].name, "LANG")
    case.assertFalse(bashrc_records[0].requires_privilege)
    case.assertTrue(etc_records[0].requires_privilege)


def test_collect_linux_records_handles_missing_files(tmp_path: Path) -> None:
    """collect_linux_records returns empty when neither file exists."""
    records = providers.collect_linux_records(
        bashrc_path=tmp_path / "missing_bashrc",
        etc_environment_path=tmp_path / "missing_etc",
    )
    assert records == []
