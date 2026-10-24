"""wsl.exe discovery trusts the Windows API for System32, never %SystemRoot%."""

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from env_inspector_core import providers_wsl
from env_inspector_core.providers_wsl import WslProvider, _windows_system_directory
from tests.assertions import ensure


def _fake_windll(text: str, returned_length: int) -> SimpleNamespace:
    """A stand-in for ctypes.windll whose GetSystemDirectoryW fills the buffer."""

    def get_system_directory(buffer: Any, _size: int) -> int:
        buffer.value = text
        return returned_length

    return SimpleNamespace(
        kernel32=SimpleNamespace(GetSystemDirectoryW=get_system_directory)
    )


def test_system_directory_is_none_without_windll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off Windows (no ctypes.windll) there is no system directory to report."""
    monkeypatch.delattr(ctypes, "windll", raising=False)
    ensure(_windows_system_directory() is None)


def test_system_directory_comes_from_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API's answer is used as-is."""
    system32 = "C:\\Windows\\System32"
    monkeypatch.setattr(
        ctypes, "windll", _fake_windll(system32, len(system32)), raising=False
    )
    ensure(_windows_system_directory() == Path(system32))


@pytest.mark.parametrize("returned_length", [0, providers_wsl._MAX_PATH])
def test_system_directory_is_none_when_the_call_fails_or_truncates(
    monkeypatch: pytest.MonkeyPatch, returned_length: int
) -> None:
    """0 means failure; a length >= the buffer size means the path did not fit."""
    monkeypatch.setattr(
        ctypes, "windll", _fake_windll("ignored", returned_length), raising=False
    )
    ensure(_windows_system_directory() is None)


def test_discover_uses_wsl_exe_from_the_system_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A wsl.exe in the API-reported System32 wins over PATH lookups."""
    wsl = tmp_path / "wsl.exe"
    wsl.write_bytes(b"")
    monkeypatch.setattr(providers_wsl, "_windows_system_directory", lambda: tmp_path)
    monkeypatch.setattr(providers_wsl.shutil, "which", lambda _name: None)
    ensure(WslProvider._discover_wsl_exe() == str(wsl))


def test_discover_ignores_the_systemroot_environment_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A wsl.exe planted under a doctored %SystemRoot% is never selected."""
    planted = tmp_path / "System32" / "wsl.exe"
    planted.parent.mkdir()
    planted.write_bytes(b"")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setattr(providers_wsl, "_windows_system_directory", lambda: None)
    monkeypatch.setattr(providers_wsl.shutil, "which", lambda _name: None)
    # Only the planted file "exists", so a candidate built from %SystemRoot%
    # would be found. The patch is scoped so pytest's own cleanup is untouched.
    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", lambda self: self == planted)
        result = WslProvider._discover_wsl_exe()
    ensure(result is None)
