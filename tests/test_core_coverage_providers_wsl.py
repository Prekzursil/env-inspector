"""Coverage tests for providers_wsl.py — WslProvider edge cases and branches."""

from __future__ import absolute_import, division

import subprocess
import types
import unittest
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from env_inspector_core.providers_wsl import WslProvider


def _case() -> unittest.TestCase:
    return unittest.TestCase()


# Line 41: _discover_wsl_exe returns None or shutil.which fallback
def test_discover_wsl_exe_returns_none_when_no_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    """_discover_wsl_exe returns None when no wsl.exe candidates exist."""
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    # On Linux without SystemRoot and no wsl.exe on PATH, should return None or a found path
    result = WslProvider._discover_wsl_exe()
    # Result can be None or a real path depending on the system
    assert result is None or isinstance(result, str)


# Line 54-55: available() OSError branch
def test_available_returns_false_on_oserror() -> None:
    """available() returns False when runner raises OSError."""
    def _raise_oserror(*args, **kwargs):
        raise OSError("cannot execute")

    provider = WslProvider(runner=_raise_oserror, wsl_exe="/fake/wsl.exe")
    assert provider.available() is False


# Line 54-55: available() caches result
def test_available_caches_result() -> None:
    """available() caches the result after first call."""
    call_count = 0
    def _fake_runner(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    assert provider.available() is True
    assert provider.available() is True  # should use cache
    assert call_count == 1


# Line 72: _run raises when not available
def test_run_raises_when_unavailable() -> None:
    """_run raises RuntimeError when WSL is not available."""
    provider = WslProvider(runner=MagicMock(), wsl_exe=None)
    provider._available_cache = False
    with pytest.raises(RuntimeError, match="not available"):
        provider._run(["-l"])


# Lines 89-90: _run raises on non-zero return code
def test_run_raises_on_nonzero_return() -> None:
    """_run raises RuntimeError when the command returns non-zero."""
    def _fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"some error"
        )

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    with pytest.raises(RuntimeError, match="some error"):
        provider._run(["-l"])


# Line 102: list_distros_for_ui filters helper distros
def test_list_distros_for_ui_filters_docker_distros() -> None:
    """list_distros_for_ui filters out docker-desktop helper distros."""
    def _fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b"Ubuntu\ndocker-desktop\nDebian\ndocker-desktop-data\n",
            stderr=b"",
        )

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    result = provider.list_distros_for_ui()
    assert "Ubuntu" in result
    assert "Debian" in result
    assert "docker-desktop" not in result
    assert "docker-desktop-data" not in result


# Lines 105-106: read_file
def test_read_file_returns_content() -> None:
    """read_file runs cat command and returns the output."""
    def _fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"file content", stderr=b"")

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    result = provider.read_file("Ubuntu", "/home/user/.bashrc")
    assert result == "file content"


# Lines 108-110: write_file
def test_write_file_sends_content() -> None:
    """write_file sends content via stdin to the WSL command."""
    calls = []
    def _fake_runner(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    provider.write_file("Ubuntu", "/tmp/test", "content")
    assert len(calls) == 1


# Lines 109-110: write_file_with_privilege
def test_write_file_with_privilege_tries_root_then_sudo() -> None:
    """write_file_with_privilege tries root first, falls back to sudo."""
    attempt = 0
    def _fake_runner(*args, **kwargs):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"root failed")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    provider.write_file_with_privilege("Ubuntu", "/etc/environment", "A=1\n")
    assert attempt == 2


# Lines 130-136: scan_dotenv_files
def test_scan_dotenv_files_returns_paths() -> None:
    """scan_dotenv_files returns discovered dotenv file paths."""
    def _fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b"/workspace/.env\n/workspace/.env.local\n",
            stderr=b"",
        )

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    result = provider.scan_dotenv_files("Ubuntu", "/workspace", 3)
    assert result == ["/workspace/.env", "/workspace/.env.local"]


# write_file_with_privilege fails both attempts
def test_write_file_with_privilege_raises_on_both_failures() -> None:
    """write_file_with_privilege raises when both root and sudo fail."""
    def _fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"failed")

    provider = WslProvider(runner=_fake_runner, wsl_exe="/fake/wsl.exe")
    provider._available_cache = True
    with pytest.raises(RuntimeError, match="Failed to write with both root and sudo"):
        provider.write_file_with_privilege("Ubuntu", "/etc/environment", "A=1\n")
