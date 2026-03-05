from __future__ import absolute_import, division
from subprocess import CompletedProcess  # nosec B404
from pathlib import Path

import pytest

from env_inspector_core.providers import WslProvider

from tests.assertions import ensure

def _proc(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> CompletedProcess:
    return CompletedProcess(args=["wsl"], returncode=returncode, stdout=stdout, stderr=stderr)

def test_write_file_with_privilege_root_success():
    calls: list[list[str]] = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return _proc(0)

    provider = WslProvider(runner=runner)
    provider.available = lambda: True  # type: ignore[assignment]
    provider.wsl_exe = "wsl.exe"

    provider.write_file_with_privilege("Ubuntu", "/etc/my env", "A=1\n")

    ensure(any("-u" in c and "root" in c for c in calls))
    ensure("cat > '/etc/my env'" in calls[0][-1])
    ensure(len(calls) == 1)

def test_write_file_with_privilege_falls_back_to_sudo():
    calls: list[list[str]] = []
    inputs: list[bytes | None] = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        inputs.append(kwargs.get("input"))
        if "-u" in cmd and "root" in cmd:
            return _proc(1, stderr=b"root failed")
        return _proc(0)

    provider = WslProvider(runner=runner)
    provider.available = lambda: True  # type: ignore[assignment]
    provider.wsl_exe = "wsl.exe"

    provider.write_file_with_privilege("Ubuntu", "/etc/environment", "A=1\n")

    ensure(len(calls) == 2)
    ensure("sudo tee /etc/environment >/dev/null" in calls[1][-1])
    ensure(inputs[1] == b"A=1\n")

def test_write_file_with_privilege_raises_when_root_and_sudo_fail():
    def runner(cmd, **kwargs):
        return _proc(1, stderr=b"fail")

    provider = WslProvider(runner=runner)
    provider.available = lambda: True  # type: ignore[assignment]
    provider.wsl_exe = "wsl.exe"

    with pytest.raises(RuntimeError) as exc:
        provider.write_file_with_privilege("Ubuntu", "/etc/environment", "A=1\n")

    ensure("root and sudo fallback" in str(exc.value))

def test_available_probes_command_and_returns_false_when_probe_fails(tmp_path: Path):
    calls: list[list[str]] = []
    fake_wsl = tmp_path / "wsl.exe"
    fake_wsl.write_text("", encoding="utf-8")

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return _proc(1, stderr=b"not working")

    provider = WslProvider(runner=runner)
    provider.wsl_exe = str(fake_wsl)
    provider._available_cache = None

    ensure(provider.available() is False)
    ensure(calls)
    ensure(calls[0][-2:] == ["-l", "-q"])
