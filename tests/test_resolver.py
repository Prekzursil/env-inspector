from __future__ import absolute_import, division

from env_inspector_core.models import EnvRecord
from env_inspector_core.resolver import resolve_effective_value

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



def rec(source_type: str, context: str, name: str, value: str, precedence: int) -> EnvRecord:
    return EnvRecord(
        source_type=source_type,
        source_id=source_type,
        source_path=source_type,
        context=context,
        name=name,
        value=value,
        is_secret=False,
        is_persistent=True,
        is_mutable=True,
        precedence_rank=precedence,
        writable=True,
        requires_privilege=False,
        last_error=None,
    )


def test_resolve_effective_windows_prefers_lower_precedence_rank():
    rows = [
        rec("windows_machine", "windows", "API_TOKEN", "machine", 30),
        rec("windows_user", "windows", "API_TOKEN", "user", 20),
        rec("powershell_profile", "windows", "API_TOKEN", "profile", 25),
    ]
    chosen = resolve_effective_value(rows, "API_TOKEN", "windows")
    _expect(chosen is not None)

    _expect(chosen.value == "user")



def test_resolve_effective_wsl_context_isolated_by_distro():
    rows = [
        rec("wsl_etc_environment", "wsl:Ubuntu", "API_TOKEN", "ubuntu-etc", 10),
        rec("wsl_bashrc", "wsl:Debian", "API_TOKEN", "debian-bash", 20),
        rec("wsl_bashrc", "wsl:Ubuntu", "API_TOKEN", "ubuntu-bash", 20),
    ]
    chosen = resolve_effective_value(rows, "API_TOKEN", "wsl:Ubuntu")
    _expect(chosen is not None)

    _expect(chosen.value == "ubuntu-etc")



def test_resolve_effective_windows_does_not_leak_linux_context():
    rows = [
        rec("linux_bashrc", "linux", "API_TOKEN", "linux-value", 20),
        rec("windows_user", "windows", "API_TOKEN", "windows-value", 20),
    ]
    chosen = resolve_effective_value(rows, "API_TOKEN", "windows")
    _expect(chosen is not None)

    _expect(chosen.value == "windows-value")



def test_resolve_effective_linux_precedence_prefers_process_then_bashrc():
    rows = [
        rec("linux_etc_environment", "linux", "PATH", "etc", 30),
        rec("linux_bashrc", "linux", "PATH", "bashrc", 20),
        rec("process", "linux", "PATH", "process", 10),
        rec("dotenv", "linux", "PATH", "dotenv", 90),
    ]
    chosen = resolve_effective_value(rows, "PATH", "linux")
    _expect(chosen is not None)

    _expect(chosen.value == "process")
