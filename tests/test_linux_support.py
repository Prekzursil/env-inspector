"""Linux-specific service and provider coverage tests."""

from pathlib import Path
from typing import List

import pytest

from importlib import import_module
from env_inspector_core.models import EnvRecord
from env_inspector_core.providers import collect_dotenv_records, collect_linux_records
from env_inspector_core.service import EnvInspectorService
from tests.assertions import ensure

service_module = import_module('env_inspector_core.service')

_ORIGINAL_PATH_EXISTS = service_module._path_exists
_ORIGINAL_READ_TEXT_IF_EXISTS = service_module._read_text_if_exists
_ORIGINAL_WRITE_TEXT_FILE = EnvInspectorService._write_text_file
_ORIGINAL_WHICH = service_module.which
_ORIGINAL_RUN = service_module.run
_ORIGINAL_PATH_HOME = service_module.Path.home


@pytest.fixture(autouse=True)
def _reset_service_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore patched service globals between tests."""
    monkeypatch.setattr(service_module, "_path_exists", _ORIGINAL_PATH_EXISTS)
    monkeypatch.setattr(
        service_module, "_read_text_if_exists", _ORIGINAL_READ_TEXT_IF_EXISTS
    )
    monkeypatch.setattr(
        EnvInspectorService,
        "_write_text_file",
        staticmethod(_ORIGINAL_WRITE_TEXT_FILE),
    )
    monkeypatch.setattr(service_module, "which", _ORIGINAL_WHICH)
    monkeypatch.setattr(service_module, "run", _ORIGINAL_RUN)
    monkeypatch.setattr(service_module.Path, "home", _ORIGINAL_PATH_HOME)


def _record(
    source_type: str,
    context: str,
    name: str,
    value: str,
    precedence: int,
) -> EnvRecord:
    """Build a minimal environment record for service list tests."""
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


def _patch_linux_etc_environment_reads(
    monkeypatch: pytest.MonkeyPatch, etc_env: Path
) -> Path:
    """Redirect `/etc/environment` reads to a temporary fixture file."""
    real_exists = service_module._path_exists
    real_read_text = service_module._read_text_if_exists
    target = Path("/etc/environment")

    def fake_read_text(path: Path) -> str:
        """Read the fixture file when the service targets `/etc/environment`."""
        if path == target:
            return etc_env.read_text(encoding="utf-8")
        return real_read_text(path)

    def fake_exists(path: Path) -> bool:
        """Pretend the redirected target exists for fixture-backed reads."""
        if path == target:
            return True
        return real_exists(path)

    monkeypatch.setattr(service_module, "_path_exists", fake_exists)
    monkeypatch.setattr(service_module, "_read_text_if_exists", fake_read_text)
    return target


def _patch_linux_etc_environment_denied(
    monkeypatch: pytest.MonkeyPatch, etc_env: Path
) -> List[str]:
    """Force direct `/etc/environment` writes to raise `PermissionError`."""
    target = _patch_linux_etc_environment_reads(monkeypatch, etc_env)
    real_write_text_file = EnvInspectorService._write_text_file
    writes: List[str] = []

    def fake_write_text_file(path: Path, text: str, *, ensure_parent: bool) -> None:
        """Raise on direct target writes while allowing ordinary fixture writes."""
        if path == target:
            raise PermissionError("denied")
        writes.append(str(path))
        real_write_text_file(path, text, ensure_parent=ensure_parent)

    monkeypatch.setattr(
        EnvInspectorService,
        "_write_text_file",
        staticmethod(fake_write_text_file),
    )
    return writes


def test_collect_linux_records_reads_bashrc_and_etc_environment(tmp_path: Path) -> None:
    """Linux provider collection should include bashrc and `/etc/environment` rows."""
    bashrc = tmp_path / ".bashrc"
    etc_env = tmp_path / "etc_environment"
    bashrc.write_text(
        "export APP_MODE='fixture-mode'\nexport PATH='/usr/bin'\n",
        encoding="utf-8",
    )
    etc_env.write_text("LANG=en_US.UTF-8\nEDITOR=vim\n", encoding="utf-8")

    rows = collect_linux_records(
        bashrc_path=bashrc,
        etc_environment_path=etc_env,
        context="linux",
    )

    source_types = {r.source_type for r in rows}
    ensure("linux_bashrc" in source_types)
    ensure("linux_etc_environment" in source_types)
    ensure(all(r.context == "linux" for r in rows))
    ensure(any(r.name == "APP_MODE" and r.value == "fixture-mode" for r in rows))
    ensure(any(r.name == "LANG" and r.value == "en_US.UTF-8" for r in rows))


def test_collect_dotenv_records_respects_runtime_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dotenv collection should preserve the runtime context on emitted rows."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("APP_MODE=fixture-mode\n", encoding="utf-8")

    rows = collect_dotenv_records(tmp_path, max_depth=2, context="linux")
    ensure(rows)
    ensure(all(r.context == "linux" for r in rows))


def test_service_available_targets_always_include_linux_targets_for_linux_context(
    tmp_path: Path,
) -> None:
    """Linux context target lists should always expose Linux file targets."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    targets = svc.available_targets([], context="linux")

    ensure("linux:bashrc" in targets)
    ensure("linux:etc_environment" in targets)


def test_service_list_contexts_hides_current_wsl_bridge_distro(
    tmp_path: Path,
) -> None:
    """Linux context lists should omit the active WSL bridge distro."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"
    svc.current_wsl_distro = "Ubuntu"

    class _FakeWsl:
        """Expose WSL state with a current distro and one additional distro."""

        @staticmethod
        def available() -> bool:
            """Report that WSL is available."""
            return True

        @staticmethod
        def list_distros_for_ui() -> List[str]:
            """Return distros for the UI context list."""
            return ["Ubuntu", "Debian"]

    svc.wsl = _FakeWsl()  # type: ignore[assignment]

    contexts = svc.list_contexts()

    ensure(contexts == ["linux", "wsl:Debian"])


def test_service_list_contexts_without_wsl_returns_current_context_only(
    tmp_path: Path,
) -> None:
    """Listing contexts without WSL should return only the runtime context."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    class _NoWsl:
        """WSL stub that reports the bridge as unavailable."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is unavailable."""
            return False

    svc.wsl = _NoWsl()  # type: ignore[assignment]

    ensure(svc.list_contexts() == ["linux"])


def test_service_list_contexts_keeps_all_distros_without_active_linux_bridge(
    tmp_path: Path,
) -> None:
    """Non-Linux hosts should keep all WSL bridge distros visible."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "windows"
    svc.current_wsl_distro = "Ubuntu"

    class _FakeWsl:
        """WSL stub that exposes two bridge distros."""

        @staticmethod
        def available() -> bool:
            """Return that WSL is available."""
            return True

        @staticmethod
        def list_distros_for_ui() -> List[str]:
            """Return bridge distros for the context picker."""
            return ["Ubuntu", "Debian"]

    svc.wsl = _FakeWsl()  # type: ignore[assignment]

    ensure(svc.list_contexts() == ["windows", "wsl:Ubuntu", "wsl:Debian"])


def test_service_list_records_collects_linux_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Listing records on Linux should include collected Linux-backed sources."""
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    class _NoBridge:
        """WSL bridge stub that reports itself as unavailable."""

        @staticmethod
        def available() -> bool:
            """Report that no WSL bridge is present."""
            return False

    svc.wsl = _NoBridge()  # type: ignore[assignment]

    linux_rows = [
        _record("linux_bashrc", "linux", "MY_KEY", "from-bashrc", 20),
        _record("linux_etc_environment", "linux", "LANG", "en_US.UTF-8", 30),
    ]
    monkeypatch.setattr(
        service_module, "collect_linux_records", lambda **_kwargs: linux_rows
    )
    monkeypatch.setattr(
        service_module, "collect_process_records", lambda context="linux": []
    )
    monkeypatch.setattr(
        service_module, "collect_dotenv_records", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        service_module,
        "collect_powershell_profile_records",
        lambda *_args, **_kwargs: [],
    )

    rows = svc.list_records(root=tmp_path, context="linux", include_raw_secrets=True)

    ensure(any(r["source_type"] == "linux_bashrc" for r in rows))
    ensure(any(r["source_type"] == "linux_etc_environment" for r in rows))


def test_linux_etc_environment_write_uses_sudo_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission-denied `/etc/environment` writes should fall back to sudo."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    etc_env = tmp_path / "etc_environment"
    etc_env.write_text("A=1\n", encoding="utf-8")

    writes = _patch_linux_etc_environment_denied(monkeypatch, etc_env)

    class Proc:
        """Successful subprocess result stub."""

        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        """Simulate a successful `sudo tee` write."""
        ensure(cmd[:3] == ["/usr/bin/sudo", "-n", "tee"])
        ensure(kwargs.get("input") == "A=2\n")
        ensure(kwargs.get("text") is True)
        etc_env.write_text("A=2\n", encoding="utf-8")
        return Proc()

    monkeypatch.setattr(service_module, "which", lambda _name: "/usr/bin/sudo")
    monkeypatch.setattr(service_module, "run", fake_run)

    result = svc.set_key(key="A", value="2", targets=["linux:etc_environment"])

    ensure(result["success"] is True)
    ensure(etc_env.read_text(encoding="utf-8") == "A=2\n")
    ensure(str(Path("/etc/environment")) not in writes)


def test_linux_etc_environment_write_uses_sudo_fallback_on_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing-host direct writes should still fall back to sudo successfully."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    etc_env = tmp_path / "etc_environment"
    etc_env.write_text("A=1\n", encoding="utf-8")

    target = _patch_linux_etc_environment_reads(monkeypatch, etc_env)

    def fake_write_text_file(path: Path, text: str, *, ensure_parent: bool) -> None:
        """Raise `FileNotFoundError` for the redirected target write."""
        ensure(path == target)
        ensure(text == "A=2\n")
        ensure(ensure_parent is False)
        raise FileNotFoundError("no /etc/environment on host")

    class Proc:
        """Successful subprocess result stub."""

        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        """Simulate a successful `sudo tee` write."""
        ensure(cmd[:3] == ["/usr/bin/sudo", "-n", "tee"])
        ensure(kwargs.get("input") == "A=2\n")
        ensure(kwargs.get("text") is True)
        etc_env.write_text("A=2\n", encoding="utf-8")
        return Proc()

    monkeypatch.setattr(svc, "_write_text_file", fake_write_text_file)
    monkeypatch.setattr(service_module, "which", lambda _name: "/usr/bin/sudo")
    monkeypatch.setattr(service_module, "run", fake_run)

    result = svc.set_key(key="A", value="2", targets=["linux:etc_environment"])

    ensure(result["success"] is True)
    ensure(etc_env.read_text(encoding="utf-8") == "A=2\n")


def test_linux_etc_environment_write_reports_oserror_with_failing_sudo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service should surface sudo failure after a direct write OSError."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    etc_env = tmp_path / "etc_environment"
    etc_env.write_text("A=1\n", encoding="utf-8")

    target = _patch_linux_etc_environment_reads(monkeypatch, etc_env)

    def fake_write_text_file(path: Path, _text: str, *, ensure_parent: bool) -> None:
        """Raise an OSError for the redirected target write."""
        ensure(path == target)
        ensure(ensure_parent is False)
        raise OSError("direct write unavailable")

    class Proc:
        """Failing subprocess result stub."""

        returncode = 1
        stdout = ""
        stderr = "sudo auth failed"

    monkeypatch.setattr(svc, "_write_text_file", fake_write_text_file)
    monkeypatch.setattr(service_module, "which", lambda _name: "/usr/bin/sudo")
    monkeypatch.setattr(service_module, "run", lambda *_args, **_kwargs: Proc())

    result = svc.set_key(key="A", value="2", targets=["linux:etc_environment"])

    ensure(result["success"] is False)
    ensure("sudo" in (result["error_message"] or "").lower())
    ensure(etc_env.read_text(encoding="utf-8") == "A=1\n")


def test_linux_bashrc_set_and_remove_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setting and removing a Linux bashrc key should round-trip cleanly."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export A='1'\n", encoding="utf-8")

    monkeypatch.setattr(service_module.Path, "home", lambda: tmp_path)

    set_result = svc.set_key(key="MY_TEST_VAR", value="hello", targets=["linux:bashrc"])
    ensure(set_result["success"] is True)
    ensure("MY_TEST_VAR" in bashrc.read_text(encoding="utf-8"))
    ensure(set_result["backup_path"])

    remove_result = svc.remove_key(key="MY_TEST_VAR", targets=["linux:bashrc"])
    ensure(remove_result["success"] is True)
    ensure("MY_TEST_VAR" not in bashrc.read_text(encoding="utf-8"))


def test_linux_etc_environment_write_reports_permission_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission failures should report the sudo fallback error cleanly."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"

    etc_env = tmp_path / "etc_environment"
    etc_env.write_text("A=1\n", encoding="utf-8")

    _patch_linux_etc_environment_denied(monkeypatch, etc_env)

    class Proc:
        """Failing subprocess result stub with byte output payloads."""

        returncode = 1
        stdout = b""
        stderr = b"sudo auth failed"

    monkeypatch.setattr(service_module, "which", lambda _name: "sudo")
    monkeypatch.setattr(service_module, "run", lambda *_args, **_kwargs: Proc())

    result = svc.set_key(key="A", value="2", targets=["linux:etc_environment"])

    ensure(result["success"] is False)
    ensure("sudo" in (result["error_message"] or "").lower())
    ensure(etc_env.read_text(encoding="utf-8") == "A=1\n")
