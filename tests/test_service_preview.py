"""Test service preview module."""

from pathlib import Path

import pytest

import env_inspector_core.service as service_module
from env_inspector_core.service import EnvInspectorService
from tests.assertions import ensure

_ORIGINAL_PATH_EXISTS = service_module._path_exists
_ORIGINAL_READ_TEXT_IF_EXISTS = service_module._read_text_if_exists
_ORIGINAL_WRITE_TEXT_FILE = EnvInspectorService._write_text_file
_ORIGINAL_WHICH = service_module.which
_ORIGINAL_RUN = service_module.run
_ORIGINAL_PATH_HOME = service_module.Path.home


@pytest.fixture(autouse=True)
def _reset_service_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset service globals."""
    monkeypatch.setattr(service_module, "_path_exists", _ORIGINAL_PATH_EXISTS)
    monkeypatch.setattr(
        service_module, "_read_text_if_exists", _ORIGINAL_READ_TEXT_IF_EXISTS
    )
    monkeypatch.setattr(
        EnvInspectorService, "_write_text_file", staticmethod(_ORIGINAL_WRITE_TEXT_FILE)
    )
    monkeypatch.setattr(service_module, "which", _ORIGINAL_WHICH)
    monkeypatch.setattr(service_module, "run", _ORIGINAL_RUN)
    monkeypatch.setattr(service_module.Path, "home", _ORIGINAL_PATH_HOME)


def test_preview_set_does_not_mutate_file(tmp_path: Path, monkeypatch):
    """Test preview set does not mutate file."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    previews = svc.preview_set(
        key="API_TOKEN",
        value="x",
        targets=[f"dotenv:{env_file}"],
        scope_roots=[tmp_path],
    )
    ensure(previews[0]["success"] is True)

    text_after_preview = env_file.read_text(encoding="utf-8")
    ensure(text_after_preview == "A=1\n")

    result = svc.set_key(
        key="API_TOKEN",
        value="x",
        targets=[f"dotenv:{env_file}"],
        scope_roots=[tmp_path],
    )
    ensure(result["success"] is True)

    text_after_apply = env_file.read_text(encoding="utf-8")
    ensure("API_TOKEN=x" in text_after_apply)


def test_set_does_not_write_when_backup_fails(tmp_path: Path, monkeypatch):
    """Test set does not write when backup fails."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    def fail_backup(*_args, **_kwargs):
        """Fail backup."""
        raise RuntimeError("backup write failed")

    monkeypatch.setattr(svc.backup_mgr, "backup_text", fail_backup)

    result = svc.set_key(
        key="A", value="2", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path]
    )
    ensure(result["success"] is False)
    ensure("backup write failed" in result["error_message"])
    ensure(env_file.read_text(encoding="utf-8") == "A=1\n")


def test_audit_log_redacts_secret_diff(tmp_path: Path, monkeypatch):
    """Test audit log redacts secret diff."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=old\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(
        key="API_TOKEN",
        value="supersecretvalue",
        targets=[f"dotenv:{env_file}"],
        scope_roots=[tmp_path],
    )
    ensure(result["success"] is True)

    log_text = (tmp_path / "state" / "audit.log").read_text(encoding="utf-8")
    ensure("[secret diff masked]" in log_text)
    ensure("supersecretvalue" not in log_text)


def test_set_rejects_dotenv_target_outside_approved_roots(tmp_path: Path, monkeypatch):
    """Test set rejects dotenv target outside approved roots."""
    monkeypatch.chdir(tmp_path)
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_root = tmp_path.parent / f"{tmp_path.name}-outside"
    outside_root.mkdir()
    env_file = outside_root / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(
        key="A", value="2", targets=[f"dotenv:{env_file}"], scope_roots=[allowed_root]
    )

    ensure(result["success"] is False)
    ensure("outside approved roots" in (result["error_message"] or ""))
    ensure(env_file.read_text(encoding="utf-8") == "A=1\n")
