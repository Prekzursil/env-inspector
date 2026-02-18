from pathlib import Path

from env_inspector_core.service import EnvInspectorService


def test_preview_set_does_not_mutate_file(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    previews = svc.preview_set(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"])
    assert previews[0]["success"] is True

    text_after_preview = env_file.read_text(encoding="utf-8")
    assert text_after_preview == "A=1\n"

    result = svc.set_key(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"])
    assert result["success"] is True

    text_after_apply = env_file.read_text(encoding="utf-8")
    assert "API_TOKEN=x" in text_after_apply


def test_set_does_not_write_when_backup_fails(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    def fail_backup(*_args, **_kwargs):
        raise RuntimeError("backup write failed")

    monkeypatch.setattr(svc.backup_mgr, "backup_text", fail_backup)

    result = svc.set_key(key="A", value="2", targets=[f"dotenv:{env_file}"])
    assert result["success"] is False
    assert "backup write failed" in result["error_message"]
    assert env_file.read_text(encoding="utf-8") == "A=1\n"


def test_audit_log_redacts_secret_diff(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=old\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(key="API_TOKEN", value="supersecretvalue", targets=[f"dotenv:{env_file}"])
    assert result["success"] is True

    log_text = (tmp_path / "state" / "audit.log").read_text(encoding="utf-8")
    assert "[secret diff masked]" in log_text
    assert "supersecretvalue" not in log_text
