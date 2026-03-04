from __future__ import absolute_import, division

from pathlib import Path

from env_inspector_core.service import EnvInspectorService

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



def test_preview_set_does_not_mutate_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    previews = svc.preview_set(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    _expect(previews[0]["success"] is True)


    text_after_preview = env_file.read_text(encoding="utf-8")
    _expect(text_after_preview == "A=1\n")


    result = svc.set_key(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    _expect(result["success"] is True)


    text_after_apply = env_file.read_text(encoding="utf-8")
    _expect("API_TOKEN=x" in text_after_apply)



def test_set_does_not_write_when_backup_fails(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    def fail_backup(*_args, **_kwargs):
        raise RuntimeError("backup write failed")

    monkeypatch.setattr(svc.backup_mgr, "backup_text", fail_backup)

    result = svc.set_key(key="A", value="2", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    _expect(result["success"] is False)

    _expect("backup write failed" in result["error_message"])

    _expect(env_file.read_text(encoding="utf-8") == "A=1\n")



def test_audit_log_redacts_secret_diff(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=old\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(key="API_TOKEN", value="supersecretvalue", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    _expect(result["success"] is True)


    log_text = (tmp_path / "state" / "audit.log").read_text(encoding="utf-8")
    _expect("[secret diff masked]" in log_text)

    _expect("supersecretvalue" not in log_text)



def test_set_rejects_dotenv_target_outside_approved_roots(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_root = tmp_path.parent / f"{tmp_path.name}-outside"
    outside_root.mkdir()
    env_file = outside_root / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(key="A", value="2", targets=[f"dotenv:{env_file}"], scope_roots=[allowed_root])

    _expect(result["success"] is False)

    _expect("outside approved roots" in (result["error_message"] or ""))

    _expect(env_file.read_text(encoding="utf-8") == "A=1\n")
