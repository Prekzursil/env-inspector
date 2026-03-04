from pathlib import Path

from env_inspector_core.service import EnvInspectorService


def test_preview_set_does_not_mutate_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    previews = svc.preview_set(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    if not (previews[0]["success"] is True):
        raise AssertionError()


    text_after_preview = env_file.read_text(encoding="utf-8")
    if not (text_after_preview == "A=1\n"):
        raise AssertionError()


    result = svc.set_key(key="API_TOKEN", value="x", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    if not (result["success"] is True):
        raise AssertionError()


    text_after_apply = env_file.read_text(encoding="utf-8")
    if not ("API_TOKEN=x" in text_after_apply):
        raise AssertionError()



def test_set_does_not_write_when_backup_fails(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")

    def fail_backup(*_args, **_kwargs):
        raise RuntimeError("backup write failed")

    monkeypatch.setattr(svc.backup_mgr, "backup_text", fail_backup)

    result = svc.set_key(key="A", value="2", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    if not (result["success"] is False):
        raise AssertionError()

    if not ("backup write failed" in result["error_message"]):
        raise AssertionError()

    if not (env_file.read_text(encoding="utf-8") == "A=1\n"):
        raise AssertionError()



def test_audit_log_redacts_secret_diff(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=old\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    result = svc.set_key(key="API_TOKEN", value="supersecretvalue", targets=[f"dotenv:{env_file}"], scope_roots=[tmp_path])
    if not (result["success"] is True):
        raise AssertionError()


    log_text = (tmp_path / "state" / "audit.log").read_text(encoding="utf-8")
    if not ("[secret diff masked]" in log_text):
        raise AssertionError()

    if not ("supersecretvalue" not in log_text):
        raise AssertionError()



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

    if not (result["success"] is False):
        raise AssertionError()

    if not ("outside approved roots" in (result["error_message"] or "")):
        raise AssertionError()

    if not (env_file.read_text(encoding="utf-8") == "A=1\n"):
        raise AssertionError()

