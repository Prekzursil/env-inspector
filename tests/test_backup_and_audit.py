import json
from pathlib import Path

from env_inspector_core.storage import BackupManager, AuditLogger
from env_inspector_core.models import OperationResult
from env_inspector_core.service import EnvInspectorService


def test_backup_manager_retention_and_restore(tmp_path: Path):
    mgr = BackupManager(tmp_path, retention=2)
    target = "dotenv:/tmp/.env"

    p1 = mgr.backup_text(target, "A=1\n")
    p2 = mgr.backup_text(target, "A=2\n")
    p3 = mgr.backup_text(target, "A=3\n")

    backups = mgr.list_backups(target)
    assert len(backups) == 2
    assert p3 in backups
    assert p2 in backups
    assert p1 not in backups

    restored = mgr.restore_text(p2)
    assert restored == "A=2\n"


def test_audit_logger_writes_masked_values(tmp_path: Path):
    logger = AuditLogger(tmp_path)
    result = OperationResult(
        operation_id="op-1",
        target="windows:user:API_TOKEN",
        action="set",
        success=True,
        backup_path="/tmp/x",
        diff_preview="--- before\n+++ after",
        error_message=None,
        value_masked="abc********xyz",
    )
    logger.log(result)

    text = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "op-1" in text
    assert "abc********xyz" in text


def test_restore_rejects_backup_file_outside_state_directory(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    external_backup = tmp_path / "external.backup.json"
    external_backup.write_text(json.dumps({"target": "linux:bashrc", "text": "export A='1'\n"}), encoding="utf-8")

    result = svc.restore_backup(backup=str(external_backup))

    assert result["success"] is False
    assert "outside managed backup directory" in (result["error_message"] or "")
