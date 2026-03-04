from __future__ import absolute_import, division

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import env_inspector_core.storage as storage_mod
from env_inspector_core.storage import BackupManager, AuditLogger
from env_inspector_core.models import OperationResult
from env_inspector_core.service import EnvInspectorService

def _expect(condition, message: str = "") -> None:
    if not condition: raise AssertionError(message)



def test_backup_manager_retention_and_restore(tmp_path: Path):
    mgr = BackupManager(tmp_path, retention=2)
    target = "dotenv:/workspace/.env"

    p1 = mgr.backup_text(target, "A=1\n")
    p2 = mgr.backup_text(target, "A=2\n")
    p3 = mgr.backup_text(target, "A=3\n")

    backups = mgr.list_backups(target)
    _expect(len(backups) == 2)

    _expect(p3 in backups)

    _expect(p2 in backups)

    _expect(p1 not in backups)


    restored = mgr.restore_text(p2)
    _expect(restored == "A=2\n")



def test_backup_manager_uses_unique_path_when_timestamp_collides(tmp_path: Path, monkeypatch):
    fixed_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    class _FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: D401 - signature matches datetime.now
            return fixed_time if tz is not None else fixed_time.replace(tzinfo=None)

    monkeypatch.setattr(storage_mod, "datetime", _FixedDateTime)

    mgr = BackupManager(tmp_path, retention=5)
    target = "dotenv:/workspace/.env"

    p1 = mgr.backup_text(target, "A=1\n")
    p2 = mgr.backup_text(target, "A=2\n")
    p3 = mgr.backup_text(target, "A=3\n")

    _expect(p1 != p2 != p3)

    _expect(p1.name.endswith("-0000.backup.json"))

    _expect(p2.name.endswith("-0001.backup.json"))

    _expect(p3.name.endswith("-0002.backup.json"))



def test_next_backup_path_raises_when_timestamp_sequence_exhausted(tmp_path: Path, monkeypatch):
    fixed_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    class _FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: D401 - signature matches datetime.now
            return fixed_time if tz is not None else fixed_time.replace(tzinfo=None)

    monkeypatch.setattr(storage_mod, "datetime", _FixedDateTime)

    mgr = BackupManager(tmp_path, retention=5)
    original_exists = Path.exists

    def _always_exists(path: Path) -> bool:
        if str(path).endswith(".backup.json"):
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", _always_exists)
    _expect(Path.exists(tmp_path))


    with pytest.raises(RuntimeError, match="Could not allocate unique backup file name"):
        mgr._next_backup_path()


def test_normalize_backup_path_rejects_escape(tmp_path: Path):
    mgr = BackupManager(tmp_path / "backups", retention=5)
    outside = tmp_path.parent / "outside.backup.json"

    with pytest.raises(ValueError, match="escapes backup root"):
        mgr._normalize_backup_path(outside)


def test_load_backup_payload_returns_none_for_invalid_json(tmp_path: Path):
    mgr = BackupManager(tmp_path, retention=5)
    bad = tmp_path / "bad.backup.json"
    bad.write_text("{not valid json", encoding="utf-8")

    _expect(mgr._load_backup_payload(bad) is None)



def test_audit_logger_writes_masked_values(tmp_path: Path):
    logger = AuditLogger(tmp_path)
    result = OperationResult(
        operation_id="op-1",
        target="windows:user:API_TOKEN",
        action="set",
        success=True,
        backup_path="/workspace/x",
        diff_preview="--- before\n+++ after",
        error_message=None,
        value_masked="abc********xyz",
    )
    logger.log(result)

    text = (tmp_path / "audit.log").read_text(encoding="utf-8")
    _expect("op-1" in text)

    _expect("abc********xyz" in text)



def test_restore_rejects_backup_file_outside_state_directory(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    external_backup = tmp_path / "external.backup.json"
    external_backup.write_text(json.dumps({"target": "linux:bashrc", "text": "export A='1'\n"}), encoding="utf-8")

    result = svc.restore_backup(backup=str(external_backup))

    _expect(result["success"] is False)

    _expect("outside managed backup directory" in (result["error_message"] or ""))


def test_restore_dotenv_backup_in_scope_writes_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    env_file = allowed / ".env"

    backup_path = svc.backup_mgr.backup_text(f"dotenv:{env_file}", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path), scope_roots=[allowed])

    _expect(result["success"] is True)

    _expect(env_file.read_text(encoding="utf-8") == "A=1\n")



def test_restore_dotenv_backup_rejects_outside_scope(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    allowed = tmp_path / "allowed"
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    allowed.mkdir()
    outside.mkdir()
    env_file = outside / ".env"

    backup_path = svc.backup_mgr.backup_text(f"dotenv:{env_file}", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path), scope_roots=[allowed])

    _expect(result["success"] is False)

    _expect("outside approved roots" in (result["error_message"] or ""))
