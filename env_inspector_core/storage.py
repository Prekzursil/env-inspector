from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import OperationResult


class BackupManager:
    def __init__(self, base_dir: Path, retention: int = 20) -> None:
        self.base_dir = Path(base_dir)
        self.retention = retention
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def backup_text(self, target: str, text: str) -> Path:
        now, path = self._next_backup_path()
        payload = {"target": target, "created_at": now, "text": text}
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        self._enforce_retention(target)
        return path

    def _next_backup_path(self) -> tuple[str, Path]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

        for sequence in range(10000):
            candidate = self.base_dir / f"{timestamp}-{sequence:04d}.backup.json"
            if not candidate.exists():
                return timestamp, candidate

        raise RuntimeError("Could not allocate unique backup file name")

    def _enforce_retention(self, target: str) -> None:
        files = self.list_backups(target)
        if len(files) <= self.retention:
            return
        for old in files[self.retention :]:
            old.unlink(missing_ok=True)

    def list_backups(self, target: str) -> list[Path]:
        backups: list[Path] = []
        for backup in self.list_all_backups():
            try:
                payload = json.loads(backup.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("target", "")) == target:
                backups.append(backup)
        return backups

    def list_all_backups(self) -> list[Path]:
        return sorted(self.base_dir.glob("*.backup.json"), reverse=True)

    def restore_text(self, backup_path: Path) -> str:
        payload = json.loads(Path(backup_path).read_text(encoding="utf-8"))
        return str(payload["text"])

    def read_backup_payload(self, backup_path: Path) -> dict[str, str]:
        payload = json.loads(Path(backup_path).read_text(encoding="utf-8"))
        return {"target": str(payload["target"]), "text": str(payload["text"])}


class AuditLogger:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.base_dir / "audit.log"

    def log(self, result: OperationResult) -> None:
        payload = asdict(result)
        payload["logged_at"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(payload, ensure_ascii=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
