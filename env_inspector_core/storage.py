from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import OperationResult


class BackupManager:
    def __init__(self, base_dir: Path, retention: int = 20) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.retention = retention
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def backup_text(self, target: str, text: str) -> Path:
        target_dir = self._target_dir(target)
        now, path = self._next_backup_path(target_dir)
        path = self._normalize_backup_path(path)
        payload = {"target": target, "created_at": now, "text": text}
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        self._enforce_retention(target)
        return path

    def _target_dir(self, target: str) -> Path:
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
        target_dir = self.base_dir / digest
        target_dir.mkdir(parents=True, exist_ok=True)
        return self._normalize_backup_path(target_dir)

    def _next_backup_path(self, target_dir: Path) -> tuple[str, Path]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

        for sequence in range(10000):
            candidate = target_dir / f"{timestamp}-{sequence:04d}.backup.json"
            if not candidate.exists():
                return timestamp, candidate

        raise RuntimeError("Could not allocate unique backup file name")

    def _normalize_backup_path(self, candidate: Path) -> Path:
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.base_dir)
        except ValueError as exc:
            raise ValueError(f"Backup path escapes backup root: {candidate}") from exc
        return resolved

    def _enforce_retention(self, target: str) -> None:
        files = self.list_backups(target)
        if len(files) <= self.retention:
            return
        for old in files[self.retention :]:
            old.unlink(missing_ok=True)

    def list_backups(self, target: str) -> list[Path]:
        backups: list[Path] = []
        for backup in self._target_dir(target).glob("*.backup.json"):
            payload = self._load_backup_payload(backup)
            if payload is not None and str(payload.get("target", "")) == target:
                backups.append(backup)
        return sorted(backups, reverse=True)

    def list_all_backups(self) -> list[Path]:
        return sorted(self.base_dir.glob("**/*.backup.json"), reverse=True)

    def _load_backup_payload(self, backup_path: Path) -> dict | None:
        try:
            payload = json.loads(backup_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

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
