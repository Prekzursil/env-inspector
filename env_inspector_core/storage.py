"""Storage module."""

import glob
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from .models import OperationResult


def _mkdirp(path: Path) -> None:
    """Mkdirp."""
    os.makedirs(path, exist_ok=True)


def _path_exists(path: Path) -> bool:
    """Path exists."""
    return os.path.exists(path)


def _read_text(path: Path) -> str:
    """Read text."""
    resolved = Path(path).resolve()
    with open(resolved, encoding="utf-8") as handle:  # noqa: S108 - caller validates scope
        return handle.read()


def _write_text(path: Path, text: str) -> None:
    """Write text."""
    resolved = Path(path).resolve()
    with open(resolved, "w", encoding="utf-8") as handle:  # noqa: S108 - caller validates scope
        handle.write(text)


class BackupManager:
    """Manages timestamped backup files with configurable retention."""

    def __init__(self, base_dir: Path, retention: int = 20) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.retention = retention
        _mkdirp(self.base_dir)

    def backup_text(self, target: str, text: str) -> Path:
        """Backup text."""
        now, path = self._next_backup_path()
        path = self._normalize_backup_path(path)
        payload = {"target": target, "created_at": now, "text": text}
        _write_text(path, json.dumps(payload, ensure_ascii=True, indent=2))  # NOSONAR
        self._enforce_retention(target)
        return path

    def _next_backup_path(self) -> Tuple[str, Path]:
        """Next backup path."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

        for sequence in range(10000):
            candidate = self.base_dir / f"{timestamp}-{sequence:04d}.backup.json"
            if not _path_exists(candidate):
                return timestamp, candidate

        raise RuntimeError("Could not allocate unique backup file name")

    def _normalize_backup_path(self, candidate: Path) -> Path:
        """Normalize backup path."""
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.base_dir)
        except ValueError as exc:
            raise ValueError(f"Backup path escapes backup root: {candidate}") from exc
        return resolved

    def _enforce_retention(self, target: str) -> None:
        """Enforce retention."""
        files = self.list_backups(target)
        if len(files) <= self.retention:
            return
        for old in files[self.retention :]:
            old.unlink(missing_ok=True)

    def list_backups(self, target: str) -> List[Path]:
        """List backups."""
        backups: List[Path] = []
        for backup in self.list_all_backups():
            payload = self._load_backup_payload(backup)
            if payload is not None and str(payload.get("target", "")) == target:
                backups.append(backup)
        return sorted(backups, reverse=True)

    def list_all_backups(self) -> List[Path]:
        """List all backups."""
        return sorted(
            (
                Path(path)
                for path in glob.glob(
                    str(self.base_dir / "**" / "*.backup.json"), recursive=True
                )
            ),
            reverse=True,
        )

    @staticmethod
    def _load_backup_payload(backup_path: Path) -> dict | None:
        """Load backup payload."""
        try:
            payload = json.loads(_read_text(backup_path))
        except (OSError, TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def restore_text(backup_path: Path) -> str:
        """Restore text."""
        payload = json.loads(_read_text(Path(backup_path)))
        return str(payload["text"])

    @staticmethod
    def read_backup_payload(backup_path: Path) -> Dict[str, str]:
        """Read backup payload."""
        payload = json.loads(_read_text(Path(backup_path)))
        return {"target": str(payload["target"]), "text": str(payload["text"])}


class AuditLogger:
    """Appends operation results to a JSON-lines audit log."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        _mkdirp(self.base_dir)
        self.path = self.base_dir / "audit.log"

    def log(self, result: OperationResult) -> None:
        """Log."""
        payload = asdict(result)
        payload["logged_at"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(payload, ensure_ascii=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
