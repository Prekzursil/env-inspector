from __future__ import absolute_import, division

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List

from .models import OperationResult
from .path_policy import parse_scoped_dotenv_target, validate_backup_path
from .providers import WindowsRegistryProvider
from .targets import (
    DOTENV_TARGET_PREFIX,
    TARGET_LINUX_BASHRC,
    TARGET_LINUX_ETC_ENV,
    TARGET_POWERSHELL_ALL_USERS,
    TARGET_POWERSHELL_CURRENT_USER,
    TARGET_WINDOWS_MACHINE,
    TARGET_WINDOWS_USER,
    WSL_DOTENV_TARGET_PREFIX,
)


class ServiceRestoreMixin:
    def list_backups(self, *, target: str | None = None) -> List[str]:
        svc: Any = self
        if target:
            return [str(p) for p in svc.backup_mgr.list_backups(target)]
        return [str(p) for p in svc.backup_mgr.list_all_backups()]

    def _restore_dotenv_target(self, *, target: str, text: str, scope_roots: List[Path]) -> None:
        svc: Any = self
        scoped = parse_scoped_dotenv_target(target, roots=scope_roots)
        svc._write_scoped_text_file(
            candidate_path=scoped.path,
            allowed_roots=scoped.roots,
            text=text,
            label="restore dotenv path",
        )

    def _restore_linux_target(self, *, target: str, text: str) -> None:
        svc: Any = self
        if target == TARGET_LINUX_BASHRC:
            path_out = Path.home() / ".bashrc"
            path_out.parent.mkdir(parents=True, exist_ok=True)
            path_out.write_text(text, encoding="utf-8")
            return
        if target == TARGET_LINUX_ETC_ENV:
            svc._write_linux_etc_environment_with_privilege(text)
            return
        raise RuntimeError(f"Unsupported Linux restore target: {target}")

    def _restore_wsl_target(self, *, target: str, text: str) -> None:
        svc: Any = self
        if target.startswith(WSL_DOTENV_TARGET_PREFIX):
            distro, pth = svc._parse_wsl_dotenv_target(target)
            svc.wsl.write_file(distro, pth, text)
            return
        if target.startswith("wsl:") and target.endswith(":bashrc"):
            distro = svc._validate_wsl_distro_name(target.split(":", 2)[1])
            svc.wsl.write_file(distro, "~/.bashrc", text)
            return
        if target.startswith("wsl:") and target.endswith(":etc_environment"):
            distro = svc._validate_wsl_distro_name(target.split(":", 2)[1])
            svc.wsl.write_file_with_privilege(distro, svc._LINUX_ETC_ENV_PATH, text)
            return
        raise RuntimeError(f"Unsupported WSL restore target: {target}")

    def _restore_powershell_target(self, *, target: str, text: str) -> None:
        svc: Any = self
        safe_profile = svc._validated_powershell_restore_path(target)
        svc._write_text_file(safe_profile, text, ensure_parent=True)

    def _restore_windows_registry_target(self, *, target: str, text: str) -> None:
        svc: Any = self
        if svc.win_provider is None:
            raise RuntimeError("Windows provider unavailable for registry restore")
        data = json.loads(text)
        scope = WindowsRegistryProvider.USER_SCOPE if target == TARGET_WINDOWS_USER else WindowsRegistryProvider.MACHINE_SCOPE
        current = svc.win_provider.list_scope(scope)
        for key in tuple(current):
            if key not in data:
                svc.win_provider.remove_scope_value(scope, key)
        for key, value in data.items():
            svc.win_provider.set_scope_value(scope, key, str(value))

    def _restore_target(self, *, target: str, text: str, scope_roots: List[Path]) -> None:
        svc: Any = self
        if target.startswith(DOTENV_TARGET_PREFIX):
            svc._restore_dotenv_target(target=target, text=text, scope_roots=scope_roots)
            return
        if target in {TARGET_LINUX_BASHRC, TARGET_LINUX_ETC_ENV}:
            svc._restore_linux_target(target=target, text=text)
            return
        if target.startswith("wsl"):
            svc._restore_wsl_target(target=target, text=text)
            return
        if target in {TARGET_POWERSHELL_CURRENT_USER, TARGET_POWERSHELL_ALL_USERS}:
            svc._restore_powershell_target(target=target, text=text)
            return
        if target in {TARGET_WINDOWS_USER, TARGET_WINDOWS_MACHINE}:
            svc._restore_windows_registry_target(target=target, text=text)
            return
        raise RuntimeError(f"Unsupported restore target: {target}")

    def restore_backup(
        self,
        *,
        backup: str,
        scope_roots: List[str | Path] | None = None,
    ) -> Dict[str, Any]:
        svc: Any = self
        operation_id = f"restore-{uuid.uuid4().hex[:10]}"
        path = Path(backup)
        try:
            resolved_scope_roots = svc._effective_scope_roots(scope_roots)
            path = validate_backup_path(backup, backups_dir=svc.backup_mgr.base_dir)
            payload = svc.backup_mgr.read_backup_payload(path)
            target = payload["target"]
            text = payload["text"]

            svc._restore_target(target=target, text=text, scope_roots=resolved_scope_roots)

            result = OperationResult(
                operation_id=operation_id,
                target=target,
                action="restore",
                success=True,
                backup_path=str(path),
                diff_preview="",
                error_message=None,
                value_masked=None,
            )
        except Exception as exc:
            result = OperationResult(
                operation_id=operation_id,
                target="restore",
                action="restore",
                success=False,
                backup_path=str(path),
                diff_preview="",
                error_message=str(exc),
                value_masked=None,
            )

        svc.audit.log(result)
        return result.to_dict()
