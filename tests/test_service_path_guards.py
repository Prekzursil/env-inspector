from __future__ import annotations

from pathlib import Path

import pytest

from env_inspector_core.service import EnvInspectorService
import env_inspector_core.service as service_module


def test_is_path_within_returns_false_for_unrelated_roots(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    assert svc._is_path_within(tmp_path / "outside" / ".env", tmp_path / "allowed") is False


def test_validate_path_in_roots_raises_for_outside_path(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    outside = tmp_path.parent / (tmp_path.name + "-outside") / ".env"
    outside.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="outside approved roots"):
        svc._validate_path_in_roots(outside, [tmp_path / "allowed"], label="dotenv target")


def test_validated_powershell_restore_path_rejects_unsupported_target(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    with pytest.raises(RuntimeError, match="Unsupported PowerShell target"):
        svc._validated_powershell_restore_path("powershell:unsupported")


def test_validated_powershell_restore_path_current_user_success(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    fake_profile = fake_home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"

    monkeypatch.setattr(service_module.Path, "home", lambda: fake_home)
    monkeypatch.setattr(EnvInspectorService, "_powershell_profile_path", lambda _self, _target: fake_profile)

    resolved = svc._validated_powershell_restore_path("powershell:current_user")

    assert resolved == fake_profile.resolve(strict=False)


def test_validated_powershell_restore_path_all_users_rejects_outside_root(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    bad_profile = tmp_path / "not-program-files" / "profile.ps1"

    monkeypatch.setattr(EnvInspectorService, "_powershell_profile_path", lambda _self, _target: bad_profile)

    with pytest.raises(RuntimeError, match="outside expected root"):
        svc._validated_powershell_restore_path("powershell:all_users")


def test_linux_etc_environment_path_guard_raises_on_unexpected_mapping(tmp_path: Path, monkeypatch):
    _ = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", "\\\\etc\\environment")

    with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
        EnvInspectorService._linux_etc_environment_path()


def test_restore_dotenv_path_checks_continue_until_matching_root(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    outside_root = tmp_path.parent / (tmp_path.name + "-outside")
    fail_root = tmp_path.parent / (tmp_path.name + "-fail")
    outside_root.mkdir(parents=True, exist_ok=True)
    fail_root.mkdir(parents=True, exist_ok=True)
    env_file = outside_root / ".env"

    monkeypatch.setattr(svc, "_effective_scope_roots", lambda _scope_roots=None: [fail_root, outside_root])

    backup_path = svc.backup_mgr.backup_text(f"dotenv:{env_file}", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path), scope_roots=[outside_root])

    assert result["success"] is True
    assert env_file.read_text(encoding="utf-8") == "A=1\n"


def test_restore_wsl_dotenv_backup_uses_wsl_write_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "write_file", lambda distro, path, text: calls.append((distro, path, text)))

    backup_path = svc.backup_mgr.backup_text("wsl_dotenv:Ubuntu:/home/user/.env", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path))

    assert result["success"] is True
    assert calls == [("Ubuntu", "/home/user/.env", "A=1\n")]


def test_restore_wsl_bashrc_backup_uses_wsl_write_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "write_file", lambda distro, path, text: calls.append((distro, path, text)))

    backup_path = svc.backup_mgr.backup_text("wsl:Ubuntu:bashrc", "export A='1'\n")
    result = svc.restore_backup(backup=str(backup_path))

    assert result["success"] is True
    assert calls == [("Ubuntu", "~/.bashrc", "export A='1'\n")]

