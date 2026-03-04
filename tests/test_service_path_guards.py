from __future__ import absolute_import

from pathlib import Path

import pytest

from env_inspector_core.service import EnvInspectorService
import env_inspector_core.service as service_module


def test_is_path_within_returns_false_for_unrelated_roots(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    if not (svc._is_path_within(tmp_path / "outside" / ".env", tmp_path / "allowed") is False):
        raise AssertionError()



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

    if not (resolved == fake_profile.resolve(strict=False)):
        raise AssertionError()



def test_validated_powershell_restore_path_all_users_rejects_outside_root(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    bad_profile = tmp_path / "not-program-files" / "profile.ps1"

    monkeypatch.setattr(EnvInspectorService, "_powershell_profile_path", lambda _self, _target: bad_profile)

    with pytest.raises(RuntimeError, match="outside approved roots"):
        svc._validated_powershell_restore_path("powershell:all_users")


def test_linux_etc_environment_path_guard_handles_platform_semantics(tmp_path: Path, monkeypatch):
    _ = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", r"\etc\environment")

    monkeypatch.setattr(service_module.os, "name", "nt", raising=False)
    with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
        EnvInspectorService._linux_etc_environment_path()

    monkeypatch.setattr(service_module.os, "name", "posix", raising=False)
    resolved = EnvInspectorService._linux_etc_environment_path()
    if not (resolved.as_posix() == r"\etc\environment"):
        raise AssertionError()



def test_write_linux_etc_environment_with_privilege_rejects_non_fixed_path(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", r"\etc\environment")

    with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
        svc._write_linux_etc_environment_with_privilege("A=1\n")


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

    if not (result["success"] is True):
        raise AssertionError()

    if not (env_file.read_text(encoding="utf-8") == "A=1\n"):
        raise AssertionError()



def test_restore_wsl_dotenv_backup_uses_wsl_write_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "write_file", lambda distro, path, text: calls.append((distro, path, text)))

    backup_path = svc.backup_mgr.backup_text("wsl_dotenv:Ubuntu:/home/user/.env", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path))

    if not (result["success"] is True):
        raise AssertionError()

    if not (calls == [("Ubuntu", "/home/user/.env", "A=1\n")]):
        raise AssertionError()



def test_restore_wsl_bashrc_backup_uses_wsl_write_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "write_file", lambda distro, path, text: calls.append((distro, path, text)))

    backup_path = svc.backup_mgr.backup_text("wsl:Ubuntu:bashrc", "export A='1'\n")
    result = svc.restore_backup(backup=str(backup_path))

    if not (result["success"] is True):
        raise AssertionError()

    if not (calls == [("Ubuntu", "~/.bashrc", "export A='1'\n")]):
        raise AssertionError()




def test_linux_etc_environment_path_guard_non_windows_branch(tmp_path: Path, monkeypatch):
    _ = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(service_module.os, "name", "posix", raising=False)
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", r"\etc\environment")

    resolved = EnvInspectorService._linux_etc_environment_path()

    if not (resolved.as_posix() == r"\etc\environment"):
        raise AssertionError()



def test_restore_wsl_dotenv_backup_rejects_path_traversal(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "write_file", lambda distro, path, text: calls.append((distro, path, text)))

    backup_path = svc.backup_mgr.backup_text("wsl_dotenv:Ubuntu:/home/user/../outside.env", "A=1\n")
    result = svc.restore_backup(backup=str(backup_path))

    if not (result["success"] is False):
        raise AssertionError()

    if not ("Unsupported WSL dotenv target path" in (result["error_message"] or "")):
        raise AssertionError()

    if not (calls == []):
        raise AssertionError()


def test_validate_target_for_operation_rejects_unknown_target(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    with pytest.raises(RuntimeError, match="Unsupported target"):
        svc._validate_target_for_operation("custom:target", scope_roots=[tmp_path])


def test_validate_target_for_operation_rejects_dotenv_outside_scope(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    allowed = tmp_path / "allowed"
    allowed.mkdir(parents=True, exist_ok=True)
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir(parents=True, exist_ok=True)

    with pytest.raises(Exception, match="outside approved roots"):
        svc._validate_target_for_operation(f"dotenv:{outside / '.env'}", scope_roots=[allowed])

def test_validate_target_for_operation_accepts_wsl_variants(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    svc._validate_target_for_operation("wsl_dotenv:Ubuntu:/home/user/.env", scope_roots=[tmp_path])
    svc._validate_target_for_operation("wsl:Ubuntu:bashrc", scope_roots=[tmp_path])


def test_restore_powershell_target_all_users_uses_program_files_root(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    profile = tmp_path / "program_files" / "PowerShell" / "7" / "profile.ps1"

    writes: dict[str, object] = {}
    monkeypatch.setattr(EnvInspectorService, "_validated_powershell_restore_path", lambda _self, _target: profile)
    monkeypatch.setattr(
        svc,
        "_write_text_file",
        lambda path, text, ensure_parent: writes.update({"path": path, "text": text, "ensure_parent": ensure_parent}),
    )

    svc._restore_powershell_target(target="powershell:all_users", text="$env:A='1'\n")

    if not (writes["path"] == profile):
        raise AssertionError()

    if not (writes["text"] == "$env:A='1'\n"):
        raise AssertionError()

    if not (writes["ensure_parent"] is True):
        raise AssertionError()


