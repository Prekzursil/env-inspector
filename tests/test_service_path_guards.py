"""Test service path guards module."""

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Tuple

from importlib import import_module

import pytest
from env_inspector_core.service import EnvInspectorService
from tests.assertions import ensure

service_module = import_module("env_inspector_core.service")
service_paths_module = import_module("env_inspector_core.service_paths")


def test_is_path_within_returns_false_for_unrelated_roots(tmp_path: Path):
    """Test is path within returns false for unrelated roots."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    ensure(
        svc._is_path_within(tmp_path / "outside" / ".env", tmp_path / "allowed")
        is False
    )


def test_validate_path_in_roots_raises_for_outside_path(tmp_path: Path):
    """Test validate path in roots raises for outside path."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    outside = tmp_path.parent / (tmp_path.name + "-outside") / ".env"
    outside.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="outside approved roots"):
        svc._validate_path_in_roots(
            outside, [tmp_path / "allowed"], label="dotenv target"
        )


def test_validated_powershell_restore_path_rejects_unsupported_target(tmp_path: Path):
    """Test validated powershell restore path rejects unsupported target."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    with pytest.raises(RuntimeError, match="Unsupported PowerShell target"):
        svc._validated_powershell_restore_path("powershell:unsupported")


def test_validated_powershell_restore_path_current_user_success(
    tmp_path: Path, monkeypatch
):
    """Test validated powershell restore path current user success."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    fake_profile = (
        fake_home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
    )

    monkeypatch.setattr(service_module.Path, "home", lambda: fake_home)
    monkeypatch.setattr(
        EnvInspectorService,
        "_powershell_profile_path",
        lambda _self, _target: fake_profile,
    )

    resolved = svc._validated_powershell_restore_path("powershell:current_user")

    ensure(resolved == fake_profile.resolve(strict=False))


def test_validated_powershell_restore_path_all_users_rejects_outside_root(
    tmp_path: Path, monkeypatch
):
    """Test validated powershell restore path all users rejects outside root."""
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    bad_profile = tmp_path / "not-program-files" / "profile.ps1"

    monkeypatch.setattr(
        EnvInspectorService,
        "_powershell_profile_path",
        lambda _self, _target: bad_profile,
    )

    with pytest.raises(RuntimeError, match="outside approved roots"):
        svc._validated_powershell_restore_path("powershell:all_users")


def test_linux_etc_environment_path_guard_handles_platform_semantics(
    tmp_path: Path, monkeypatch
):
    """Test linux etc environment path guard handles platform semantics."""
    _ = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", r"\etc\environment")

    monkeypatch.setattr(service_paths_module, "os", SimpleNamespace(name="nt"))
    with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
        EnvInspectorService._linux_etc_environment_path()

    # pathlib selects the Windows/Posix flavour from the REAL host, not the mocked os.name, so a
    # backslash input round-trips unchanged only on a posix host; on a Windows host it normalizes
    # to forward slashes and the guard fires. The posix branch (line 98) executes on both.
    monkeypatch.setattr(service_paths_module, "os", SimpleNamespace(name="posix"))
    if os.name == "nt":
        with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
            EnvInspectorService._linux_etc_environment_path()
    else:
        resolved = EnvInspectorService._linux_etc_environment_path()
        ensure(resolved.as_posix() == r"\etc\environment")


def test_linux_etc_environment_path_guard_rejects_normalized_path():
    """Test linux etc environment path guard rejects normalized path."""
    with pytest.raises(RuntimeError, match="Unexpected /etc/environment resolution"):
        service_paths_module.linux_etc_environment_path("/etc//environment")


def test_linux_etc_environment_path_returns_normalized_input(tmp_path, monkeypatch):
    """An already-normalized posix path round-trips unchanged on any host (covers the return branch)."""
    _ = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(EnvInspectorService, "_LINUX_ETC_ENV_PATH", "/etc/environment")
    monkeypatch.setattr(service_paths_module, "os", SimpleNamespace(name="posix"))
    resolved = EnvInspectorService._linux_etc_environment_path()
    ensure(resolved.as_posix() == "/etc/environment")
