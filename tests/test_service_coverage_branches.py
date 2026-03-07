from __future__ import absolute_import, division

from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from env_inspector_core.constants import (
    SOURCE_DOTENV,
    SOURCE_LINUX_BASHRC,
    SOURCE_LINUX_ETC_ENV,
    SOURCE_POWERSHELL_PROFILE,
    SOURCE_WSL_BASHRC,
    SOURCE_WSL_DOTENV,
    SOURCE_WSL_ETC_ENV,
)
from env_inspector_core.models import EnvRecord
from env_inspector_core.service import EnvInspectorService
import env_inspector_core.service as service_module

from tests.assertions import ensure


def _record(source_type: str, source_path: str, *, context: str = "linux", source_id: str = "Ubuntu") -> EnvRecord:
    return EnvRecord(
        source_type=source_type,
        source_id=source_id,
        source_path=source_path,
        context=context,
        name="API_TOKEN",
        value="value",
        is_secret=False,
        is_persistent=True,
        is_mutable=True,
        precedence_rank=1,
        writable=True,
        requires_privilege=False,
    )


def test_collect_wsl_rows_uses_linux_exclusion_and_dotenv(monkeypatch, tmp_path: Path) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.runtime_context = "linux"
    svc.current_wsl_distro = "Ubuntu"
    monkeypatch.setattr(svc.wsl, "available", lambda: True)

    calls: Dict[str, object] = {}

    def _fake_collect_wsl_records(wsl, include_etc: bool, exclude_distros) -> List[EnvRecord]:
        calls["exclude"] = exclude_distros
        return [_record(SOURCE_WSL_BASHRC, "~/.bashrc", context="wsl:Debian", source_id="Debian")]

    def _fake_collect_wsl_dotenv_records(wsl, distro: str, root_path: str, max_depth: int) -> List[EnvRecord]:
        calls["dotenv"] = (distro, root_path, max_depth)
        return [_record(SOURCE_WSL_DOTENV, "Debian:/home/user/.env", context="wsl:Debian", source_id="Debian")]

    monkeypatch.setattr(service_module, "collect_wsl_records", _fake_collect_wsl_records)
    monkeypatch.setattr(service_module, "collect_wsl_dotenv_records", _fake_collect_wsl_dotenv_records)

    rows = svc._collect_wsl_rows(scan_depth=3, distro="Debian", wsl_path="/home/user")

    ensure(calls["exclude"] == {"Ubuntu"})
    ensure(calls["dotenv"] == ("Debian", "/home/user", 3))
    ensure(len(rows) == 2)


def test_collect_wsl_rows_swallows_collection_errors(monkeypatch, tmp_path: Path) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    monkeypatch.setattr(svc.wsl, "available", lambda: True)

    def _raise_runtime_error(*_args, **_kwargs) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(service_module, "collect_wsl_records", _raise_runtime_error)
    monkeypatch.setattr(service_module, "collect_wsl_dotenv_records", _raise_runtime_error)

    rows = svc._collect_wsl_rows(scan_depth=2, distro="Ubuntu", wsl_path="/home/user")

    ensure(rows == [])


def test_available_targets_maps_all_known_sources_and_filters_context(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.win_provider = object()
    records = [
        _record(SOURCE_DOTENV, str(tmp_path / ".env"), context="linux"),
        _record(SOURCE_LINUX_BASHRC, str(tmp_path / ".bashrc"), context="linux"),
        _record(SOURCE_LINUX_ETC_ENV, "/etc/environment", context="linux"),
        _record(SOURCE_WSL_DOTENV, "Ubuntu:/home/u/.env", context="linux", source_id="Ubuntu"),
        _record(SOURCE_WSL_BASHRC, "~/.bashrc", context="linux", source_id="Ubuntu"),
        _record(SOURCE_WSL_ETC_ENV, "/etc/environment", context="linux", source_id="Ubuntu"),
        _record(SOURCE_POWERSHELL_PROFILE, r"C:\Program Files\PowerShell\7\profile.ps1", context="linux"),
        _record(SOURCE_POWERSHELL_PROFILE, r"C:\Users\me\Documents\PowerShell\profile.ps1", context="linux"),
        _record(SOURCE_DOTENV, "ignored.env", context="wsl:Ubuntu"),
    ]

    targets = svc.available_targets(records, context="linux")

    ensure("dotenv:" + str(tmp_path / ".env") in targets)
    ensure("linux:bashrc" in targets)
    ensure("linux:etc_environment" in targets)
    ensure("wsl_dotenv:Ubuntu:/home/u/.env" in targets)
    ensure("wsl:Ubuntu:bashrc" in targets)
    ensure("wsl:Ubuntu:etc_environment" in targets)
    ensure("powershell:all_users" in targets)
    ensure("powershell:current_user" in targets)
    ensure("windows:user" in targets and "windows:machine" in targets)
    ensure("dotenv:ignored.env" not in targets)
    ensure(svc._record_target(_record("unknown_source", "x")) is None)


def test_registry_write_requires_provider(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    svc.win_provider = None

    with pytest.raises(RuntimeError, match="registry provider unavailable"):
        svc._registry_write("windows:user", "A", "1", "set", apply_changes=False)


def test_update_helpers_cover_dispatch_and_error_branches(monkeypatch, tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    with pytest.raises(RuntimeError, match="Unsupported Linux target"):
        svc._update_linux_file(target="linux:unknown", key="A", value="1", action="set", apply_changes=False)

    wsl_writes: List[Tuple[str, str, str]] = []
    monkeypatch.setattr(svc.wsl, "read_file", lambda distro, path: "")
    monkeypatch.setattr(
        svc.wsl,
        "write_file_with_privilege",
        lambda distro, path, text: wsl_writes.append((distro, path, text)),
    )
    svc._update_wsl_file(target="wsl:Ubuntu:etc_environment", key="A", value="1", action="set", apply_changes=True)
    ensure(wsl_writes and wsl_writes[0][0] == "Ubuntu")

    with pytest.raises(RuntimeError, match="Unsupported WSL target"):
        svc._update_wsl_file(target="wsl:Ubuntu:profile", key="A", value="1", action="set", apply_changes=False)

    with pytest.raises(RuntimeError, match="Unsupported WSL dotenv target path"):
        svc._update_wsl_file(
            target="wsl_dotenv:Ubuntu:/home/user/../outside.env",
            key="A",
            value="1",
            action="set",
            apply_changes=False,
        )

    profile = tmp_path / "profile.ps1"
    monkeypatch.setattr(EnvInspectorService, "_powershell_target_path_and_roots", lambda _self, _target: (profile, [tmp_path], False))
    _before, _after, out_path, _requires_priv, _ = svc._update_powershell_file(
        target="powershell:current_user",
        key="A",
        value="1",
        action="set",
        apply_changes=True,
    )
    ensure(out_path == str(profile))
    ensure("$env:A" in profile.read_text(encoding="utf-8"))

    monkeypatch.setattr(
        svc,
        "_update_wsl_file",
        lambda **kwargs: ("before", "after", "wsl", False, None),
    )
    monkeypatch.setattr(
        svc,
        "_update_powershell_file",
        lambda **kwargs: ("before", "after", "ps", False, None),
    )
    ensure(svc._file_update("wsl:Ubuntu:bashrc", "A", "1", "set", apply_changes=False, scope_roots=[])[2] == "wsl")
    ensure(svc._file_update("powershell:current_user", "A", "1", "set", apply_changes=False, scope_roots=[])[2] == "ps")


def test_restore_helpers_cover_linux_and_wsl_targets(tmp_path: Path, monkeypatch) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(service_module.Path, "home", lambda: fake_home)

    svc._restore_linux_target(target="linux:bashrc", text="export A=1\n")
    ensure((fake_home / ".bashrc").read_text(encoding="utf-8") == "export A=1\n")

    etc_calls: List[str] = []
    monkeypatch.setattr(svc, "_write_linux_etc_environment_with_privilege", etc_calls.append)
    svc._restore_linux_target(target="linux:etc_environment", text="A=1\n")
    ensure(etc_calls == ["A=1\n"])

    with pytest.raises(RuntimeError, match="Unsupported Linux restore target"):
        svc._restore_linux_target(target="linux:unknown", text="x")

    wsl_calls: List[Tuple[str, str, str]] = []
    monkeypatch.setattr(
        svc.wsl,
        "write_file_with_privilege",
        lambda distro, path, text: wsl_calls.append((distro, path, text)),
    )
    svc._restore_wsl_target(target="wsl:Ubuntu:etc_environment", text="A=1\n")
    ensure(wsl_calls == [("Ubuntu", "/etc/environment", "A=1\n")])

    with pytest.raises(RuntimeError, match="Unsupported WSL restore target"):
        svc._restore_wsl_target(target="wsl:Ubuntu:unknown", text="x")


def test_restore_helpers_cover_powershell_and_registry(tmp_path: Path, monkeypatch) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    profile = fake_home / "Documents" / "PowerShell" / "ps-profile.ps1"
    monkeypatch.setattr(service_module.Path, "home", lambda: fake_home)
    monkeypatch.setattr(EnvInspectorService, "_validated_powershell_restore_path", lambda _self, _target: profile)
    svc._restore_powershell_target(target="powershell:current_user", text="$env:A=\"1\"\n")
    ensure(profile.read_text(encoding="utf-8") == "$env:A=\"1\"\n")

    svc.win_provider = None
    with pytest.raises(RuntimeError, match="provider unavailable"):
        svc._restore_windows_registry_target(target="windows:user", text="{}")

    class _FakeWinProvider:
        def __init__(self) -> None:
            self.removed: List[Tuple[str, str]] = []
            self.sets: List[Tuple[str, str, str]] = []

        @staticmethod
        def list_scope(scope: str) -> Dict[str, str]:
            return {"KEEP": "1", "DROP": "2"}

        def remove_scope_value(self, scope: str, key: str) -> None:
            self.removed.append((scope, key))

        def set_scope_value(self, scope: str, key: str, value: str) -> None:
            self.sets.append((scope, key, value))

    fake = _FakeWinProvider()
    svc.win_provider = fake
    svc._restore_windows_registry_target(target="windows:user", text="{\"KEEP\":\"1\",\"NEW\":\"3\"}")
    ensure(fake.removed and fake.removed[0][1] == "DROP")
    ensure(any(key == "NEW" for _scope, key, _value in fake.sets))


def test_restore_helpers_cover_dispatch(tmp_path: Path, monkeypatch) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    calls: List[str] = []
    monkeypatch.setattr(svc, "_restore_linux_target", lambda **kwargs: calls.append("linux"))
    monkeypatch.setattr(svc, "_restore_powershell_target", lambda **kwargs: calls.append("powershell"))
    monkeypatch.setattr(svc, "_restore_windows_registry_target", lambda **kwargs: calls.append("windows"))
    svc._restore_target(target="linux:bashrc", text="x", scope_roots=[])
    svc._restore_target(target="powershell:current_user", text="x", scope_roots=[])
    svc._restore_target(target="windows:user", text="x", scope_roots=[])
    ensure(calls == ["linux", "powershell", "windows"])

    with pytest.raises(RuntimeError, match="Unsupported restore target"):
        svc._restore_target(target="custom:target", text="x", scope_roots=[])


def test_restore_dotenv_target_rejects_outside_scope(tmp_path: Path, monkeypatch) -> None:
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    allowed = tmp_path / "allowed"
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    env_path = outside / ".env"
    allowed.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)

    class _Scoped:
        def __init__(self, path: Path) -> None:
            self.path = path
            self.roots = [allowed]

    monkeypatch.setattr(service_module, "parse_scoped_dotenv_target", lambda target, roots: _Scoped(env_path))

    with pytest.raises(RuntimeError, match="outside approved roots"):
        svc._restore_dotenv_target(
            target=f"dotenv:{env_path}",
            text="A=1\n",
            scope_roots=[allowed],
        )


def test_registry_write_machine_requires_privilege_and_user_scope(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    import types

    fake_provider = types.SimpleNamespace(
        USER_SCOPE="User",
        MACHINE_SCOPE="Machine",
        list_scope=lambda _scope: {"A": "1"},
        set_scope_value=lambda _scope, _key, _value: None,
        remove_scope_value=lambda _scope, _key: None,
    )

    svc.win_provider = fake_provider  # type: ignore[assignment]

    _before_user, _after_user, _path_user, user_requires_priv, _ = svc._registry_write(
        "windows:user",
        "A",
        "2",
        "set",
        apply_changes=False,
    )
    _before_machine, _after_machine, _path_machine, machine_requires_priv, _ = svc._registry_write(
        "windows:machine",
        "A",
        "2",
        "set",
        apply_changes=False,
    )

    import unittest

    case = unittest.TestCase()
    case.assertFalse(user_requires_priv)
    case.assertTrue(machine_requires_priv)

    svc._registry_write(
        "windows:user",
        "B",
        "9",
        "set",
        apply_changes=True,
    )
    svc._registry_write(
        "windows:machine",
        "A",
        None,
        "remove",
        apply_changes=True,
    )


def test_powershell_profile_path_returns_expected_target_paths(tmp_path: Path, monkeypatch):
    svc = EnvInspectorService(state_dir=tmp_path / "state")
    current = tmp_path / "current.ps1"
    all_users = tmp_path / "all.ps1"
    monkeypatch.setattr(EnvInspectorService, "get_powershell_profile_paths", staticmethod(lambda: [current, all_users]))

    import unittest

    case = unittest.TestCase()
    case.assertEqual(svc._powershell_profile_path("powershell:current_user"), current)
    case.assertEqual(svc._powershell_profile_path("powershell:all_users"), all_users)


def test_validate_wsl_dotenv_path_rejects_empty_and_wrong_filename(tmp_path: Path):
    svc = EnvInspectorService(state_dir=tmp_path / "state")

    with pytest.raises(RuntimeError, match="Unsupported WSL dotenv target path"):
        svc._validate_wsl_dotenv_path("")

    with pytest.raises(RuntimeError, match="Unsupported WSL dotenv target path"):
        svc._validate_wsl_dotenv_path("/home/user/not-env.txt")


def test_list_backups_uses_target_filter_when_provided(tmp_path: Path):
    import unittest

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    backup_path = svc.backup_mgr.backup_text("linux:bashrc", "A=1\n")

    all_backups = svc.list_backups()
    scoped_backups = svc.list_backups(target="linux:bashrc")

    case = unittest.TestCase()
    case.assertIn(str(backup_path), all_backups)
    case.assertIn(str(backup_path), scoped_backups)


def test_list_records_raw_builds_env_records_from_payload(tmp_path: Path, monkeypatch):
    import unittest

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    sample_payload = [
        {
            "source_type": "dotenv",
            "source_id": "dotenv",
            "source_path": str(tmp_path / ".env"),
            "context": "windows",
            "name": "A",
            "value": "1",
            "is_secret": bool(0),
            "is_persistent": True,
            "is_mutable": True,
            "precedence_rank": 10,
            "writable": True,
            "requires_privilege": False,
            "last_error": None,
        }
    ]
    monkeypatch.setattr(svc, "list_records", lambda **_kwargs: sample_payload)

    rows = svc.list_records_raw()

    case = unittest.TestCase()
    case.assertEqual(len(rows), 1)
    case.assertEqual(rows[0].name, "A")
    case.assertEqual(rows[0].value, "1")
