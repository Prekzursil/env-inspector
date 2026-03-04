from __future__ import annotations

from typing import Literal

import pytest

from tests.conftest import ensure

import env_inspector_core.providers as providers


class _KeyContext:
    def __init__(self, module: "_FakeWinreg") -> None:
        self.module = module

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        return False


class _FakeWinreg:
    HKEY_CURRENT_USER = object()
    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 1
    KEY_SET_VALUE = 2
    KEY_WOW64_64KEY = 4
    REG_EXPAND_SZ = 10
    REG_SZ = 11

    def __init__(self) -> None:
        self.open_calls: list[tuple[object, str, int, int]] = []
        self.set_calls: list[tuple[str, int, str]] = []
        self.delete_calls: list[str] = []
        self.enum_rows = [("A", "1", 1)]
        self.raise_delete_missing = False

    def open_key(self, root, path: str, _zero: int, access: int):
        self.open_calls.append((root, path, 0, access))
        return _KeyContext(self)

    def enum_value(self, _regkey, index: int):
        if index >= len(self.enum_rows):
            raise OSError("done")
        return self.enum_rows[index]

    def set_value_ex(self, _regkey, key: str, _zero: int, reg_type: int, value: str) -> None:
        self.set_calls.append((key, reg_type, value))

    def delete_value(self, _regkey, key: str) -> None:
        if self.raise_delete_missing:
            raise FileNotFoundError(key)
        self.delete_calls.append(key)


_FakeWinreg.OpenKey = _FakeWinreg.open_key
_FakeWinreg.EnumValue = _FakeWinreg.enum_value
_FakeWinreg.SetValueEx = _FakeWinreg.set_value_ex
_FakeWinreg.DeleteValue = _FakeWinreg.delete_value


def test_windows_registry_provider_winreg_guard_raises_when_missing(monkeypatch):
    monkeypatch.setattr(providers, "winreg", None)

    with pytest.raises(RuntimeError):
        providers.WindowsRegistryProvider._winreg()


def test_windows_registry_provider_machine_scope_paths(monkeypatch):
    fake = _FakeWinreg()
    monkeypatch.setattr(providers, "winreg", fake)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    provider = providers.WindowsRegistryProvider()

    rows = provider.list_scope(provider.MACHINE_SCOPE)
    provider.set_scope_value(provider.MACHINE_SCOPE, "APP_HOME", "%ProgramFiles%\\EnvInspector")
    provider.remove_scope_value(provider.MACHINE_SCOPE, "APP_HOME")

    ensure(rows == {"A": "1"})
    ensure(any(call[3] & fake.KEY_WOW64_64KEY for call in fake.open_calls))
    ensure(fake.set_calls == [("APP_HOME", fake.REG_EXPAND_SZ, "%ProgramFiles%\\EnvInspector")])
    ensure(fake.delete_calls == ["APP_HOME"])


def test_windows_registry_provider_remove_missing_value_is_ignored(monkeypatch):
    fake = _FakeWinreg()
    fake.raise_delete_missing = True

    monkeypatch.setattr(providers, "winreg", fake)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    provider = providers.WindowsRegistryProvider()
    provider.remove_scope_value(provider.MACHINE_SCOPE, "MISSING")

    ensure(len(fake.open_calls) == 1)
