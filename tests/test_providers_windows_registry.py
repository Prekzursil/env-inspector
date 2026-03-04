from __future__ import annotations

from tests.conftest import ensure
import pytest

import env_inspector_core.providers as providers


class _KeyContext:
    def __init__(self, module: "_FakeWinreg") -> None:
        self.module = module

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
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

    def OpenKey(self, root, path: str, _zero: int, access: int):
        self.open_calls.append((root, path, 0, access))
        return _KeyContext(self)

    def EnumValue(self, _regkey, index: int):
        if index >= len(self.enum_rows):
            raise OSError("done")
        return self.enum_rows[index]

    def SetValueEx(self, _regkey, key: str, _zero: int, reg_type: int, value: str) -> None:
        self.set_calls.append((key, reg_type, value))

    def DeleteValue(self, _regkey, key: str) -> None:
        if self.raise_delete_missing:
            raise FileNotFoundError(key)
        self.delete_calls.append(key)


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
    provider.set_scope_value(provider.MACHINE_SCOPE, "PATH", "%SystemRoot%\\Temp")
    provider.remove_scope_value(provider.MACHINE_SCOPE, "PATH")

    ensure(rows == {"A": "1"})
    ensure(any((call[3] & fake.KEY_WOW64_64KEY for call in fake.open_calls)))
    ensure(fake.set_calls == [("PATH", fake.REG_EXPAND_SZ, "%SystemRoot%\\Temp")])
    ensure(fake.delete_calls == ["PATH"])


def test_windows_registry_provider_remove_missing_value_is_ignored(monkeypatch):
    fake = _FakeWinreg()
    fake.raise_delete_missing = True

    monkeypatch.setattr(providers, "winreg", fake)
    monkeypatch.setattr(providers, "is_windows", lambda: True)

    provider = providers.WindowsRegistryProvider()
    provider.remove_scope_value(provider.MACHINE_SCOPE, "MISSING")

    ensure(len(fake.open_calls) == 1)

