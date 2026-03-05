from __future__ import division

from pathlib import Path
import unittest

import env_inspector


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_main_print_secrets_rejects_invalid_root(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path.parent

    monkeypatch.chdir(workspace)

    class _ForbiddenService:
        def __init__(self, *args, **kwargs):  # pragma: no cover - should not be reached
            raise AssertionError("EnvInspectorService should not be created for invalid --root")

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _ForbiddenService)
    monkeypatch.setattr(
        env_inspector.sys,
        "argv",
        ["env_inspector.py", "--print-secrets", "--root", str(outside)],
    )

    code = env_inspector.main()

    case = _case()
    case.assertEqual(code, 2)
    err = capsys.readouterr().err
    case.assertIn("Invalid --root", err)


def test_legacy_print_secrets_revalidates_root_before_list_records(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path.parent.resolve()

    monkeypatch.chdir(workspace)
    monkeypatch.setattr(env_inspector, "resolve_scan_root", lambda _root: outside)

    class _ForbiddenService:
        def __init__(self, *args, **kwargs):  # pragma: no cover - should not be reached
            raise AssertionError("EnvInspectorService should not be created for revalidation failure")

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _ForbiddenService)

    code = env_inspector._legacy_print_secrets(str(workspace))

    case = _case()
    case.assertEqual(code, 2)
    err = capsys.readouterr().err
    case.assertIn("Invalid --root", err)


def test_legacy_print_secrets_uses_workspace_root_for_listing(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.chdir(workspace)

    captured = {}

    def _list_records(**kwargs):
        captured.update(kwargs)
        return [{"is_secret": True, "source_type": "dotenv", "source_id": ".env", "name": "API_TOKEN"}]

    class _Service:
        list_records = staticmethod(_list_records)

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _Service)

    code = env_inspector._legacy_print_secrets(str(workspace))

    case = _case()
    case.assertEqual(code, 0)
    case.assertTrue(captured["include_raw_secrets"] is True)
    case.assertEqual(Path(str(captured["root"])), workspace.resolve())
    out = capsys.readouterr().out
    case.assertIn("API_TOKEN", out)


def test_legacy_print_secrets_rejects_nested_subdirectory_root(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    nested = workspace / "nested"
    nested.mkdir(parents=True)

    monkeypatch.chdir(workspace)

    class _ForbiddenService:
        def __init__(self, *args, **kwargs):  # pragma: no cover - should not be reached
            raise AssertionError("EnvInspectorService should not be created for unsupported nested root")

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _ForbiddenService)

    code = env_inspector._legacy_print_secrets(str(nested))

    case = _case()
    case.assertEqual(code, 2)
    err = capsys.readouterr().err
    case.assertIn("Legacy --print-secrets only supports the current working directory.", err)
