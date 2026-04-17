"""Test entrypoint module."""

import unittest
from pathlib import Path
from typing import List

import env_inspector
from env_inspector_core.path_policy import PathPolicyError


def _case() -> unittest.TestCase:
    """Return a tiny unittest helper instance for assertion-style checks."""
    return unittest.TestCase()


def test_main_print_secrets_rejects_invalid_root(tmp_path: Path, monkeypatch, capsys):
    """Main should reject roots outside the current workspace when printing secrets."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path.parent

    monkeypatch.chdir(workspace)

    class _ForbiddenService:
        """Guard service proving invalid roots fail before service construction."""

        def __init__(self, *args, **kwargs):  # pragma: no cover - should not be reached
            """Init."""
            raise AssertionError(
                "EnvInspectorService should not be created for invalid --root"
            )

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


def test_legacy_print_secrets_uses_workspace_root_for_listing(
    tmp_path: Path, monkeypatch, capsys
):
    """Legacy print-secrets should list secrets from the validated workspace root."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.chdir(workspace)

    captured = {}

    def _list_records(**kwargs):
        """List records."""
        secret_flag = bool(1)
        captured.update(kwargs)
        return [
            {
                "is_secret": secret_flag,
                "source_type": "dotenv",
                "source_id": ".env",
                "name": "API_TOKEN",
            }
        ]

    class _Service:
        """Minimal service stub that returns the captured secret rows."""

        list_records = staticmethod(_list_records)

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _Service)

    code = env_inspector._legacy_print_secrets(str(workspace))

    case = _case()
    case.assertEqual(code, 0)
    case.assertTrue(captured["include_raw_secrets"] is True)
    case.assertEqual(Path(str(captured["root"])), workspace.resolve())
    out = capsys.readouterr().out
    case.assertIn("API_TOKEN", out)


def test_legacy_print_secrets_skips_non_secret_rows(
    tmp_path: Path, monkeypatch, capsys
):
    """Legacy print-secrets should not emit rows that are not marked as secrets."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monkeypatch.chdir(workspace)

    def _list_records(**_kwargs):
        """List records."""
        return [
            {
                "is_secret": False,  # nosec B105
                "source_type": "dotenv",
                "source_id": ".env",
                "name": "PUBLIC_VAR",
            }
        ]

    class _Service:
        """Minimal service stub that only yields non-secret rows."""

        list_records = staticmethod(_list_records)

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _Service)

    code = env_inspector._legacy_print_secrets(str(workspace))

    case = _case()
    case.assertEqual(code, 0)
    case.assertEqual(capsys.readouterr().out, "")


def test_legacy_print_secrets_rejects_nested_subdirectory_root(
    tmp_path: Path, monkeypatch, capsys
):
    """Legacy print-secrets should reject nested roots even when they are under the workspace."""
    workspace = tmp_path / "workspace"
    nested = workspace / "nested"
    nested.mkdir(parents=True)

    monkeypatch.chdir(workspace)

    class _ForbiddenService:
        """Guard service proving nested roots fail before service construction."""

        def __init__(self, *args, **kwargs):  # pragma: no cover - should not be reached
            """Init."""
            raise AssertionError(
                "EnvInspectorService should not be created for unsupported nested root"
            )

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _ForbiddenService)

    code = env_inspector._legacy_print_secrets(str(nested))

    case = _case()
    case.assertEqual(code, 2)
    err = capsys.readouterr().err
    case.assertIn(
        "Legacy --print-secrets only supports the current working directory.", err
    )


def test_resolve_legacy_print_secrets_root_does_not_renormalize_validated_root(
    tmp_path: Path, monkeypatch
):
    """Validated roots should round-trip through the legacy resolver without drift."""
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    calls: List[str] = []

    def _validated_root(_value):
        """Return the already validated workspace root for the legacy resolver."""
        calls.append(str(_value))
        return workspace

    monkeypatch.setattr(env_inspector, "resolve_scan_root", _validated_root)

    case = _case()
    case.assertEqual(
        env_inspector._resolve_legacy_print_secrets_root(str(workspace)), workspace
    )
    case.assertEqual(len(calls), 2)


def test_resolve_legacy_print_secrets_root_rejects_missing_directory(
    tmp_path: Path, monkeypatch
):
    """Legacy secret-root resolution should fail when the requested directory is missing."""
    workspace = (tmp_path / "workspace").resolve()
    missing = workspace / "missing"
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    case = _case()
    with case.assertRaises(PathPolicyError) as exc_info:
        env_inspector._resolve_legacy_print_secrets_root(missing)

    case.assertIn("Scan root must exist as a directory", str(exc_info.exception))
