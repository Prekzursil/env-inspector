from __future__ import annotations

from pathlib import Path

import env_inspector


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

    assert code == 2
    err = capsys.readouterr().err
    assert "Invalid --root" in err


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

    assert code == 2
    err = capsys.readouterr().err
    assert "Invalid --root" in err
