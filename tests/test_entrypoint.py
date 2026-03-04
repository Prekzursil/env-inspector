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


def test_main_print_secrets_uses_validated_root_without_forwarding_raw_path(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secrets_root = workspace / "inner"
    secrets_root.mkdir()

    monkeypatch.chdir(workspace)

    captured: dict[str, object] = {"kwargs": None}

    class _Service:
        def list_records(self, **kwargs):
            captured["kwargs"] = kwargs
            return []

    monkeypatch.setattr(env_inspector, "EnvInspectorService", _Service)
    monkeypatch.setattr(
        env_inspector.sys,
        "argv",
        ["env_inspector.py", "--print-secrets", "--root", str(secrets_root)],
    )

    original_cwd = Path.cwd()
    code = env_inspector.main()

    assert code == 0
    assert captured["kwargs"] == {"include_raw_secrets": True}
    assert Path.cwd() == original_cwd
