from __future__ import absolute_import, division

from pathlib import Path

import env_inspector

def _expect(condition, message: str = "") -> None:
    if not condition: raise AssertionError(message)



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

    _expect(code == 2)

    err = capsys.readouterr().err
    _expect("Invalid --root" in err)
