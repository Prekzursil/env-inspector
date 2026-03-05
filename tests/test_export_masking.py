from __future__ import absolute_import, division
from pathlib import Path

from env_inspector_core.service import EnvInspectorService

from tests.assertions import ensure

def test_export_masks_secrets_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=supersecretvalue\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    csv_text = svc.export_records(
        output="csv",
        include_raw_secrets=False,
        root=tmp_path,
        context=svc.runtime_context,
    )
    ensure("supersecretvalue" not in csv_text)

def test_export_can_include_raw_secrets_when_opted_in(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_TOKEN=supersecretvalue\n", encoding="utf-8")

    svc = EnvInspectorService(state_dir=tmp_path / "state")
    csv_text = svc.export_records(
        output="csv",
        include_raw_secrets=True,
        root=tmp_path,
        context=svc.runtime_context,
    )
    ensure("supersecretvalue" in csv_text)
