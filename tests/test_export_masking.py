from __future__ import absolute_import, division

from pathlib import Path

from env_inspector_core.service import EnvInspectorService

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



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
    _expect("supersecretvalue" not in csv_text)




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
    _expect("supersecretvalue" in csv_text)


def test_expect_helper_raises_on_false():
    raised = False
    try:
        _expect(False, "expected")
    except AssertionError:
        raised = True
    _expect(raised is True)

