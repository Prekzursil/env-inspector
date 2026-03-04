from __future__ import absolute_import, division

import json

from env_inspector_core.cli import build_parser, run_cli


class FakeService:
    def __init__(self):
        self.last_set: dict | None = None
        self.last_remove: dict | None = None

    def list_records(self, **kwargs):
        return [
            {
                "name": "API_TOKEN",
                "value": "abc123",
                "source_type": "windows_user",
                "context": "windows",
                "is_secret": True,
            }
        ]

    def export_records(self, **kwargs):
        return "name,value\\nAPI_TOKEN,abc***123\\n"

    def set_key(self, **kwargs):
        self.last_set = kwargs
        return {"success": True, "operation_id": "op-set"}

    def remove_key(self, **kwargs):
        self.last_remove = kwargs
        return {"success": True, "operation_id": "op-remove"}

    def list_backups(self, **kwargs):
        return ["/workspace/backup1"]

    def restore_backup(self, **kwargs):
        return {"success": True, "operation_id": "op-restore"}


def test_parser_has_expected_subcommands():
    parser = build_parser()
    help_text = parser.format_help()
    assert "list" in help_text
    assert "set" in help_text
    assert "remove" in help_text
    assert "export" in help_text
    assert "backup" in help_text
    assert "restore" in help_text


def test_run_cli_list_json_contract(capsys):
    code = run_cli(["list", "--output", "json"], service=FakeService())
    assert code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload[0]["name"] == "API_TOKEN"


def test_run_cli_set_and_remove(capsys):
    set_code = run_cli(["set", "--key", "A", "--value", "1", "--target", "windows:user"], service=FakeService())
    remove_code = run_cli(["remove", "--key", "A", "--target", "windows:user"], service=FakeService())
    assert set_code == 0
    assert remove_code == 0
    out = capsys.readouterr().out
    assert "op-set" in out
    assert "op-remove" in out


def test_run_cli_set_and_remove_forward_scope_roots():
    svc = FakeService()

    run_cli(
        [
            "set",
            "--key",
            "A",
            "--value",
            "1",
            "--target",
            "dotenv:/workspace/.env",
            "--root",
            "/workspace",
            "--root",
            "/var/workspace",
        ],
        service=svc,
    )
    run_cli(
        [
            "remove",
            "--key",
            "A",
            "--target",
            "dotenv:/workspace/.env",
            "--root",
            "/workspace",
        ],
        service=svc,
    )

    assert svc.last_set is not None
    assert svc.last_set["scope_roots"] == ["/workspace", "/var/workspace"]
    assert svc.last_remove is not None
    assert svc.last_remove["scope_roots"] == ["/workspace"]


def test_run_cli_export_backup_and_restore(capsys):
    svc = FakeService()

    export_code = run_cli(["export", "--output", "csv"], service=svc)
    backup_code = run_cli(["backup"], service=svc)
    restore_code = run_cli(["restore", "--backup", "/workspace/backup1"], service=svc)

    assert export_code == 0
    assert backup_code == 0
    assert restore_code == 0

    out = capsys.readouterr().out
    assert "API_TOKEN,abc***123" in out
    assert "backup1" in out
    assert "op-restore" in out
