from tests.conftest import ensure
import json
from argparse import Namespace

from env_inspector_core import cli as cli_mod
from env_inspector_core.cli import _command_success, build_parser, run_cli


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
    ensure('list' in help_text)
    ensure('set' in help_text)
    ensure('remove' in help_text)
    ensure('export' in help_text)
    ensure('backup' in help_text)
    ensure('restore' in help_text)


def test_run_cli_list_json_contract(capsys):
    code = run_cli(["list", "--output", "json"], service=FakeService())
    ensure(code == 0)
    out = capsys.readouterr().out
    payload = json.loads(out)
    ensure(payload[0]['name'] == 'API_TOKEN')


def test_run_cli_list_non_json_routes_to_export(capsys):
    code = run_cli(["list", "--output", "table"], service=FakeService())

    ensure(code == 0)
    out = capsys.readouterr().out
    ensure(out == 'name,value\\nAPI_TOKEN,abc***123\\n')


def test_run_cli_set_and_remove(capsys):
    set_code = run_cli(["set", "--key", "A", "--value", "1", "--target", "windows:user"], service=FakeService())
    remove_code = run_cli(["remove", "--key", "A", "--target", "windows:user"], service=FakeService())
    ensure(set_code == 0)
    ensure(remove_code == 0)
    out = capsys.readouterr().out
    ensure('op-set' in out)
    ensure('op-remove' in out)


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

    ensure(svc.last_set is not None)
    ensure(svc.last_set['scope_roots'] == ['/workspace', '/var/workspace'])
    ensure(svc.last_remove is not None)
    ensure(svc.last_remove['scope_roots'] == ['/workspace'])


def test_run_cli_export_backup_and_restore(capsys):
    svc = FakeService()

    export_code = run_cli(["export", "--output", "csv"], service=svc)
    backup_code = run_cli(["backup"], service=svc)
    restore_code = run_cli(["restore", "--backup", "/workspace/backup1"], service=svc)

    ensure(export_code == 0)
    ensure(backup_code == 0)
    ensure(restore_code == 0)

    out = capsys.readouterr().out
    ensure('API_TOKEN,abc***123' in out)
    ensure('backup1' in out)
    ensure('op-restore' in out)


def test_command_success_handles_non_dict_sequences():
    ensure(_command_success([{'success': True}, {'success': True}]) is True)
    ensure(_command_success([{'success': True}, {'success': False}]) is False)


def test_run_cli_without_command_prints_help(monkeypatch):
    parser = build_parser()

    monkeypatch.setattr(parser, "parse_args", lambda _argv=None: Namespace(command=None))
    monkeypatch.setattr(cli_mod, "build_parser", lambda: parser)

    code = run_cli([])

    ensure(code == 0)


def test_run_cli_unknown_command_returns_error(monkeypatch):
    parser = build_parser()

    monkeypatch.setattr(parser, "parse_args", lambda _argv=None: Namespace(command="bogus"))
    monkeypatch.setattr(cli_mod, "build_parser", lambda: parser)

    code = run_cli([])

    ensure(code == 2)
