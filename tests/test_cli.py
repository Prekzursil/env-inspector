import argparse
import json
import unittest

import env_inspector_core.cli as cli_mod
from env_inspector_core.cli import build_parser, run_cli


class FakeService:
    def __init__(self):
        self.last_set: dict | None = None
        self.last_remove: dict | None = None
        self.last_preview_set: dict | None = None
        self.last_preview_remove: dict | None = None

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
        return "name,value\nAPI_TOKEN,abc***123\n"

    def preview_set(self, **kwargs):
        self.last_preview_set = kwargs
        return [{"success": True, "operation_id": "op-preview-set"}]

    def preview_remove(self, **kwargs):
        self.last_preview_remove = kwargs
        return [{"success": True, "operation_id": "op-preview-remove"}]

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


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_parser_has_expected_subcommands():
    parser = build_parser()
    help_text = parser.format_help()
    case = _case()
    case.assertIn("list", help_text)
    case.assertIn("set", help_text)
    case.assertIn("remove", help_text)
    case.assertIn("export", help_text)
    case.assertIn("backup", help_text)
    case.assertIn("restore", help_text)


def test_emit_payload_handles_list_and_invalid_payload(capsys):
    case = _case()
    case.assertEqual(cli_mod._emit_payload([{"success": True}, {"success": True}]), 0)
    case.assertEqual(cli_mod._emit_payload([{"success": True}, {"success": False}]), 1)
    case.assertEqual(cli_mod._emit_payload(["not-a-dict"]), 1)
    case.assertEqual(cli_mod._emit_payload("unexpected"), 1)
    out = capsys.readouterr().out
    case.assertIn("unexpected", out)


def test_run_cli_list_json_contract(capsys):
    code = run_cli(["list", "--output", "json"], service=FakeService())
    case = _case()
    case.assertEqual(code, 0)
    out = capsys.readouterr().out
    payload = json.loads(out)
    case.assertEqual(payload[0]["name"], "API_TOKEN")


def test_run_cli_list_non_json_uses_export_records(capsys):
    code = run_cli(["list", "--output", "csv"], service=FakeService())
    case = _case()
    case.assertEqual(code, 0)
    out = capsys.readouterr().out
    case.assertIn("API_TOKEN,abc***123", out)


def test_run_cli_set_and_remove(capsys):
    set_code = run_cli(["set", "--key", "A", "--value", "1", "--target", "windows:user"], service=FakeService())
    remove_code = run_cli(["remove", "--key", "A", "--target", "windows:user"], service=FakeService())
    case = _case()
    case.assertEqual(set_code, 0)
    case.assertEqual(remove_code, 0)
    out = capsys.readouterr().out
    case.assertIn("op-set", out)
    case.assertIn("op-remove", out)


def test_run_cli_preview_set_and_remove(capsys):
    svc = FakeService()
    set_code = run_cli(
        ["set", "--key", "A", "--value", "1", "--target", "windows:user", "--preview-only"],
        service=svc,
    )
    remove_code = run_cli(
        ["remove", "--key", "A", "--target", "windows:user", "--preview-only"],
        service=svc,
    )
    case = _case()
    case.assertEqual(set_code, 0)
    case.assertEqual(remove_code, 0)
    case.assertIsNotNone(svc.last_preview_set)
    case.assertIsNotNone(svc.last_preview_remove)
    out = capsys.readouterr().out
    case.assertIn("op-preview-set", out)
    case.assertIn("op-preview-remove", out)


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

    case = _case()
    case.assertIsNotNone(svc.last_set)
    case.assertEqual(svc.last_set["scope_roots"], ["/workspace", "/var/workspace"])
    case.assertIsNotNone(svc.last_remove)
    case.assertEqual(svc.last_remove["scope_roots"], ["/workspace"])


def test_run_cli_export_backup_and_restore(capsys):
    svc = FakeService()

    export_code = run_cli(["export", "--output", "csv"], service=svc)
    backup_code = run_cli(["backup"], service=svc)
    restore_code = run_cli(["restore", "--backup", "/workspace/backup1"], service=svc)

    case = _case()
    case.assertEqual(export_code, 0)
    case.assertEqual(backup_code, 0)
    case.assertEqual(restore_code, 0)

    out = capsys.readouterr().out
    case.assertIn("API_TOKEN,abc***123", out)
    case.assertIn("backup1", out)
    case.assertIn("op-restore", out)


def test_run_cli_returns_error_for_unknown_command(monkeypatch, capsys):
    class _DummyParser:
        def parse_args(self, _argv):
            return argparse.Namespace(command="unknown")

    monkeypatch.setattr(cli_mod, "build_parser", lambda: _DummyParser())

    rc = cli_mod.run_cli(["unknown"], service=FakeService())

    case = _case()
    case.assertEqual(rc, 2)
    case.assertIn("Unknown command: unknown", capsys.readouterr().err)
