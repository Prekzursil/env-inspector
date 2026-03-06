from __future__ import absolute_import, division

import argparse
import json
import unittest
from types import SimpleNamespace
from typing import Any, cast

import env_inspector_core.cli as cli_mod
from env_inspector_core.cli import build_parser, run_cli
from env_inspector_core.service import EnvInspectorService


class FakeService:
    def __init__(self) -> None:
        self.last_set: dict | None = None
        self.last_remove: dict | None = None
        self.last_preview_set: dict | None = None
        self.last_preview_remove: dict | None = None
        self.last_list: dict | None = None

    def list_records(self, **kwargs):
        self.last_list = kwargs
        secret_flag = bool(1)
        return [
            {
                "name": "API_TOKEN",
                "value": "fixture-value",
                "source_type": "windows_user",
                "source_id": "windows:user",
                "source_path": "registry://HKCU/Environment",
                "context": "windows",
                "is_secret": secret_flag,
                "is_persistent": True,
                "is_mutable": True,
                "precedence_rank": 10,
                "writable": True,
                "requires_privilege": False,
                "last_error": None,
            }
        ]

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
    svc = FakeService()
    code = run_cli(["list", "--output", "json"], service=svc)
    case = _case()
    case.assertEqual(code, 0)
    last_list = cast(dict[str, object], svc.last_list)
    case.assertIsNotNone(last_list)
    case.assertIs(last_list["include_raw_secrets"], False)
    out = capsys.readouterr().out
    payload = json.loads(out)
    case.assertEqual(payload[0]["name"], "API_TOKEN")
    case.assertEqual(payload[0]["value"], "[secret masked]")


def test_run_cli_list_non_json_uses_export_records(capsys):
    svc = FakeService()
    code = run_cli(["list", "--output", "csv"], service=svc)
    case = _case()
    case.assertEqual(code, 0)
    case.assertIsNotNone(svc.last_list)
    case.assertIs(svc.last_list["include_raw_secrets"], False)
    out = capsys.readouterr().out
    case.assertIn("API_TOKEN", out)
    case.assertIn("[secret masked]", out)


def test_stdout_safe_rows_projects_only_exportable_fields():
    svc = FakeService()
    args = SimpleNamespace(
        root="/workspace",
        context=None,
        source=[],
        wsl_path=None,
        distro=None,
        scan_depth=3,
    )
    rows = svc.list_records(
        root=args.root,
        context=args.context,
        source=args.source,
        wsl_path=args.wsl_path,
        distro=args.distro,
        scan_depth=args.scan_depth,
        include_raw_secrets=False,
    )
    rows[0]["debug_marker"] = "fixture-extra"

    def _list_records(**_kwargs):
        return rows

    typed_service = cast(EnvInspectorService, svc)
    cast(Any, typed_service).list_records = _list_records

    safe_rows = cli_mod._stdout_safe_rows(typed_service, args)

    case = _case()
    case.assertEqual(safe_rows[0]["value"], "[secret masked]")
    case.assertNotIn("debug_marker", safe_rows[0])
    case.assertEqual(set(safe_rows[0]), set(cli_mod._SAFE_EXPORT_KEYS))


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
    case.assertIsNotNone(svc.last_list)
    case.assertIs(svc.last_list["include_raw_secrets"], False)

    out = capsys.readouterr().out
    case.assertIn("API_TOKEN", out)
    case.assertIn("[secret masked]", out)
    case.assertIn("backup1", out)
    case.assertIn("op-restore", out)


def test_run_cli_returns_error_for_unknown_command(monkeypatch, capsys):
    dummy_parser = type("DummyParser", (), {})()

    def _parse_unknown(_argv):
        return argparse.Namespace(command="unknown")

    setattr(dummy_parser, "parse_args", _parse_unknown)

    def _build_dummy_parser():
        return dummy_parser

    monkeypatch.setattr(cli_mod, "build_parser", _build_dummy_parser)

    rc = cli_mod.run_cli(["unknown"], service=FakeService())

    case = _case()
    case.assertEqual(rc, 2)
    case.assertIn("Unknown command: unknown", capsys.readouterr().err)


def test_run_cli_rejects_raw_secret_stdout_for_list_and_export(capsys):
    svc = FakeService()

    list_code = run_cli(["list", "--include-raw-secrets"], service=svc)
    export_code = run_cli(["export", "--include-raw-secrets"], service=svc)

    case = _case()
    case.assertEqual(list_code, 2)
    case.assertEqual(export_code, 2)
    case.assertIsNone(svc.last_list)
    err = capsys.readouterr().err
    case.assertIn("--include-raw-secrets is not supported", err)
