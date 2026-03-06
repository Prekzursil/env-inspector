from __future__ import absolute_import, division
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .constants import DEFAULT_SCAN_DEPTH
from .rendering import export_rows
from .service import EnvInspectorService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Env Inspector CLI")
    sub = parser.add_subparsers(dest="command")

    common_parent = argparse.ArgumentParser(add_help=False)
    common_parent.add_argument("--context", default=None)
    common_parent.add_argument("--source", action="append", default=[])
    common_parent.add_argument("--root", default=str(Path.cwd()))
    common_parent.add_argument("--wsl-path", default=None)
    common_parent.add_argument("--distro", default=None)
    common_parent.add_argument("--scan-depth", type=int, default=DEFAULT_SCAN_DEPTH)
    common_parent.add_argument("--include-raw-secrets", action="store_true")

    p_list = sub.add_parser("list", parents=[common_parent], help="List records")
    p_list.add_argument("--output", choices=["json", "csv", "table"], default="json")

    p_set = sub.add_parser("set", help="Set variable")
    p_set.add_argument("--key", required=True)
    p_set.add_argument("--value", required=True)
    p_set.add_argument("--target", action="append", required=True)
    p_set.add_argument("--root", action="append", default=[], help="Additional approved root for dotenv targets")
    p_set.add_argument("--preview-only", action="store_true")

    p_remove = sub.add_parser("remove", help="Remove variable")
    p_remove.add_argument("--key", required=True)
    p_remove.add_argument("--target", action="append", required=True)
    p_remove.add_argument("--root", action="append", default=[], help="Additional approved root for dotenv targets")
    p_remove.add_argument("--preview-only", action="store_true")

    p_export = sub.add_parser("export", parents=[common_parent], help="Export records")
    p_export.add_argument("--output", choices=["json", "csv", "table"], default="json")

    p_backup = sub.add_parser("backup", help="List backups")
    p_backup.add_argument("--target", default=None)

    p_restore = sub.add_parser("restore", help="Restore from backup")
    p_restore.add_argument("--backup", required=True)

    return parser


def _is_successful_payload(item: dict) -> bool:
    return bool(item.get("success", False))


def _list_payload_success(payload: List[object]) -> bool:
    items = [item for item in payload if isinstance(item, dict)]
    return bool(items) and all(_is_successful_payload(item) for item in items)


def _emit_payload(payload: object) -> int:
    print(json.dumps(payload, ensure_ascii=True, indent=2))

    if isinstance(payload, dict):
        return 0 if _is_successful_payload(payload) else 1
    if isinstance(payload, list):
        return 0 if _list_payload_success(payload) else 1
    return 1


def _write_rendered_output(rendered: str) -> None:
    sys.stdout.write(rendered)


def _reject_raw_secret_stdout(args: argparse.Namespace) -> None:
    if args.include_raw_secrets:
        raise ValueError("--include-raw-secrets is not supported for stdout-rendered CLI output.")


def _stdout_safe_rows(service: EnvInspectorService, args: argparse.Namespace) -> List[Dict[str, Any]]:
    rows = service.list_records(
        include_raw_secrets=False,
        root=args.root,
        context=args.context,
        source=args.source,
        wsl_path=args.wsl_path,
        distro=args.distro,
        scan_depth=args.scan_depth,
    )
    safe_rows: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if item.get("is_secret"):
            item["value"] = "[secret masked]"
        safe_rows.append(item)
    return safe_rows


def _list_records(service: EnvInspectorService, args: argparse.Namespace) -> None:
    _reject_raw_secret_stdout(args)
    rendered = export_rows(_stdout_safe_rows(service, args), output=args.output)
    _write_rendered_output(rendered)


def _export_records(service: EnvInspectorService, args: argparse.Namespace) -> int:
    _reject_raw_secret_stdout(args)
    rendered = export_rows(_stdout_safe_rows(service, args), output=args.output)
    _write_rendered_output(rendered)
    return 0


def _set_key(service: EnvInspectorService, args: argparse.Namespace) -> int:
    if args.preview_only:
        payload = service.preview_set(key=args.key, value=args.value, targets=args.target, scope_roots=args.root)
    else:
        payload = service.set_key(key=args.key, value=args.value, targets=args.target, scope_roots=args.root)
    return _emit_payload(payload)


def _remove_key(service: EnvInspectorService, args: argparse.Namespace) -> int:
    if args.preview_only:
        payload = service.preview_remove(key=args.key, targets=args.target, scope_roots=args.root)
    else:
        payload = service.remove_key(key=args.key, targets=args.target, scope_roots=args.root)
    return _emit_payload(payload)


def _list_backups(service: EnvInspectorService, args: argparse.Namespace) -> int:
    print(json.dumps(service.list_backups(target=args.target), ensure_ascii=True, indent=2))
    return 0


def _restore_backup(service: EnvInspectorService, args: argparse.Namespace) -> int:
    payload = service.restore_backup(backup=args.backup)
    return _emit_payload(payload)


def run_cli(argv: Sequence[str] | None = None, *, service: EnvInspectorService | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0

    active_service = service or EnvInspectorService()
    if args.command == "list":
        try:
            _list_records(active_service, args)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0

    handlers = {
        "set": _set_key,
        "remove": _remove_key,
        "export": _export_records,
        "backup": _list_backups,
        "restore": _restore_backup,
    }
    handler = handlers.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 2
    try:
        return handler(active_service, args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
