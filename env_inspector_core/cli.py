from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from .constants import DEFAULT_SCAN_DEPTH
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


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=True, indent=2))


def _command_success(payload: Any) -> bool:
    if isinstance(payload, dict):
        return bool(payload.get("success", True))
    return all(bool(item.get("success", False)) for item in payload)


def _handle_list(args: argparse.Namespace, service: EnvInspectorService) -> int:
    rows = service.list_records(
        root=args.root,
        context=args.context,
        source=args.source,
        wsl_path=args.wsl_path,
        distro=args.distro,
        scan_depth=args.scan_depth,
        include_raw_secrets=args.include_raw_secrets,
    )
    if args.output == "json":
        _print_json(rows)
        return 0

    export_text = service.export_records(
        output=args.output,
        include_raw_secrets=args.include_raw_secrets,
        root=args.root,
        context=args.context,
        source=args.source,
        wsl_path=args.wsl_path,
        distro=args.distro,
        scan_depth=args.scan_depth,
    )
    print(export_text, end="")
    return 0


def _handle_set(args: argparse.Namespace, service: EnvInspectorService) -> int:
    payload = (
        service.preview_set(key=args.key, value=args.value, targets=args.target, scope_roots=args.root)
        if args.preview_only
        else service.set_key(
            key=args.key,
            value=args.value,
            targets=args.target,
            scope_roots=args.root,
        )
    )
    _print_json(payload)
    return 0 if _command_success(payload) else 1


def _handle_remove(args: argparse.Namespace, service: EnvInspectorService) -> int:
    payload = (
        service.preview_remove(key=args.key, targets=args.target, scope_roots=args.root)
        if args.preview_only
        else service.remove_key(
            key=args.key,
            targets=args.target,
            scope_roots=args.root,
        )
    )
    _print_json(payload)
    return 0 if _command_success(payload) else 1


def _handle_export(args: argparse.Namespace, service: EnvInspectorService) -> int:
    print(
        service.export_records(
            output=args.output,
            include_raw_secrets=args.include_raw_secrets,
            root=args.root,
            context=args.context,
            source=args.source,
            wsl_path=args.wsl_path,
            distro=args.distro,
            scan_depth=args.scan_depth,
        ),
        end="",
    )
    return 0


def _handle_backup(args: argparse.Namespace, service: EnvInspectorService) -> int:
    _print_json(service.list_backups(target=args.target))
    return 0


def _handle_restore(args: argparse.Namespace, service: EnvInspectorService) -> int:
    payload = service.restore_backup(backup=args.backup)
    _print_json(payload)
    return 0 if payload.get("success") else 1


def run_cli(argv: Sequence[str] | None = None, *, service: EnvInspectorService | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0

    service = service or EnvInspectorService()

    handlers: dict[str, Callable[[argparse.Namespace, EnvInspectorService], int]] = {
        "list": _handle_list,
        "set": _handle_set,
        "remove": _handle_remove,
        "export": _handle_export,
        "backup": _handle_backup,
        "restore": _handle_restore,
    }
    handler = handlers.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 2
    return handler(args, service)