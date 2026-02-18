from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

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
    p_set.add_argument("--preview-only", action="store_true")

    p_remove = sub.add_parser("remove", help="Remove variable")
    p_remove.add_argument("--key", required=True)
    p_remove.add_argument("--target", action="append", required=True)
    p_remove.add_argument("--preview-only", action="store_true")

    p_export = sub.add_parser("export", parents=[common_parent], help="Export records")
    p_export.add_argument("--output", choices=["json", "csv", "table"], default="json")

    p_backup = sub.add_parser("backup", help="List backups")
    p_backup.add_argument("--target", default=None)

    p_restore = sub.add_parser("restore", help="Restore from backup")
    p_restore.add_argument("--backup", required=True)

    return parser


def run_cli(argv: Sequence[str] | None = None, *, service: EnvInspectorService | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0

    service = service or EnvInspectorService()

    if args.command == "list":
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
            print(json.dumps(rows, ensure_ascii=True, indent=2))
        elif args.output == "csv":
            print(service.export_records(output="csv", include_raw_secrets=args.include_raw_secrets, root=args.root, context=args.context, source=args.source, wsl_path=args.wsl_path, distro=args.distro, scan_depth=args.scan_depth), end="")
        else:
            print(service.export_records(output="table", include_raw_secrets=args.include_raw_secrets, root=args.root, context=args.context, source=args.source, wsl_path=args.wsl_path, distro=args.distro, scan_depth=args.scan_depth), end="")
        return 0

    if args.command == "set":
        payload = service.preview_set(key=args.key, value=args.value, targets=args.target) if args.preview_only else service.set_key(
            key=args.key,
            value=args.value,
            targets=args.target,
        )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        success = payload.get("success", True) if isinstance(payload, dict) else all(x.get("success", False) for x in payload)
        return 0 if success else 1

    if args.command == "remove":
        payload = service.preview_remove(key=args.key, targets=args.target) if args.preview_only else service.remove_key(
            key=args.key,
            targets=args.target,
        )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        success = payload.get("success", True) if isinstance(payload, dict) else all(x.get("success", False) for x in payload)
        return 0 if success else 1

    if args.command == "export":
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

    if args.command == "backup":
        print(json.dumps(service.list_backups(target=args.target), ensure_ascii=True, indent=2))
        return 0

    if args.command == "restore":
        payload = service.restore_backup(backup=args.backup)
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0 if payload.get("success") else 1

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 2
