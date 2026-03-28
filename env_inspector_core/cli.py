"""Command-line entrypoints for Env Inspector."""

from __future__ import absolute_import, division
import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .constants import DEFAULT_SCAN_DEPTH
from .service import EnvInspectorService

_SAFE_EXPORT_KEYS = (
    "source_type",
    "source_id",
    "source_path",
    "context",
    "name",
    "value",
    "is_secret",
    "is_persistent",
    "is_mutable",
    "precedence_rank",
    "writable",
    "requires_privilege",
    "last_error",
)


SupportsListRecords = Any


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
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
    p_set.add_argument(
        "--root",
        action="append",
        default=[],
        help="Additional approved root for dotenv targets",
    )
    p_set.add_argument("--preview-only", action="store_true")

    p_remove = sub.add_parser("remove", help="Remove variable")
    p_remove.add_argument("--key", required=True)
    p_remove.add_argument("--target", action="append", required=True)
    p_remove.add_argument(
        "--root",
        action="append",
        default=[],
        help="Additional approved root for dotenv targets",
    )
    p_remove.add_argument("--preview-only", action="store_true")

    p_export = sub.add_parser("export", parents=[common_parent], help="Export records")
    p_export.add_argument("--output", choices=["json", "csv", "table"], default="json")

    p_backup = sub.add_parser("backup", help="List backups")
    p_backup.add_argument("--target", default=None)

    p_restore = sub.add_parser("restore", help="Restore from backup")
    p_restore.add_argument("--backup", required=True)

    return parser


def _is_successful_payload(item: dict) -> bool:
    """Return whether a payload item reports success."""
    return bool(item.get("success", False))


def _list_payload_success(payload: List[object]) -> bool:
    """Return whether every payload item reports success."""
    items = [item for item in payload if isinstance(item, dict)]
    return bool(items) and all(_is_successful_payload(item) for item in items)


def _emit_payload(payload: object) -> int:
    """Emit a JSON payload and return a matching CLI exit code."""
    print(json.dumps(payload, ensure_ascii=True, indent=2))

    if isinstance(payload, dict):
        return 0 if _is_successful_payload(payload) else 1
    if isinstance(payload, list):
        return 0 if _list_payload_success(payload) else 1
    return 1


def _reject_raw_secret_stdout(args: argparse.Namespace) -> None:
    """Reject raw-secret output for stdout renderers."""
    if args.include_raw_secrets:
        raise ValueError(
            "--include-raw-secrets is not supported for stdout-rendered CLI output."
        )


def _sanitize_stdout_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Mask secret values before writing rows to stdout."""
    safe_row: Dict[str, Any] = {}
    for key in _SAFE_EXPORT_KEYS:
        if key == "value":
            safe_row[key] = (
                "[secret masked]" if row.get("is_secret") else row.get("value", "")
            )
            continue
        safe_row[key] = row.get(key)
    return safe_row


def _stdout_safe_rows(
    service: SupportsListRecords, args: argparse.Namespace
) -> List[Dict[str, Any]]:
    """Collect rows that are safe to emit directly to stdout."""
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
        safe_rows.append(_sanitize_stdout_row(row))
    return safe_rows


def _emit_stdout_rows(rows: List[Dict[str, Any]], *, output: str) -> None:
    """Emit rows in the requested stdout format."""
    if output == "json":
        sys.stdout.write(json.dumps(rows, ensure_ascii=True, indent=2))
        return
    if output == "csv":
        if not rows:
            return
        keys = sorted(rows[0].keys())
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
        sys.stdout.write(buffer.getvalue())
        return

    lines = [
        f"{row['context']}\t{row['source_type']}\t{row['name']}\t{row['value']}"
        for row in rows
    ]
    if lines:
        sys.stdout.write("\n".join(lines) + "\n")


def _list_records(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """List records through the CLI."""
    _reject_raw_secret_stdout(args)
    _emit_stdout_rows(_stdout_safe_rows(service, args), output=args.output)
    return 0


def _export_records(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """Export records through the CLI."""
    _reject_raw_secret_stdout(args)
    _emit_stdout_rows(_stdout_safe_rows(service, args), output=args.output)
    return 0


def _set_key(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """Set a key through the CLI."""
    if args.preview_only:
        return _emit_payload(
            service.preview_set(
                key=args.key,
                value=args.value,
                targets=args.target,
                scope_roots=args.root,
            )
        )
    return _emit_payload(
        service.set_key(
            key=args.key,
            value=args.value,
            targets=args.target,
            scope_roots=args.root,
        )
    )


def _remove_key(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """Remove a key through the CLI."""
    if args.preview_only:
        return _emit_payload(
            service.preview_remove(
                key=args.key,
                targets=args.target,
                scope_roots=args.root,
            )
        )
    return _emit_payload(
        service.remove_key(
            key=args.key,
            targets=args.target,
            scope_roots=args.root,
        )
    )


def _list_backups(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """List available backups through the CLI."""
    print(
        json.dumps(
            service.list_backups(target=args.target),
            ensure_ascii=True,
            indent=2,
        )
    )
    return 0


def _restore_backup(service: EnvInspectorService, args: argparse.Namespace) -> int:
    """Restore a backup through the CLI."""
    payload = service.restore_backup(backup=args.backup)
    return _emit_payload(payload)


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    service: EnvInspectorService | None = None,
) -> int:
    """Run the Env Inspector CLI."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help()
        return 0

    active_service = service or EnvInspectorService()
    handlers = {
        "list": _list_records,
        "set": _set_key,
        "remove": _remove_key,
        "export": _export_records,
        "backup": _list_backups,
        "restore": _restore_backup,
    }
    handler = handlers.get(args.command)
    exit_code = 2
    if handler is None:
        print(f"Unknown command: {args.command}", file=sys.stderr)
    else:
        try:
            exit_code = handler(active_service, args)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
    return exit_code
