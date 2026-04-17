#!/usr/bin/env python3
"""Env Inspector entrypoint.

- CLI mode: `list/set/remove/export/backup/restore`
- GUI mode: launched when no subcommand is provided
"""

import argparse
import os
import sys
from pathlib import Path
from typing import List

from env_inspector_core.cli import run_cli
from env_inspector_core.path_policy import PathPolicyError, resolve_scan_root
from env_inspector_core.service import EnvInspectorService
from env_inspector_gui import EnvInspectorApp

CLI_COMMANDS = {"list", "set", "remove", "export", "backup", "restore"}


def _resolve_legacy_print_secrets_root(root: str | Path) -> Path:
    """Resolve legacy print secrets root."""
    workspace_root = resolve_scan_root(Path.cwd())
    requested = resolve_scan_root(root)
    if requested != workspace_root:
        raise PathPolicyError(
            "Legacy --print-secrets only supports the current working directory."
        )
    return workspace_root


def _legacy_print_secrets(root: str | Path) -> int:
    """Legacy print secrets."""
    try:
        safe_root = _resolve_legacy_print_secrets_root(root)
    except PathPolicyError as exc:
        print(f"Invalid --root: {exc}", file=sys.stderr)
        return 2

    svc = EnvInspectorService()
    rows = svc.list_records(root=safe_root, include_raw_secrets=True)
    for row in rows:
        if row.get("is_secret"):
            print(f"{row.get('source_type')}:{row.get('source_id')}\t{row.get('name')}")
    return 0


def _parse_gui_args(argv: list[str]) -> argparse.Namespace:
    """Parse gui args."""
    parser = argparse.ArgumentParser(description="Env Inspector GUI")
    parser.add_argument(
        "--root", default=os.getcwd(), help="Root path to scan for .env files"
    )
    parser.add_argument(
        "--print-secrets",
        action="store_true",
        help="Print detected secret keys and exit",
    )
    return parser.parse_args(argv)


def main() -> int:
    """Main."""
    argv = sys.argv[1:]

    if argv and (argv[0] in CLI_COMMANDS or argv[0] in {"-h", "--help"}):
        return run_cli(argv)

    args = _parse_gui_args(argv)
    if args.print_secrets:
        return _legacy_print_secrets(args.root)

    try:
        root = resolve_scan_root(args.root)
    except PathPolicyError as exc:
        print(f"Invalid --root: {exc}", file=sys.stderr)
        return 2

    app = EnvInspectorApp(root)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
