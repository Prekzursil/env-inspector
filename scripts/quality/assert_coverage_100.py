"""Assert coverage 100 module."""
#!/usr/bin/env python3

import argparse
import importlib
import sys
from pathlib import Path
from typing import List, Set, Tuple

from scripts.quality import _coverage_assert_support as _support
from scripts.quality._coverage_assert_support import (
    CoverageStats,
    _build_payload,
    _write_outputs,
    coverage_sources_from_lcov,
    coverage_sources_from_xml,
    evaluate,
    parse_coverage_xml,
    parse_lcov,
)
from scripts.quality._coverage_assert_support import (
    parse_named_path as parse_named_path_impl,
)

_matches_required_source = _support._matches_required_source
_normalize_source_path = _support._normalize_source_path
_render_md = _support._render_md
normalize_source_path = _support.normalize_source_path
posixpath = _support.posixpath


def _load_security_helpers():
    """Load security helpers."""
    try:
        security_imports = importlib.import_module("scripts.quality._security_imports")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        security_imports = importlib.import_module("_security_imports")

    return (
        security_imports.safe_input_file_path_in_workspace,
        security_imports.safe_output_path_in_workspace,
    )


SAFE_INPUT_FILE_PATH_IN_WORKSPACE, SAFE_OUTPUT_PATH_IN_WORKSPACE = (
    _load_security_helpers()
)


def _parse_args() -> argparse.Namespace:
    """Parse args."""
    parser = argparse.ArgumentParser(
        description="Assert minimum coverage for all declared components."
    )
    parser.add_argument(
        "--xml", action="append", default=[], help="Coverage XML input: name=path"
    )
    parser.add_argument(
        "--lcov", action="append", default=[], help="LCOV input: name=path"
    )
    parser.add_argument(
        "--require-source",
        action="append",
        default=[],
        help="Workspace-relative file or directory that must appear in the coverage inputs.",
    )
    parser.add_argument(
        "--min-percent",
        type=float,
        default=100.0,
        help="Minimum required coverage percentage for each component and combined summary.",
    )
    parser.add_argument(
        "--out-json", default="coverage-100/coverage.json", help="Output JSON path"
    )
    parser.add_argument(
        "--out-md", default="coverage-100/coverage.md", help="Output markdown path"
    )
    return parser.parse_args()


def parse_named_path(value: str):
    """Parse named path."""
    return parse_named_path_impl(value, SAFE_INPUT_FILE_PATH_IN_WORKSPACE)


def _collect_stats(args: argparse.Namespace) -> tuple[list[CoverageStats], set[str]]:
    """Collect stats."""
    stats: list[CoverageStats] = []
    covered_sources: set[str] = set()
    for item in args.xml:
        name, path = parse_named_path(item)
        stats.append(parse_coverage_xml(name, path))
        covered_sources.update(coverage_sources_from_xml(path))
    for item in args.lcov:
        name, path = parse_named_path(item)
        stats.append(parse_lcov(name, path))
        covered_sources.update(coverage_sources_from_lcov(path))
    return stats, covered_sources


def main() -> int:
    """Main."""
    args = _parse_args()
    stats, covered_sources = _collect_stats(args)

    if not stats:
        raise SystemExit(
            "No coverage files were provided; pass --xml and/or --lcov inputs."
        )

    min_percent = max(0.0, min(100.0, float(args.min_percent)))
    status, findings = evaluate(
        stats,
        min_percent,
        required_sources=list(args.require_source),
        reported_sources=covered_sources,
    )
    payload = _build_payload(stats, covered_sources, min_percent, findings, status)

    try:
        out_json = SAFE_OUTPUT_PATH_IN_WORKSPACE(
            args.out_json, "coverage-100/coverage.json"
        )
        out_md = SAFE_OUTPUT_PATH_IN_WORKSPACE(args.out_md, "coverage-100/coverage.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    _write_outputs(payload, out_json=out_json, out_md=out_md)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
