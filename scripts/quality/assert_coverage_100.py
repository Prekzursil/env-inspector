#!/usr/bin/env python3

import argparse
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if os.path.exists(_SCRIPT_DIR / "security_helpers.py") else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))


def _load_security_helpers():
    from security_helpers import (
        safe_input_file_path_in_workspace as _safe_input_helper,
        safe_output_path_in_workspace as _safe_output_helper,
    )

    return _safe_input_helper, _safe_output_helper


SAFE_INPUT_FILE_PATH_IN_WORKSPACE, SAFE_OUTPUT_PATH_IN_WORKSPACE = _load_security_helpers()


@dataclass
class CoverageStats:
    name: str
    path: str
    covered: int
    total: int

    @property
    def percent(self) -> float:
        if self.total <= 0:
            return 100.0
        return (self.covered / self.total) * 100.0


_PAIR_RE = re.compile(r"^(?P<name>[^=]+)=(?P<path>.+)$")
_XML_LINES_VALID_RE = re.compile(r'lines-valid="(\d+(?:\.\d+)?)"')
_XML_LINES_COVERED_RE = re.compile(r'lines-covered="(\d+(?:\.\d+)?)"')
_XML_LINE_HITS_RE = re.compile(r"<line\b[^>]*\bhits=\"(\d+(?:\.\d+)?)\"")
_XML_FILENAME_RE = re.compile(r"""<[^>]+\bfilename=(?P<quote>["'])(?P<value>.*?)(?P=quote)""")
_NONE_LIST_ITEM = "- None"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert minimum coverage for all declared components.")
    parser.add_argument("--xml", action="append", default=[], help="Coverage XML input: name=path")
    parser.add_argument("--lcov", action="append", default=[], help="LCOV input: name=path")
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
    parser.add_argument("--out-json", default="coverage-100/coverage.json", help="Output JSON path")
    parser.add_argument("--out-md", default="coverage-100/coverage.md", help="Output markdown path")
    return parser.parse_args()


def parse_named_path(value: str) -> Tuple[str, Path]:
    match = _PAIR_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid input '{value}'. Expected format: name=path")
    name = match.group("name").strip()
    raw_path = match.group("path").strip()
    candidate = SAFE_INPUT_FILE_PATH_IN_WORKSPACE(raw_path)
    return name, candidate


def parse_coverage_xml(name: str, path: Path) -> CoverageStats:
    text = path.read_text(encoding="utf-8")  # lgtm [py/path-injection]
    lines_valid_match = _XML_LINES_VALID_RE.search(text)
    lines_covered_match = _XML_LINES_COVERED_RE.search(text)

    if lines_valid_match and lines_covered_match:
        total = int(float(lines_valid_match.group(1)))
        covered = int(float(lines_covered_match.group(1)))
        return CoverageStats(name=name, path=str(path), covered=covered, total=total)

    total = 0
    covered = 0
    for hits_raw in _XML_LINE_HITS_RE.findall(text):
        total += 1
        if int(float(hits_raw)) > 0:
            covered += 1

    return CoverageStats(name=name, path=str(path), covered=covered, total=total)


def _normalize_source_path(raw_path: str) -> str:
    text = posixpath.normpath(raw_path.strip().replace("\\", "/"))
    if not text:
        return ""
    if text == ".":
        return ""

    workspace_root = posixpath.normpath(Path.cwd().resolve(strict=False).as_posix())
    if text == workspace_root:
        return ""
    if text.startswith(f"{workspace_root}/"):
        return text[len(workspace_root) + 1 :]
    return text


def coverage_sources_from_xml(path: Path) -> Set[str]:
    text = path.read_text(encoding="utf-8")  # lgtm [py/path-injection]
    covered_sources: Set[str] = set()
    for match in _XML_FILENAME_RE.finditer(text):
        filename = _normalize_source_path(match.group("value"))
        if filename:
            covered_sources.add(filename)
    return covered_sources


def parse_lcov(name: str, path: Path) -> CoverageStats:
    total = 0
    covered = 0

    for raw in path.read_text(encoding="utf-8").splitlines():  # lgtm [py/path-injection]
        line = raw.strip()
        if line.startswith("LF:"):
            total += int(line.split(":", 1)[1])
        elif line.startswith("LH:"):
            covered += int(line.split(":", 1)[1])

    return CoverageStats(name=name, path=str(path), covered=covered, total=total)


def coverage_sources_from_lcov(path: Path) -> Set[str]:
    covered_sources: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():  # lgtm [py/path-injection]
        line = raw.strip()
        if not line.startswith("SF:"):
            continue
        filename = _normalize_source_path(line.split(":", 1)[1])
        if filename:
            covered_sources.add(filename)
    return covered_sources


def _matches_required_source(source_path: str, required_source: str) -> bool:
    normalized_required = _normalize_source_path(required_source).rstrip("/")
    if not normalized_required:
        return False
    return source_path == normalized_required or source_path.startswith(f"{normalized_required}/")


def _find_missing_required_sources(reported_sources: Set[str], required_sources: List[str]) -> List[str]:
    missing: List[str] = []
    for required_source in required_sources:
        normalized_required = _normalize_source_path(required_source).rstrip("/")
        if not normalized_required:
            continue
        if any(_matches_required_source(source_path, normalized_required) for source_path in reported_sources):
            continue
        missing.append(normalized_required)
    return missing


def _is_tests_only_report(reported_sources: Set[str]) -> bool:
    return bool(reported_sources) and all(
        source_path == "tests" or source_path.startswith("tests/") for source_path in reported_sources
    )


def _coverage_findings(stats: List[CoverageStats], min_percent: float) -> List[str]:
    findings: List[str] = []
    for item in stats:
        if item.percent < min_percent:
            findings.append(
                f"{item.name} coverage below {min_percent:.2f}%: {item.percent:.2f}% ({item.covered}/{item.total})"
            )

    combined_total = sum(item.total for item in stats)
    combined_covered = sum(item.covered for item in stats)
    combined = 100.0 if combined_total <= 0 else (combined_covered / combined_total) * 100.0
    if combined < min_percent:
        findings.append(
            f"combined coverage below {min_percent:.2f}%: {combined:.2f}% ({combined_covered}/{combined_total})"
        )
    return findings


def _source_findings(reported_sources: Set[str], required_sources: List[str]) -> List[str]:
    findings: List[str] = []
    if _is_tests_only_report(reported_sources):
        findings.append("coverage inputs only reference tests/ paths; first-party sources are missing.")

    for required_source in _find_missing_required_sources(reported_sources, required_sources):
        findings.append(f"missing required source path: {required_source}")
    return findings


def evaluate(
    stats: List[CoverageStats],
    min_percent: float,
    *,
    required_sources: Optional[List[str]] = None,
    reported_sources: Optional[Set[str]] = None,
) -> Tuple[str, List[str]]:
    normalized_sources = reported_sources or set()
    findings = _coverage_findings(stats, min_percent)
    findings.extend(_source_findings(normalized_sources, required_sources or []))
    status = "pass" if not findings else "fail"
    return status, findings


def _append_component_lines(lines: List[str], payload: Dict[str, Any]) -> None:
    components = payload.get("components") or []
    if components:
        for item in components:
            lines.append(
                f"- `{item['name']}`: `{item['percent']:.2f}%` ({item['covered']}/{item['total']}) from `{item['path']}`"
            )
        return
    lines.append(_NONE_LIST_ITEM)


def _append_covered_source_lines(lines: List[str], payload: Dict[str, Any]) -> None:
    sources = payload.get("covered_sources") or []
    if sources:
        lines.extend(f"- `{source_path}`" for source_path in sources)
        return
    lines.append(_NONE_LIST_ITEM)


def _append_finding_lines(lines: List[str], payload: Dict[str, Any]) -> None:
    findings = payload.get("findings") or []
    if findings:
        lines.extend(f"- {finding}" for finding in findings)
        return
    lines.append(_NONE_LIST_ITEM)


def _render_md(payload: Dict[str, Any]) -> str:
    lines = [
        "# Coverage 100 Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Minimum required coverage: `{payload['min_percent']:.2f}%`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Components",
    ]
    _append_component_lines(lines, payload)

    lines.extend(["", "## Covered sources"])
    _append_covered_source_lines(lines, payload)

    lines.extend(["", "## Findings"])
    _append_finding_lines(lines, payload)

    return "\n".join(lines) + "\n"


def main() -> int:
    args = _parse_args()

    stats: List[CoverageStats] = []
    covered_sources: Set[str] = set()
    for item in args.xml:
        name, path = parse_named_path(item)
        stats.append(parse_coverage_xml(name, path))
        covered_sources.update(coverage_sources_from_xml(path))
    for item in args.lcov:
        name, path = parse_named_path(item)
        stats.append(parse_lcov(name, path))
        covered_sources.update(coverage_sources_from_lcov(path))

    if not stats:
        raise SystemExit("No coverage files were provided; pass --xml and/or --lcov inputs.")

    min_percent = max(0.0, min(100.0, float(args.min_percent)))
    status, findings = evaluate(
        stats,
        min_percent,
        required_sources=list(args.require_source),
        reported_sources=covered_sources,
    )
    payload = {
        "status": status,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "min_percent": min_percent,
        "components": [
            {
                "name": item.name,
                "path": item.path,
                "covered": item.covered,
                "total": item.total,
                "percent": item.percent,
            }
            for item in stats
        ],
        "covered_sources": sorted(covered_sources),
        "findings": findings,
    }

    try:
        out_json = SAFE_OUTPUT_PATH_IN_WORKSPACE(args.out_json, "coverage-100/coverage.json")
        out_md = SAFE_OUTPUT_PATH_IN_WORKSPACE(args.out_md, "coverage-100/coverage.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    os.makedirs(out_json.parent, exist_ok=True)
    os.makedirs(out_md.parent, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    rendered = _render_md(payload)
    with open(out_md, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(rendered, end="")

    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
