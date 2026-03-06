#!/usr/bin/env python3

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))


def _load_security_helpers():
    from security_helpers import safe_input_file_path_in_workspace, safe_output_path_in_workspace

    return safe_input_file_path_in_workspace, safe_output_path_in_workspace


safe_input_file_path_in_workspace, safe_output_path_in_workspace = _load_security_helpers()


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


def parse_named_path(value: str) -> tuple[str, Path]:
    match = _PAIR_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid input '{value}'. Expected format: name=path")
    name = match.group("name").strip()
    raw_path = match.group("path").strip()
    candidate = safe_input_file_path_in_workspace(raw_path)
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
    text = raw_path.strip().replace("\\", "/")
    if not text:
        return ""

    candidate = Path(text)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve(strict=False).relative_to(Path.cwd().resolve(strict=False))
        except ValueError:
            return candidate.as_posix()

    return candidate.as_posix()


def coverage_sources_from_xml(path: Path) -> set[str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))  # lgtm [py/path-injection]
    except ET.ParseError:
        return set()

    covered_sources: set[str] = set()
    for node in root.findall(".//*[@filename]"):
        filename = _normalize_source_path(node.attrib.get("filename", ""))
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


def coverage_sources_from_lcov(path: Path) -> set[str]:
    covered_sources: set[str] = set()
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


def _find_missing_required_sources(reported_sources: set[str], required_sources: list[str]) -> list[str]:
    missing: list[str] = []
    for required_source in required_sources:
        normalized_required = _normalize_source_path(required_source).rstrip("/")
        if not normalized_required:
            continue
        if any(_matches_required_source(source_path, normalized_required) for source_path in reported_sources):
            continue
        missing.append(normalized_required)
    return missing


def _is_tests_only_report(reported_sources: set[str]) -> bool:
    return bool(reported_sources) and all(
        source_path == "tests" or source_path.startswith("tests/") for source_path in reported_sources
    )


def evaluate(
    stats: list[CoverageStats],
    min_percent: float,
    *,
    required_sources: list[str] | None = None,
    reported_sources: set[str] | None = None,
) -> tuple[str, list[str]]:
    findings: list[str] = []
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

    normalized_sources = reported_sources or set()
    if _is_tests_only_report(normalized_sources):
        findings.append("coverage inputs only reference tests/ paths; first-party sources are missing.")

    for required_source in _find_missing_required_sources(normalized_sources, required_sources or []):
        findings.append(f"missing required source path: {required_source}")

    status = "pass" if not findings else "fail"
    return status, findings


def _render_md(payload: dict) -> str:
    lines = [
        "# Coverage 100 Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Minimum required coverage: `{payload['min_percent']:.2f}%`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Components",
    ]

    for item in payload.get("components", []):
        lines.append(
            f"- `{item['name']}`: `{item['percent']:.2f}%` ({item['covered']}/{item['total']}) from `{item['path']}`"
        )

    if not payload.get("components"):
        lines.append("- None")

    lines.extend(["", "## Covered sources"])
    sources = payload.get("covered_sources") or []
    if sources:
        lines.extend(f"- `{source_path}`" for source_path in sources)
    else:
        lines.append("- None")

    lines.extend(["", "## Findings"])
    findings = payload.get("findings") or []
    if findings:
        lines.extend(f"- {finding}" for finding in findings)
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = _parse_args()

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
        out_json = safe_output_path_in_workspace(args.out_json, "coverage-100/coverage.json")
        out_md = safe_output_path_in_workspace(args.out_md, "coverage-100/coverage.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(_render_md(payload), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"), end="")

    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
