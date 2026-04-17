"""Coverage assert support module."""

import json
import os
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_PAIR_RE = re.compile(r"^(?P<name>[^=]+)=(?P<path>.+)$")
_XML_LINES_VALID_RE = re.compile(r'lines-valid="(\d+(?:\.\d+)?)"')
_XML_LINES_COVERED_RE = re.compile(r'lines-covered="(\d+(?:\.\d+)?)"')
_XML_LINE_HITS_RE = re.compile(r'<line\b[^>]*\bhits="(\d+(?:\.\d+)?)"')
_XML_FILENAME_RE = re.compile(
    r"""<[^>]+\bfilename=(?P<quote>["'])(?P<value>.*?)(?P=quote)"""
)
_NONE_LIST_ITEM = "- None"


@dataclass
class CoverageStats:
    """Coverage statistics for a single report component."""

    name: str
    path: str
    covered: int
    total: int

    @property
    def percent(self) -> float:
        """Percent."""
        if self.total <= 0:
            return 100.0
        return (self.covered / self.total) * 100.0


def parse_named_path(value: str, safe_input_file_path_in_workspace) -> tuple[str, Path]:
    """Parse named path."""
    match = _PAIR_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid input '{value}'. Expected format: name=path")
    name = match.group("name").strip()
    raw_path = match.group("path").strip()
    candidate = safe_input_file_path_in_workspace(raw_path)
    return name, candidate


def parse_coverage_xml(name: str, path: Path) -> CoverageStats:
    """Parse coverage xml."""
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
    """Normalize source path."""
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


def normalize_source_path(raw_path: str) -> str:
    """Normalize source path."""
    return _normalize_source_path(raw_path)


def coverage_sources_from_xml(path: Path) -> set[str]:
    """Coverage sources from xml."""
    text = path.read_text(encoding="utf-8")  # lgtm [py/path-injection]
    covered_sources: set[str] = set()
    for match in _XML_FILENAME_RE.finditer(text):
        filename = _normalize_source_path(match.group("value"))
        if filename:
            covered_sources.add(filename)
    return covered_sources


def parse_lcov(name: str, path: Path) -> CoverageStats:
    """Parse lcov."""
    total = 0
    covered = 0

    for raw in path.read_text(
        encoding="utf-8"
    ).splitlines():  # lgtm [py/path-injection]
        line = raw.strip()
        if line.startswith("LF:"):
            total += int(line.split(":", 1)[1])
        elif line.startswith("LH:"):
            covered += int(line.split(":", 1)[1])

    return CoverageStats(name=name, path=str(path), covered=covered, total=total)


def coverage_sources_from_lcov(path: Path) -> set[str]:
    """Coverage sources from lcov."""
    covered_sources: set[str] = set()
    for raw in path.read_text(
        encoding="utf-8"
    ).splitlines():  # lgtm [py/path-injection]
        line = raw.strip()
        if not line.startswith("SF:"):
            continue
        filename = _normalize_source_path(line.split(":", 1)[1])
        if filename:
            covered_sources.add(filename)
    return covered_sources


def _matches_required_source(source_path: str, required_source: str) -> bool:
    """Matches required source."""
    normalized_required = _normalize_source_path(required_source).rstrip("/")
    if not normalized_required:
        return False
    return source_path == normalized_required or source_path.startswith(
        f"{normalized_required}/"
    )


def _find_missing_required_sources(
    reported_sources: set[str], required_sources: list[str]
) -> list[str]:
    """Find missing required sources."""
    missing: list[str] = []
    for required_source in required_sources:
        normalized_required = _normalize_source_path(required_source).rstrip("/")
        if not normalized_required:
            continue
        if any(
            _matches_required_source(source_path, normalized_required)
            for source_path in reported_sources
        ):
            continue
        missing.append(normalized_required)
    return missing


def _is_tests_only_report(reported_sources: set[str]) -> bool:
    """Is tests only report."""
    return bool(reported_sources) and all(
        source_path == "tests" or source_path.startswith("tests/")
        for source_path in reported_sources
    )


def _coverage_findings(stats: list[CoverageStats], min_percent: float) -> list[str]:
    """Coverage findings."""
    findings: list[str] = []
    for item in stats:
        if item.percent < min_percent:
            findings.append(
                f"{item.name} coverage below {min_percent:.2f}%: {item.percent:.2f}% ({item.covered}/{item.total})"
            )

    combined_total = sum(item.total for item in stats)
    combined_covered = sum(item.covered for item in stats)
    combined = (
        100.0 if combined_total <= 0 else (combined_covered / combined_total) * 100.0
    )
    if combined < min_percent:
        findings.append(
            f"combined coverage below {min_percent:.2f}%: {combined:.2f}% ({combined_covered}/{combined_total})"
        )
    return findings


def _source_findings(
    reported_sources: set[str], required_sources: list[str]
) -> list[str]:
    """Source findings."""
    findings: list[str] = []
    if _is_tests_only_report(reported_sources):
        findings.append(
            "coverage inputs only reference tests/ paths; first-party sources are missing."
        )

    for required_source in _find_missing_required_sources(
        reported_sources, required_sources
    ):
        findings.append(f"missing required source path: {required_source}")
    return findings


def evaluate(
    stats: list[CoverageStats],
    min_percent: float,
    *,
    required_sources: list[str] | None = None,
    reported_sources: set[str] | None = None,
) -> tuple[str, list[str]]:
    """Evaluate."""
    normalized_sources = reported_sources or set()
    findings = _coverage_findings(stats, min_percent)
    findings.extend(_source_findings(normalized_sources, required_sources or []))
    status = "pass" if not findings else "fail"
    return status, findings


def _append_component_lines(lines: list[str], payload: dict[str, Any]) -> None:
    """Append component lines."""
    components = payload.get("components") or []
    if components:
        for item in components:
            lines.append(
                f"- `{item['name']}`: `{item['percent']:.2f}%` ({item['covered']}/{item['total']}) from `{item['path']}`"
            )
        return
    lines.append(_NONE_LIST_ITEM)


def _append_covered_source_lines(lines: list[str], payload: dict[str, Any]) -> None:
    """Append covered source lines."""
    sources = payload.get("covered_sources") or []
    if sources:
        lines.extend(f"- `{source_path}`" for source_path in sources)
        return
    lines.append(_NONE_LIST_ITEM)


def _append_finding_lines(lines: list[str], payload: dict[str, Any]) -> None:
    """Append finding lines."""
    findings = payload.get("findings") or []
    if findings:
        lines.extend(f"- {finding}" for finding in findings)
        return
    lines.append(_NONE_LIST_ITEM)


def _render_md(payload: dict[str, Any]) -> str:
    """Render md."""
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
    return "`n".replace("`n", "\n").join(lines) + "\n"


def _build_payload(
    stats: list[CoverageStats],
    covered_sources: set[str],
    min_percent: float,
    findings: list[str],
    status: str,
) -> dict[str, Any]:
    """Build payload."""
    return {
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


def _write_outputs(payload: dict[str, Any], *, out_json: Path, out_md: Path) -> str:
    """Write outputs."""
    os.makedirs(out_json.parent, exist_ok=True)
    os.makedirs(out_md.parent, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    rendered = _render_md(payload)
    with open(out_md, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(rendered, end="")
    return rendered
