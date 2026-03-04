#!/usr/bin/env python3

import argparse
import base64
import json
import os
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import request_json_https, safe_output_path_in_workspace

SONAR_HOST = "sonarcloud.io"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert SonarCloud has zero open issues and zero open security hotspots."
    )
    parser.add_argument("--project-key", required=True, help="Sonar project key")
    parser.add_argument("--token", default="", help="Sonar token (falls back to SONAR_TOKEN env)")
    parser.add_argument("--branch", default="", help="Optional branch scope")
    parser.add_argument("--pull-request", default="", help="Optional PR scope")
    parser.add_argument("--out-json", default="sonar-zero/sonar.json", help="Output JSON path")
    parser.add_argument("--out-md", default="sonar-zero/sonar.md", help="Output markdown path")
    return parser.parse_args()


def _auth_header(token: str) -> str:
    raw = f"{token}:".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _request_json(path: str, query: Dict[str, str], auth_header: str) -> Dict[str, object]:
    payload, _headers = request_json_https(
        host=SONAR_HOST,
        path=path,
        headers={
            "Accept": "application/json",
            "Authorization": auth_header,
            "User-Agent": "reframe-sonar-zero-gate",
        },
        method="GET",
        query=query,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Sonar response payload.")
    return payload


def _apply_scope(query: Dict[str, str], branch: str, pull_request: str) -> Dict[str, str]:
    scoped = dict(query)
    if pull_request:
        scoped["pullRequest"] = pull_request
    elif branch:
        scoped["branch"] = branch
    return scoped


def _to_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _fetch_sonar_status(
    auth_header: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> Tuple[int, str, int]:
    issue_query = _apply_scope(
        {
            "componentKeys": project_key,
            "resolved": "false",
            "ps": "1",
        },
        branch,
        pull_request,
    )
    issues_payload = _request_json("/api/issues/search", issue_query, auth_header)
    open_issues = _to_int(((issues_payload.get("paging") or {}).get("total")))

    gate_query = _apply_scope({"projectKey": project_key}, branch, pull_request)
    gate_payload = _request_json("/api/qualitygates/project_status", gate_query, auth_header)
    quality_gate = str(((gate_payload.get("projectStatus") or {}).get("status")) or "UNKNOWN")

    hotspot_query = _apply_scope(
        {
            "projectKey": project_key,
            "status": "TO_REVIEW",
            "ps": "1",
        },
        branch,
        pull_request,
    )
    hotspots_payload = _request_json("/api/hotspots/search", hotspot_query, auth_header)
    open_hotspots = _to_int(((hotspots_payload.get("paging") or {}).get("total")))

    return open_issues, quality_gate, open_hotspots


def _evaluate_sonar(
    token: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str], List[str]]:
    findings: List[str] = []
    open_issues: Optional[int] = None
    quality_gate: Optional[str] = None
    open_hotspots: Optional[int] = None
    quality_gate_warning: Optional[str] = None

    if not token:
        return open_issues, quality_gate, open_hotspots, quality_gate_warning, ["SONAR_TOKEN is missing."]

    try:
        open_issues, quality_gate, open_hotspots = _fetch_sonar_status(
            _auth_header(token),
            project_key,
            branch,
            pull_request,
        )
    except (urllib.error.URLError, ValueError, RuntimeError, json.JSONDecodeError) as exc:  # pragma: no cover
        return open_issues, quality_gate, open_hotspots, quality_gate_warning, [f"Sonar API request failed: {exc}"]

    if open_issues != 0:
        findings.append(f"Sonar reports {open_issues} open issues (expected 0).")
    if open_hotspots != 0:
        findings.append(f"Sonar reports {open_hotspots} open security hotspots pending review (expected 0).")
    if quality_gate != "OK":
        quality_gate_warning = (
            f"Sonar quality gate status is {quality_gate}; "
            "SonarCloud Code Analysis remains the authoritative quality gate check."
        )

    return open_issues, quality_gate, open_hotspots, quality_gate_warning, findings


def _render_md(payload: Dict[str, object]) -> str:
    lines = [
        "# Sonar Zero Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Project: `{payload['project_key']}`",
        f"- Open issues: `{payload.get('open_issues')}`",
        f"- Open hotspots: `{payload.get('open_hotspots')}`",
        f"- Quality gate: `{payload.get('quality_gate')}`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Findings",
    ]
    findings = payload.get("findings") or []
    if findings:
        lines.extend(f"- {item}" for item in findings)
    else:
        lines.append("- None")

    warning = payload.get("quality_gate_warning")
    if warning:
        lines.extend(["", "## Notes", f"- {warning}"])

    return "\n".join(lines) + "\n"


def main() -> int:
    args = _parse_args()
    token = (args.token or os.environ.get("SONAR_TOKEN", "")).strip()

    open_issues, quality_gate, open_hotspots, quality_gate_warning, findings = _evaluate_sonar(
        token,
        args.project_key,
        args.branch,
        args.pull_request,
    )

    status = "pass" if not findings else "fail"
    payload: Dict[str, object] = {
        "status": status,
        "project_key": args.project_key,
        "open_issues": open_issues,
        "open_hotspots": open_hotspots,
        "quality_gate": quality_gate,
        "quality_gate_warning": quality_gate_warning,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "sonar-zero/sonar.json")
        out_md = safe_output_path_in_workspace(args.out_md, "sonar-zero/sonar.md")
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
