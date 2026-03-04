#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

import argparse
import base64
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import normalize_https_url, safe_output_path_in_workspace

SONAR_API_BASE = "https://sonarcloud.io"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert SonarCloud has zero open issues and a passing quality gate.")
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


def _request_json(url: str, auth_header: str) -> dict[str, Any]:
    safe_url = normalize_https_url(url, allowed_host_suffixes={"sonarcloud.io"}).rstrip("/")
    request = urllib.request.Request(
        safe_url,
        headers={
            "Accept": "application/json",
            "Authorization": auth_header,
            "User-Agent": "reframe-sonar-zero-gate",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _build_issue_query(project_key: str, *, branch: str, pull_request: str) -> dict[str, str]:
    query = {
        "componentKeys": project_key,
        "resolved": "false",
        "ps": "1",
    }
    if branch:
        query["branch"] = branch
    if pull_request:
        query["pullRequest"] = pull_request
    return query


def _build_quality_gate_query(project_key: str, *, branch: str, pull_request: str) -> dict[str, str]:
    query = {"projectKey": project_key}
    if branch:
        query["branch"] = branch
    if pull_request:
        query["pullRequest"] = pull_request
    return query


def _fetch_sonar_status(
    *,
    api_base: str,
    auth_header: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> tuple[int, str]:
    issues_url = (
        f"{api_base}/api/issues/search?"
        f"{urllib.parse.urlencode(_build_issue_query(project_key, branch=branch, pull_request=pull_request))}"
    )
    issues_payload = _request_json(issues_url, auth_header)
    open_issues = int((issues_payload.get("paging") or {}).get("total") or 0)

    gate_url = (
        f"{api_base}/api/qualitygates/project_status?"
        f"{urllib.parse.urlencode(_build_quality_gate_query(project_key, branch=branch, pull_request=pull_request))}"
    )
    gate_payload = _request_json(gate_url, auth_header)
    quality_gate = str((gate_payload.get("projectStatus") or {}).get("status") or "UNKNOWN")
    return open_issues, quality_gate


def _evaluate_sonar(
    *,
    token: str,
    api_base: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> tuple[int | None, str | None, list[str]]:
    findings: list[str] = []
    open_issues: int | None = None
    quality_gate: str | None = None

    if not token:
        return open_issues, quality_gate, ["SONAR_TOKEN is missing."]

    try:
        open_issues, quality_gate = _fetch_sonar_status(
            api_base=api_base,
            auth_header=_auth_header(token),
            project_key=project_key,
            branch=branch,
            pull_request=pull_request,
        )
    except Exception as exc:  # pragma: no cover - network/runtime surface
        return open_issues, quality_gate, [f"Sonar API request failed: {exc}"]

    if open_issues != 0:
        findings.append(f"Sonar reports {open_issues} open issues (expected 0).")
    if quality_gate != "OK":
        findings.append(f"Sonar quality gate status is {quality_gate} (expected OK).")
    return open_issues, quality_gate, findings


def _render_md(payload: dict) -> str:
    lines = [
        "# Sonar Zero Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Project: `{payload['project_key']}`",
        f"- Open issues: `{payload.get('open_issues')}`",
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
    return "\n".join(lines) + "\n"


def main() -> int:
    import os

    args = _parse_args()
    token = (args.token or os.environ.get("SONAR_TOKEN", "")).strip()
    api_base = normalize_https_url(SONAR_API_BASE, allowed_hosts={"sonarcloud.io"}).rstrip("/")

    open_issues, quality_gate, findings = _evaluate_sonar(
        token=token,
        api_base=api_base,
        project_key=args.project_key,
        branch=args.branch,
        pull_request=args.pull_request,
    )

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "project_key": args.project_key,
        "open_issues": open_issues,
        "quality_gate": quality_gate,
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
