#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

try:
    from ._security_imports import normalize_https_url, request_json_https, safe_output_path_in_workspace
except ImportError:  # pragma: no cover - direct script execution
    from _security_imports import normalize_https_url, request_json_https, safe_output_path_in_workspace

SONAR_API_HOST = "sonarcloud.io"
SONAR_API_BASE = f"https://{SONAR_API_HOST}"


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


def _request_json(*, path: str, query: dict[str, str], auth_header: str) -> dict[str, Any]:
    payload, _headers = request_json_https(
        host=SONAR_API_HOST,
        path=path,
        query=query,
        headers={
            "Accept": "application/json",
            "Authorization": auth_header,
            "User-Agent": "env-inspector-sonar-zero-gate",
        },
        method="GET",
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Sonar response payload.")
    return payload


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


def _build_hotspot_query(project_key: str, *, branch: str, pull_request: str) -> dict[str, str]:
    query = {
        "projectKey": project_key,
        "status": "TO_REVIEW",
        "ps": "1",
    }
    if branch:
        query["branch"] = branch
    if pull_request:
        query["pullRequest"] = pull_request
    return query


def _fetch_sonar_status(
    *,
    auth_header: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> tuple[int, str, int]:
    issues_payload = _request_json(
        path="/api/issues/search",
        query=_build_issue_query(project_key, branch=branch, pull_request=pull_request),
        auth_header=auth_header,
    )
    open_issues = int((issues_payload.get("paging") or {}).get("total") or 0)

    gate_payload = _request_json(
        path="/api/qualitygates/project_status",
        query=_build_quality_gate_query(project_key, branch=branch, pull_request=pull_request),
        auth_header=auth_header,
    )
    quality_gate = str((gate_payload.get("projectStatus") or {}).get("status") or "UNKNOWN")

    hotspots_payload = _request_json(
        path="/api/hotspots/search",
        query=_build_hotspot_query(project_key, branch=branch, pull_request=pull_request),
        auth_header=auth_header,
    )
    open_hotspots = int((hotspots_payload.get("paging") or {}).get("total") or 0)

    return open_issues, quality_gate, open_hotspots


def _evaluate_sonar(
    *,
    token: str,
    project_key: str,
    branch: str,
    pull_request: str,
) -> tuple[int | None, str | None, int | None, str | None, list[str]]:
    findings: list[str] = []
    open_issues: int | None = None
    quality_gate: str | None = None
    open_hotspots: int | None = None
    quality_gate_warning: str | None = None

    if not token:
        return open_issues, quality_gate, open_hotspots, quality_gate_warning, ["SONAR_TOKEN is missing."]

    try:
        open_issues, quality_gate, open_hotspots = _fetch_sonar_status(
            auth_header=_auth_header(token),
            project_key=project_key,
            branch=branch,
            pull_request=pull_request,
        )
    except Exception as exc:  # pragma: no cover - network/runtime surface
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


def _render_md(payload: dict) -> str:
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
        token=token,
        project_key=args.project_key,
        branch=args.branch,
        pull_request=args.pull_request,
    )

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "project_key": args.project_key,
        "open_issues": open_issues,
        "open_hotspots": open_hotspots,
        "quality_gate": quality_gate,
        "quality_gate_warning": quality_gate_warning,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "api_base": normalize_https_url(SONAR_API_BASE, allowed_hosts={SONAR_API_HOST}).rstrip("/"),
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
