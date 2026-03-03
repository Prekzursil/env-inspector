#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import encode_identifier, request_json_https, safe_output_path_in_workspace

SENTRY_API_HOST = "sentry.io"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert Sentry has zero unresolved issues for configured projects.")
    parser.add_argument("--org", default="", help="Sentry org slug (falls back to SENTRY_ORG env)")
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        help="Project slug (repeatable, falls back to SENTRY_PROJECT_BACKEND/SENTRY_PROJECT_WEB env)",
    )
    parser.add_argument("--token", default="", help="Sentry auth token (falls back to SENTRY_AUTH_TOKEN env)")
    parser.add_argument("--out-json", default="sentry-zero/sentry.json", help="Output JSON path")
    parser.add_argument("--out-md", default="sentry-zero/sentry.md", help="Output markdown path")
    return parser.parse_args()


def _request_project_issues(org: str, project: str, token: str) -> tuple[list[Any], dict[str, str]]:
    org_slug = encode_identifier(org, field_name="Sentry org")
    project_slug = encode_identifier(project, field_name="Sentry project")
    payload, headers = request_json_https(
        host=SENTRY_API_HOST,
        path=f"/api/0/projects/{org_slug}/{project_slug}/issues/",
        query={"query": "is:unresolved", "limit": "1"},
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "reframe-sentry-zero-gate",
        },
        method="GET",
    )
    if not isinstance(payload, list):
        raise RuntimeError("Unexpected Sentry response payload")
    return payload, headers


def _hits_from_headers(headers: dict[str, str]) -> int | None:
    raw = headers.get("x-hits")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _render_md(payload: dict) -> str:
    lines = [
        "# Sentry Zero Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Mode: `{payload.get('mode', 'strict')}`",
        f"- Org: `{payload.get('org')}`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Project results",
    ]

    for item in payload.get("projects", []):
        lines.append(f"- `{item['project']}` unresolved=`{item['unresolved']}`")

    if not payload.get("projects"):
        lines.append("- None")

    lines.extend(["", "## Findings"])
    findings = payload.get("findings") or []
    if findings:
        lines.extend(f"- {item}" for item in findings)
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def main() -> int:
    import os

    args = _parse_args()
    token = (args.token or os.environ.get("SENTRY_AUTH_TOKEN", "")).strip()
    org = (args.org or os.environ.get("SENTRY_ORG", "")).strip()

    projects = [p for p in args.project if p]
    if not projects:
        for env_name in ("SENTRY_PROJECT_BACKEND", "SENTRY_PROJECT_WEB"):
            value = str(os.environ.get(env_name, "")).strip()
            if value:
                projects.append(value)

    findings: list[str] = []
    failures: list[str] = []
    project_results: list[dict[str, Any]] = []
    mode = "strict"

    if not token:
        findings.append("SENTRY_AUTH_TOKEN is missing.")
    if not org:
        findings.append("SENTRY_ORG is missing.")
    if not projects:
        findings.append("No Sentry projects configured (SENTRY_PROJECT_BACKEND/SENTRY_PROJECT_WEB).")

    if findings:
        status = "pass"
        mode = "skipped"
    else:
        for project in projects:
            try:
                issues, headers = _request_project_issues(org, project, token)
                unresolved = _hits_from_headers(headers)
                if unresolved is None:
                    unresolved = len(issues)
                    if unresolved >= 1:
                        failures.append(
                            f"Sentry project {project} returned unresolved issues but no X-Hits header for exact totals."
                        )
                if unresolved != 0:
                    failures.append(f"Sentry project {project} has {unresolved} unresolved issues (expected 0).")
                project_results.append({"project": project, "unresolved": unresolved})
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    mode = "skipped"
                    findings.append(f"Sentry project {project} not found (HTTP 404). Skipping project.")
                    continue
                failures.append(f"Sentry API request failed for project {project}: HTTP {exc.code}")
                mode = "error"
                break
            except Exception as exc:  # pragma: no cover - network/runtime surface
                failures.append(f"Sentry API request failed for project {project}: {exc}")
                mode = "error"
                break

        status = "pass" if not failures else "fail"
        findings.extend(failures)

    payload = {
        "status": status,
        "mode": mode,
        "org": org,
        "projects": project_results,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "sentry-zero/sentry.json")
        out_md = safe_output_path_in_workspace(args.out_md, "sentry-zero/sentry.md")
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
