#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

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

TOTAL_KEYS = ("total", "totalItems", "total_items", "count", "hits", "open_issues")
CODACY_API_HOST = "api.codacy.com"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert Codacy has zero total open issues.")
    parser.add_argument("--provider", default="gh", help="Organization provider, for example gh")
    parser.add_argument("--owner", required=True, help="Repository owner")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument("--branch", default="", help="Optional branch name to scope issue totals")
    parser.add_argument("--token", default="", help="Codacy API token (falls back to CODACY_API_TOKEN env)")
    parser.add_argument("--out-json", default="codacy-zero/codacy.json", help="Output JSON path")
    parser.add_argument("--out-md", default="codacy-zero/codacy.md", help="Output markdown path")
    return parser.parse_args()


def _request_json(
    *,
    provider: str,
    owner: str,
    repo: str,
    token: str,
    branch: str,
    limit: int,
    method: str = "GET",
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "api-token": token,
        "User-Agent": "reframe-codacy-zero-gate",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"

    provider_slug = encode_identifier(provider, field_name="Codacy provider")
    owner_slug = encode_identifier(owner, field_name="Codacy owner")
    repo_slug = encode_identifier(repo, field_name="Codacy repository")

    payload_data: dict[str, Any] = data or {}
    branch_name = str(branch or "").strip()
    if branch_name:
        payload_data = {**payload_data, "branchName": branch_name}

    payload, _headers = request_json_https(
        host=CODACY_API_HOST,
        path=f"/api/v3/analysis/organizations/{provider_slug}/{owner_slug}/repositories/{repo_slug}/issues/search",
        headers=headers,
        method=method,
        query={"limit": str(max(limit, 1))},
        data=payload_data,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Codacy response payload.")
    return payload


def extract_total_open(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None

    pagination = payload.get("pagination")
    if isinstance(pagination, dict):
        for key in ("total", "totalItems", "count"):
            value = pagination.get(key)
            if isinstance(value, (int, float)):
                return int(value)

    for key in TOTAL_KEYS:
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return int(value)

    return None


def _provider_candidates(preferred: str) -> list[str]:
    values = [preferred, "gh", "github"]
    return list(dict.fromkeys(item for item in values if item))


def _format_issue_sample(issue: dict[str, Any]) -> str | None:
    pattern = str(issue.get("patternId") or issue.get("pattern") or "").strip()
    path = str(issue.get("filename") or issue.get("filePath") or issue.get("path") or "").strip()
    message = str(issue.get("message") or issue.get("title") or "").strip()
    if not (pattern or path or message):
        return None

    identity = pattern or "pattern:unknown"
    location = path or "file:unknown"
    if message:
        return f"Sample issue: `{identity}` at `{location}` - {message}"
    return f"Sample issue: `{identity}` at `{location}`"


def _sample_issue_findings(payload: dict[str, Any], limit: int = 5) -> list[str]:
    data = payload.get("data")
    if not isinstance(data, list):
        return []

    findings: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        sample = _format_issue_sample(item)
        if not sample:
            continue
        findings.append(sample)
        if len(findings) >= limit:
            break
    return findings


def _query_open_issues(
    *,
    provider: str,
    owner: str,
    repo: str,
    token: str,
    branch: str,
) -> tuple[int | None, list[str]]:
    findings: list[str] = []
    open_issues: int | None = None
    last_exc: Exception | None = None

    for candidate in _provider_candidates(provider):
        try:
            payload = _request_json(
                provider=candidate,
                owner=owner,
                repo=repo,
                token=token,
                branch=branch,
                limit=1,
                method="POST",
                data={},
            )
            open_issues = extract_total_open(payload)
            if open_issues is None:
                findings.append("Codacy response did not include a parseable total issue count.")
            elif open_issues != 0:
                findings.append(f"Codacy reports {open_issues} open issues (expected 0).")
                sample_payload = _request_json(
                    provider=candidate,
                    owner=owner,
                    repo=repo,
                    token=token,
                    branch=branch,
                    limit=20,
                    method="POST",
                    data={},
                )
                findings.extend(_sample_issue_findings(sample_payload))
            return open_issues, findings
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code == 404:
                continue
            findings.append(f"Codacy API request failed: HTTP {exc.code}")
            return open_issues, findings
        except Exception as exc:  # pragma: no cover - network/runtime surface
            last_exc = exc
            findings.append(f"Codacy API request failed: {exc}")
            return open_issues, findings

    findings.append(
        f"Codacy API endpoint was not found for provider(s): {', '.join(_provider_candidates(provider))}."
    )
    if last_exc is not None:
        findings.append(f"Last Codacy API error: {last_exc}")
    return open_issues, findings


def _render_md(payload: dict) -> str:
    lines = [
        "# Codacy Zero Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Owner/repo: `{payload['owner']}/{payload['repo']}`",
        f"- Branch: `{payload.get('branch') or 'default'}`",
        f"- Open issues: `{payload.get('open_issues')}`",
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
    token = (args.token or os.environ.get("CODACY_API_TOKEN", "")).strip()
    findings: list[str] = []
    open_issues: int | None = None

    if not token:
        findings.append("CODACY_API_TOKEN is missing.")
    else:
        open_issues, findings = _query_open_issues(
            provider=args.provider,
            owner=args.owner.strip(),
            repo=args.repo.strip(),
            token=token,
            branch=args.branch,
        )

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "owner": args.owner,
        "repo": args.repo,
        "provider": args.provider,
        "branch": args.branch,
        "open_issues": open_issues,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "codacy-zero/codacy.json")
        out_md = safe_output_path_in_workspace(args.out_md, "codacy-zero/codacy.md")
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
