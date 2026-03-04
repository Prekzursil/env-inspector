#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

import argparse
import json
import sys
import urllib.error
from datetime import datetime, timezone
from typing import Any

try:
    from ._security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace
except ImportError:  # pragma: no cover - direct script execution
    from _security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace

TOTAL_KEYS = ("total", "totalItems", "total_items", "count", "hits", "open_issues")
CODACY_API_HOST = "api.codacy.com"
CODACY_REQUEST_EXCEPTIONS = (urllib.error.URLError, ValueError, TypeError, RuntimeError)


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
    branch: str = "",
    limit: int = 1,
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


def _extract_numeric_total(payload: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return int(value)
    return None


def extract_total_open(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None

    pagination = payload.get("pagination")
    if isinstance(pagination, dict):
        total = _extract_numeric_total(pagination, ("total", "totalItems", "count"))
        if total is not None:
            return total

    stack: list[Any] = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            total = _extract_numeric_total(node, TOTAL_KEYS)
            if total is not None:
                return total
            stack.extend(node.values())
            continue
        if isinstance(node, list):
            stack.extend(node)

    return None


def _provider_candidates(preferred: str) -> list[str]:
    values = [preferred, "gh", "github"]
    return list(dict.fromkeys(item for item in values if item))


def _first_text(issue: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = str(issue.get(key) or "").strip()
        if value:
            return value
    return ""


def _format_issue_sample(issue: dict[str, Any]) -> str | None:
    pattern = _first_text(issue, ("patternId", "pattern"))
    path = _first_text(issue, ("filename", "filePath", "path"))
    message = _first_text(issue, ("message", "title"))
    if not (pattern or path or message):
        return None

    identity = pattern or "pattern:unknown"
    location = path or "file:unknown"
    suffix = f" - {message}" if message else ""
    return f"Sample issue: `{identity}` at `{location}`{suffix}"


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


def _fetch_open_issues_for_provider(
    *,
    provider: str,
    owner: str,
    repo: str,
    token: str,
    branch: str,
) -> tuple[bool, int | None, list[str], Exception | None]:
    findings: list[str] = []
    open_issues: int | None = None

    try:
        payload = _request_json(
            provider=provider,
            owner=owner,
            repo=repo,
            token=token,
            branch=branch,
            limit=1,
            method="POST",
            data={},
        )
        open_issues = extract_total_open(payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, None, [], exc
        return True, None, [f"Codacy API request failed: HTTP {exc.code}"], exc
    except CODACY_REQUEST_EXCEPTIONS as exc:  # pragma: no cover - network/runtime surface
        return True, None, [f"Codacy API request failed: {exc}"], exc

    if open_issues is None:
        findings.append("Codacy response did not include a parseable total issue count.")
        return True, open_issues, findings, None

    if open_issues == 0:
        return True, open_issues, findings, None

    findings.append(f"Codacy reports {open_issues} open issues (expected 0).")
    sample_payload = _request_json(
        provider=provider,
        owner=owner,
        repo=repo,
        token=token,
        branch=branch,
        limit=20,
        method="POST",
        data={},
    )
    findings.extend(_sample_issue_findings(sample_payload))
    return True, open_issues, findings, None



def _query_open_issues(
    *,
    provider: str,
    owner: str,
    repo: str,
    token: str,
    branch: str,
) -> tuple[int | None, list[str]]:
    last_exc: Exception | None = None

    for candidate in _provider_candidates(provider):
        handled, open_issues, findings, error = _fetch_open_issues_for_provider(
            provider=candidate,
            owner=owner,
            repo=repo,
            token=token,
            branch=branch,
        )
        if handled:
            return open_issues, findings
        last_exc = error

    findings = [
        f"Codacy API endpoint was not found for provider(s): {', '.join(_provider_candidates(provider))}."
    ]
    if last_exc is not None:
        findings.append(f"Last Codacy API error: {last_exc}")
    return None, findings



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
    branch = getattr(args, "branch", "")
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
            branch=branch,
        )

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "owner": args.owner,
        "repo": args.repo,
        "provider": args.provider,
        "branch": branch,
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


