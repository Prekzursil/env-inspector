#!/usr/bin/env python3
from __future__ import absolute_import, division

import argparse
from dataclasses import replace
import urllib.error
from datetime import datetime, timezone
import sys
from typing import Any, List, Tuple

try:
    from ._codacy_zero_support import (
        CODACY_API_HOST,
        CODACY_REQUEST_EXCEPTIONS,
        TOTAL_KEYS,
        CodacyRequest,
        _fetch_sample_payload,
        _first_text,
        _format_issue_sample,
        _provider_candidates,
        _request_json,
        _sample_issue_findings,
        encode_identifier,
        request_json_https,
        safe_output_path_in_workspace,
    )
except ImportError:  # pragma: no cover - direct script execution
    from _codacy_zero_support import (  # type: ignore
        CODACY_API_HOST,
        CODACY_REQUEST_EXCEPTIONS,
        TOTAL_KEYS,
        CodacyRequest,
        _fetch_sample_payload,
        _first_text,
        _format_issue_sample,
        _provider_candidates,
        _request_json,
        _sample_issue_findings,
        encode_identifier,
        request_json_https,
        safe_output_path_in_workspace,
    )


def _public_codacy_module() -> Any | None:
    return sys.modules.get("scripts.quality.check_codacy_zero")


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


def _extract_numeric_total(payload: dict, keys: tuple) -> int | None:
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

    stack: List[Any] = [payload]
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


def _fetch_open_issues_for_provider(
    request: CodacyRequest | None = None,
    **kwargs: Any,
) -> Tuple[bool, int | None, List[str], Exception | None]:
    if request is None:
        request = CodacyRequest(**kwargs)
    elif kwargs:
        raise TypeError("Pass either a CodacyRequest or keyword arguments, not both.")

    findings: List[str] = []
    open_issues: int | None = None
    handled = True
    error: Exception | None = None

    public = _public_codacy_module()
    request_json_fn = getattr(public, "_request_json", _request_json)
    sample_findings_fn = getattr(public, "_sample_issue_findings", _sample_issue_findings)

    try:
        payload = request_json_fn(request=replace(request, limit=1, method="POST", data={}))
        open_issues = extract_total_open(payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            handled = False
            error = exc
        else:
            findings.append(f"Codacy API request failed: HTTP {exc.code}")
            error = exc
    except CODACY_REQUEST_EXCEPTIONS as exc:  # pragma: no cover - network/runtime surface
        findings.append(f"Codacy API request failed: {exc}")
        error = exc

    if handled and open_issues is None:
        findings.append("Codacy response did not include a parseable total issue count.")
    elif handled and open_issues == 0:
        pass
    elif handled:
        findings.append(f"Codacy reports {open_issues} open issues (expected 0).")
        sample_payload = request_json_fn(request=replace(request, limit=20, method="POST", data={}))
        findings.extend(sample_findings_fn(sample_payload))

    return handled, open_issues, findings, error


def _query_open_issues(request: CodacyRequest | None = None, **kwargs: Any) -> Tuple[int | None, List[str]]:
    if request is None:
        request = CodacyRequest(**kwargs)
    elif kwargs:
        raise TypeError("Pass either a CodacyRequest or keyword arguments, not both.")

    last_exc: Exception | None = None

    public = _public_codacy_module()
    provider_candidates_fn = getattr(public, "_provider_candidates", _provider_candidates)
    fetch_fn = getattr(public, "_fetch_open_issues_for_provider", _fetch_open_issues_for_provider)

    for candidate in provider_candidates_fn(request.provider):
        handled, open_issues, findings, error = fetch_fn(request=replace(request, provider=candidate))
        if handled:
            return open_issues, findings
        last_exc = error
    findings = [
        f"Codacy API endpoint was not found for provider(s): {', '.join(provider_candidates_fn(request.provider))}."
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
