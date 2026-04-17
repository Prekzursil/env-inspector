"""Codacy zero impl module."""
#!/usr/bin/env python3

import argparse
import sys
import urllib.error
from dataclasses import replace
from typing import TYPE_CHECKING, Any, List, Tuple

try:
    from . import _codacy_zero_support as _support
except ImportError:  # pragma: no cover - direct script execution
    import _codacy_zero_support as _support  # type: ignore

if TYPE_CHECKING:
    from scripts.quality._codacy_zero_support import CodacyRequest
else:
    CodacyRequest = _support.CodacyRequest

CODACY_API_HOST = _support.CODACY_API_HOST
CODACY_REQUEST_EXCEPTIONS = _support.CODACY_REQUEST_EXCEPTIONS
TOTAL_KEYS = _support.TOTAL_KEYS
_fetch_sample_payload = _support._fetch_sample_payload
_first_text = _support._first_text
_format_issue_sample = _support._format_issue_sample
_provider_candidates = _support._provider_candidates
_request_json = _support._request_json
_sample_issue_findings = _support._sample_issue_findings
encode_identifier = _support.encode_identifier
request_json_https = _support.request_json_https
safe_output_path_in_workspace = _support.safe_output_path_in_workspace


def _public_codacy_module() -> Any | None:
    """Public codacy module."""
    return sys.modules.get("scripts.quality.check_codacy_zero")


def _parse_args() -> argparse.Namespace:
    """Parse args."""
    parser = argparse.ArgumentParser(
        description="Assert Codacy has zero total open issues."
    )
    parser.add_argument(
        "--provider", default="gh", help="Organization provider, for example gh"
    )
    parser.add_argument("--owner", required=True, help="Repository owner")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument(
        "--branch", default="", help="Optional branch name to scope issue totals"
    )
    parser.add_argument(
        "--token",
        default="",
        help="Codacy API token (falls back to CODACY_API_TOKEN env)",
    )
    parser.add_argument(
        "--out-json", default="codacy-zero/codacy.json", help="Output JSON path"
    )
    parser.add_argument(
        "--out-md", default="codacy-zero/codacy.md", help="Output markdown path"
    )
    return parser.parse_args()


def _extract_numeric_total(payload: dict, keys: tuple) -> int | None:
    """Extract numeric total."""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return int(value)
    return None


def extract_total_open(payload: Any) -> int | None:
    """Extract total open."""
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


def _fetch_open_issues_for_provider(
    request: CodacyRequest | None = None,
    **kwargs: Any,
) -> tuple[bool, int | None, list[str], Exception | None]:
    """Fetch open issues for provider."""
    request = _resolve_codacy_request(request, kwargs)

    public = _public_codacy_module()
    request_json_fn = getattr(public, "_request_json", _request_json)
    sample_findings_fn = getattr(
        public, "_sample_issue_findings", _sample_issue_findings
    )
    handled, open_issues, findings, error = _attempt_issue_total(
        request, request_json_fn
    )
    findings.extend(
        _issue_total_findings(
            request, open_issues, handled, request_json_fn, sample_findings_fn
        )
    )
    return handled, open_issues, findings, error


def _attempt_issue_total(
    request: CodacyRequest,
    request_json_fn: Any,
) -> tuple[bool, int | None, list[str], Exception | None]:
    """Attempt issue total."""
    findings: list[str] = []

    try:
        return True, _request_issue_total(request, request_json_fn), findings, None
    except urllib.error.HTTPError as exc:
        handled, error = _handle_http_error(exc, findings)
        return handled, None, findings, error
    except (
        CODACY_REQUEST_EXCEPTIONS
    ) as exc:  # pragma: no cover - network/runtime surface
        findings.append(f"Codacy API request failed: {exc}")
        return True, None, findings, exc


def _resolve_codacy_request(
    request: CodacyRequest | None, kwargs: Any
) -> CodacyRequest:
    """Resolve codacy request."""
    if request is None:
        return CodacyRequest(**kwargs)
    if kwargs:
        raise TypeError("Pass either a CodacyRequest or keyword arguments, not both.")
    return request


def _request_issue_total(request: CodacyRequest, request_json_fn: Any) -> int | None:
    """Request issue total."""
    payload = request_json_fn(request=replace(request, limit=1, method="POST", data={}))
    return extract_total_open(payload)


def _handle_http_error(
    exc: urllib.error.HTTPError, findings: list[str]
) -> tuple[bool, Exception]:
    """Handle http error."""
    if exc.code == 404:
        return False, exc
    findings.append(f"Codacy API request failed: HTTP {exc.code}")
    return True, exc


def _non_zero_issue_findings(
    request: CodacyRequest,
    open_issues: int,
    request_json_fn: Any,
    sample_findings_fn: Any,
) -> list[str]:
    """Non zero issue findings."""
    findings = [f"Codacy reports {open_issues} open issues (expected 0)."]
    sample_payload = request_json_fn(
        request=replace(request, limit=20, method="POST", data={})
    )
    findings.extend(sample_findings_fn(sample_payload))
    return findings


def _issue_total_findings(
    request: CodacyRequest,
    open_issues: int | None,
    handled: bool,
    request_json_fn: Any,
    sample_findings_fn: Any,
) -> list[str]:
    """Issue total findings."""
    if not handled:
        return []
    if open_issues is None:
        return ["Codacy response did not include a parseable total issue count."]
    if open_issues == 0:
        return []
    return _non_zero_issue_findings(
        request, open_issues, request_json_fn, sample_findings_fn
    )


def _query_open_issues(
    request: CodacyRequest | None = None, **kwargs: Any
) -> tuple[int | None, list[str]]:
    """Query open issues."""
    if request is None:
        request = CodacyRequest(**kwargs)
    elif kwargs:
        raise TypeError("Pass either a CodacyRequest or keyword arguments, not both.")

    last_exc: Exception | None = None

    public = _public_codacy_module()
    provider_candidates_fn = getattr(
        public, "_provider_candidates", _provider_candidates
    )
    fetch_fn = getattr(
        public, "_fetch_open_issues_for_provider", _fetch_open_issues_for_provider
    )

    for candidate in provider_candidates_fn(request.provider):
        handled, open_issues, findings, error = fetch_fn(
            request=replace(request, provider=candidate)
        )
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
    """Render md."""
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
