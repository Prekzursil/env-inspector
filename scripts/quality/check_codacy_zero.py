#!/usr/bin/env python3
"""Codacy zero-issue gate for repository and branch scopes."""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    from ._module_loader import load_quality_module
except ImportError:  # pragma: no cover - direct script execution
    from _module_loader import load_quality_module  # type: ignore

_impl = load_quality_module("scripts.quality._codacy_zero_impl", "_codacy_zero_impl")
_support = load_quality_module(
    "scripts.quality._codacy_zero_support", "_codacy_zero_support"
)
CodacyRequest = _impl.CodacyRequest
TOTAL_KEYS = _impl.TOTAL_KEYS
CODACY_API_HOST = _impl.CODACY_API_HOST
CODACY_REQUEST_EXCEPTIONS = _impl.CODACY_REQUEST_EXCEPTIONS
request_json_https = _impl.request_json_https
encode_identifier = _impl.encode_identifier
emit_zero_report = _impl.emit_zero_report
ZeroReportSpec = _impl.ZeroReportSpec

extract_total_open = _impl.extract_total_open


def _impl_helper(name: str) -> Any:
    """Return a helper exported by the reusable Codacy implementation module."""
    return getattr(_impl, name)


def _support_helper(name: str) -> Any:
    """Return a helper exported by the reusable Codacy support module."""
    return getattr(_support, name)


def _parse_args() -> Any:
    """Parse command-line arguments for the Codacy zero gate."""
    return _impl_helper("_parse_args")()


def _request_json(
    request: Any = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Request the Codacy issue-search payload for the target repository scope."""
    return _support_helper("_request_json")(request=request, **kwargs)


def _extract_numeric_total(
    payload: Dict[str, Any],
    keys: Tuple[str, ...],
) -> int | None:
    """Extract the first numeric total value from a payload using fallback keys."""
    return _impl_helper("_extract_numeric_total")(payload, keys)


def _provider_candidates(preferred: str) -> List[str]:
    """Return the ordered provider aliases to try for Codacy API resolution."""
    return _support_helper("_provider_candidates")(preferred)


def _first_text(issue: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    """Return the first populated text field from a Codacy issue payload."""
    return _support_helper("_first_text")(issue, keys)


def _format_issue_sample(issue: Dict[str, Any]) -> str | None:
    """Render one sample Codacy issue into a short human-readable finding."""
    return _support_helper("_format_issue_sample")(issue)


def _sample_issue_findings(
    payload: Dict[str, Any],
    limit: int = 5,
) -> List[str]:
    """Extract a bounded sample of issue descriptions from the Codacy payload."""
    return _support_helper("_sample_issue_findings")(payload, limit)


def _fetch_open_issues_for_provider(
    request: Any = None,
    **kwargs: Any,
) -> Tuple[bool, int | None, List[str], Exception | None]:
    """Query Codacy for one provider alias and interpret the result payload."""
    return _impl_helper("_fetch_open_issues_for_provider")(request=request, **kwargs)


def _query_open_issues(
    request: Any = None,
    **kwargs: Any,
) -> Tuple[int | None, List[str]]:
    """Query Codacy across provider aliases until one returns a settled result."""
    return _impl_helper("_query_open_issues")(request=request, **kwargs)


def _render_md(payload: Dict[str, Any]) -> str:
    """Render the markdown artifact for the Codacy zero gate result."""
    return _impl_helper("_render_md")(payload)


def main() -> int:
    """Run the Codacy zero-issue gate and write its report artifacts."""
    args = _parse_args()
    branch = getattr(args, "branch", "")
    token = (args.token or os.environ.get("CODACY_API_TOKEN", "")).strip()
    findings: List[str] = []
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

    return emit_zero_report(
        ZeroReportSpec(
            out_json_arg=args.out_json,
            out_md_arg=args.out_md,
            json_fallback="codacy-zero/codacy.json",
            md_fallback="codacy-zero/codacy.md",
            payload=payload,
            rendered_md=_render_md(payload),
            passed=status == "pass",
        ),
        echo=False,
    )


if __name__ == "__main__":
    raise SystemExit(main())
