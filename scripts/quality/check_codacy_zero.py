#!/usr/bin/env python3
"""Codacy zero-issue gate for repository and branch scopes."""

import importlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_impl() -> Any:
    """Load the reusable Codacy helper module for script and package modes."""
    try:
        return importlib.import_module("scripts.quality._codacy_zero_impl")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_codacy_zero_impl")


def _load_support() -> Any:
    """Load the shared Codacy support module for script and package modes."""
    try:
        return importlib.import_module("scripts.quality._codacy_zero_support")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_codacy_zero_support")


_impl = _load_impl()
_support = _load_support()
CodacyRequest = _impl.CodacyRequest
TOTAL_KEYS = _impl.TOTAL_KEYS
CODACY_API_HOST = _impl.CODACY_API_HOST
CODACY_REQUEST_EXCEPTIONS = _impl.CODACY_REQUEST_EXCEPTIONS
request_json_https = _impl.request_json_https
encode_identifier = _impl.encode_identifier
safe_output_path_in_workspace = _impl.safe_output_path_in_workspace

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
) -> dict[str, Any]:
    """Request the Codacy issue-search payload for the target repository scope."""
    return _support_helper("_request_json")(request=request, **kwargs)


def _extract_numeric_total(
    payload: dict[str, Any],
    keys: tuple[str, ...],
) -> int | None:
    """Extract the first numeric total value from a payload using fallback keys."""
    return _impl_helper("_extract_numeric_total")(payload, keys)


def _provider_candidates(preferred: str) -> list[str]:
    """Return the ordered provider aliases to try for Codacy API resolution."""
    return _support_helper("_provider_candidates")(preferred)


def _first_text(issue: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Return the first populated text field from a Codacy issue payload."""
    return _support_helper("_first_text")(issue, keys)


def _format_issue_sample(issue: dict[str, Any]) -> str | None:
    """Render one sample Codacy issue into a short human-readable finding."""
    return _support_helper("_format_issue_sample")(issue)


def _sample_issue_findings(
    payload: dict[str, Any],
    limit: int = 5,
) -> list[str]:
    """Extract a bounded sample of issue descriptions from the Codacy payload."""
    return _support_helper("_sample_issue_findings")(payload, limit)


def _fetch_open_issues_for_provider(
    request: Any = None,
    **kwargs: Any,
) -> tuple[bool, int | None, list[str], Exception | None]:
    """Query Codacy for one provider alias and interpret the result payload."""
    return _impl_helper("_fetch_open_issues_for_provider")(request=request, **kwargs)


def _query_open_issues(
    request: Any = None,
    **kwargs: Any,
) -> tuple[int | None, list[str]]:
    """Query Codacy across provider aliases until one returns a settled result."""
    return _impl_helper("_query_open_issues")(request=request, **kwargs)


def _render_md(payload: dict[str, Any]) -> str:
    """Render the markdown artifact for the Codacy zero gate result."""
    return _impl_helper("_render_md")(payload)


def main() -> int:
    """Run the Codacy zero-issue gate and write its report artifacts."""
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
        out_json = safe_output_path_in_workspace(
            args.out_json,
            "codacy-zero/codacy.json",
        )
        out_md = safe_output_path_in_workspace(args.out_md, "codacy-zero/codacy.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out_md.write_text(_render_md(payload), encoding="utf-8")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
