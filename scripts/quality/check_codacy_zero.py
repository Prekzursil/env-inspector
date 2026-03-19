#!/usr/bin/env python3
from __future__ import absolute_import, division

import importlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_impl() -> Any:
    try:
        return importlib.import_module("scripts.quality._codacy_zero_impl")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_codacy_zero_impl")


def _load_support() -> Any:
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

_parse_args = _impl._parse_args
_request_json = _impl._request_json
_extract_numeric_total = _impl._extract_numeric_total
extract_total_open = _impl.extract_total_open
_provider_candidates = _impl._provider_candidates
_first_text = _support._first_text
_format_issue_sample = _support._format_issue_sample
_sample_issue_findings = _support._sample_issue_findings
_fetch_open_issues_for_provider = _impl._fetch_open_issues_for_provider
_query_open_issues = _impl._query_open_issues
_render_md = _impl._render_md


def main() -> int:
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
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
