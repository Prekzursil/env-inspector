#!/usr/bin/env python3
from __future__ import absolute_import

import argparse
import json
import os
import sys
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    from ._security_imports import request_json_https, safe_output_path_in_workspace, split_validated_https_url
except ImportError:  # pragma: no cover - direct script execution
    from _security_imports import request_json_https, safe_output_path_in_workspace, split_validated_https_url

TOTAL_KEYS = {"total", "totalItems", "total_items", "count", "hits", "open_issues"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert DeepScan has zero total open issues.")
    parser.add_argument("--token", default="", help="DeepScan API token (falls back to DEEPSCAN_API_TOKEN env)")
    parser.add_argument("--out-json", default="deepscan-zero/deepscan.json", help="Output JSON path")
    parser.add_argument("--out-md", default="deepscan-zero/deepscan.md", help="Output markdown path")
    return parser.parse_args()


def extract_total_open(payload: Any) -> int | None:
    stack: List[Any] = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key in TOTAL_KEYS:
                value = node.get(key)
                if isinstance(value, (int, float)):
                    return int(value)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def _request_json(*, host: str, path: str, query: Dict[str, str], token: str) -> Dict[str, Any]:
    payload, _headers = request_json_https(
        host=host,
        path=path,
        query=query,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "reframe-deepscan-zero-gate",
        },
        method="GET",
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected DeepScan response payload.")
    return payload


def _resolve_deepscan_endpoint(open_issues_url: str) -> Tuple[str, str, Dict[str, str]]:
    return split_validated_https_url(
        open_issues_url,
        allowed_host_suffixes={"deepscan.io"},
    )


def _fetch_open_issues(
    *,
    host: str,
    path: str,
    query: dict,
    token: str,
    findings: List[str],
) -> int | None:
    try:
        payload = _request_json(host=host, path=path, query=query, token=token)
    except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError, ValueError, TypeError) as exc:  # pragma: no cover - network/runtime surface
        findings.append(f"DeepScan API request failed: {exc}")
        return None

    open_issues = extract_total_open(payload)
    if open_issues is None:
        findings.append("DeepScan response did not include a parseable total issue count.")
        return None
    if open_issues != 0:
        findings.append(f"DeepScan reports {open_issues} open issues (expected 0).")
    return open_issues


def _render_md(payload: dict) -> str:
    lines = [
        "# DeepScan Zero Gate",
        "",
        f"- Status: `{payload['status']}`",
        f"- Open issues: `{payload.get('open_issues')}`",
        f"- Source URL: `{payload.get('open_issues_url') or 'n/a'}`",
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
    args = _parse_args()
    token = (args.token or os.environ.get("DEEPSCAN_API_TOKEN", "")).strip()
    open_issues_url = os.environ.get("DEEPSCAN_OPEN_ISSUES_URL", "").strip()

    findings: List[str] = []
    open_issues: int | None = None

    if not token:
        findings.append("DEEPSCAN_API_TOKEN is missing.")
    if not open_issues_url:
        findings.append("DEEPSCAN_OPEN_ISSUES_URL is missing.")

    if not findings:
        host, path, query = _resolve_deepscan_endpoint(open_issues_url)
        open_issues = _fetch_open_issues(host=host, path=path, query=query, token=token, findings=findings)

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "open_issues": open_issues,
        "open_issues_url": open_issues_url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "deepscan-zero/deepscan.json")
        out_md = safe_output_path_in_workspace(args.out_md, "deepscan-zero/deepscan.md")
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
