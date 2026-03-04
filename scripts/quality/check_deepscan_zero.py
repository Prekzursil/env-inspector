#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import request_json_https, safe_output_path_in_workspace, split_validated_https_url

TOTAL_KEYS = ("total", "totalItems", "total_items", "count", "hits", "open_issues")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert DeepScan has zero total open issues.")
    parser.add_argument("--token", default="", help="DeepScan API token (falls back to DEEPSCAN_API_TOKEN env)")
    parser.add_argument("--out-json", default="deepscan-zero/deepscan.json", help="Output JSON path")
    parser.add_argument("--out-md", default="deepscan-zero/deepscan.md", help="Output markdown path")
    return parser.parse_args()


def _iter_nested_nodes(payload: Any) -> Iterable[Any]:
    stack: List[Any] = [payload]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def extract_total_open(payload: Any) -> Optional[int]:
    for node in _iter_nested_nodes(payload):
        if not isinstance(node, dict):
            continue
        for key in TOTAL_KEYS:
            value = node.get(key)
            if isinstance(value, (int, float)):
                return int(value)
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
    lines.extend(f"- {item}" for item in findings) if findings else lines.append("- None")
    return "\n".join(lines) + "\n"


def _collect_inputs(args: argparse.Namespace) -> Tuple[str, str, List[str]]:
    findings: List[str] = []
    token = (args.token or os.environ.get("DEEPSCAN_API_TOKEN", "")).strip()
    open_issues_url = os.environ.get("DEEPSCAN_OPEN_ISSUES_URL", "").strip()

    if not token:
        findings.append("DEEPSCAN_API_TOKEN is missing.")
    if not open_issues_url:
        findings.append("DEEPSCAN_OPEN_ISSUES_URL is missing.")

    return token, open_issues_url, findings


def _parse_open_issue_endpoint(open_issues_url: str) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, str]], List[str]]:
    findings: List[str] = []
    if not open_issues_url:
        return None, None, None, findings

    try:
        host, path, query = split_validated_https_url(
            open_issues_url,
            allowed_host_suffixes={"deepscan.io"},
        )
        return host, path, query, findings
    except ValueError as exc:
        findings.append(str(exc))
        return None, None, None, findings


def _evaluate_open_issues(*, host: str, path: str, query: Dict[str, str], token: str) -> Tuple[Optional[int], List[str]]:
    findings: List[str] = []
    open_issues: Optional[int] = None

    try:
        payload = _request_json(host=host, path=path, query=query, token=token)
        open_issues = extract_total_open(payload)
        if open_issues is None:
            findings.append("DeepScan response did not include a parseable total issue count.")
        elif open_issues != 0:
            findings.append(f"DeepScan reports {open_issues} open issues (expected 0).")
    except (urllib.error.URLError, ValueError, RuntimeError, json.JSONDecodeError) as exc:  # pragma: no cover
        findings.append(f"DeepScan API request failed: {exc}")

    return open_issues, findings


def main() -> int:
    args = _parse_args()
    token, open_issues_url, findings = _collect_inputs(args)
    open_issues: Optional[int] = None

    host, path, query, endpoint_findings = _parse_open_issue_endpoint(open_issues_url)
    findings.extend(endpoint_findings)

    if not findings and host and path and query is not None:
        open_issues, query_findings = _evaluate_open_issues(host=host, path=path, query=query, token=token)
        findings.extend(query_findings)

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