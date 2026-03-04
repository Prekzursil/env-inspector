#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import request_json_https, safe_output_path_in_workspace, split_validated_https_url

TOTAL_KEYS = {"total", "totalItems", "total_items", "count", "hits", "open_issues"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert DeepScan has zero total open issues.")
    parser.add_argument("--token", default="", help="DeepScan API token (falls back to DEEPSCAN_API_TOKEN env)")
    parser.add_argument("--out-json", default="deepscan-zero/deepscan.json", help="Output JSON path")
    parser.add_argument("--out-md", default="deepscan-zero/deepscan.md", help="Output markdown path")
    return parser.parse_args()


def _walk_nodes(payload: Any) -> list[Any]:
    stack: list[Any] = [payload]
    nodes: list[Any] = []
    while stack:
        node = stack.pop()
        nodes.append(node)
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return nodes


def extract_total_open(payload: Any) -> int | None:
    for node in _walk_nodes(payload):
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            if key in TOTAL_KEYS and isinstance(value, (int, float)):
                return int(value)
    return None


def _request_json(*, host: str, path: str, query: dict[str, str], token: str) -> dict[str, Any]:
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


def _resolve_deepscan_endpoint(open_issues_url: str) -> tuple[str, str, dict[str, str]]:
    return split_validated_https_url(
        open_issues_url,
        allowed_host_suffixes={"deepscan.io"},
    )


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


def _evaluate_deepscan(*, token: str, open_issues_url: str) -> tuple[int | None, list[str]]:
    findings: list[str] = []
    try:
        host, path, query = _resolve_deepscan_endpoint(open_issues_url)
        payload = _request_json(host=host, path=path, query=query, token=token)
    except Exception as exc:  # pragma: no cover - network/runtime surface
        findings.append(f"DeepScan API request failed: {exc}")
        return None, findings

    open_issues = extract_total_open(payload)
    if open_issues is None:
        findings.append("DeepScan response did not include a parseable total issue count.")
    elif open_issues != 0:
        findings.append(f"DeepScan reports {open_issues} open issues (expected 0).")

    return open_issues, findings


def main() -> int:
    import os

    args = _parse_args()
    token = (args.token or os.environ.get("DEEPSCAN_API_TOKEN", "")).strip()
    open_issues_url = os.environ.get("DEEPSCAN_OPEN_ISSUES_URL", "").strip()

    findings: list[str] = []
    open_issues: int | None = None

    if not token:
        findings.append("DEEPSCAN_API_TOKEN is missing.")
    if not open_issues_url:
        findings.append("DEEPSCAN_OPEN_ISSUES_URL is missing.")

    if not findings:
        open_issues, findings = _evaluate_deepscan(token=token, open_issues_url=open_issues_url)

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
