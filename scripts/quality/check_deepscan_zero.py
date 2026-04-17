#!/usr/bin/env python3
from __future__ import absolute_import, division

import argparse
import importlib
import json
import os
import sys
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple, cast

TOTAL_KEYS = {"total", "totalItems", "total_items", "count", "hits", "open_issues"}

RequestJsonHttps = Callable[..., Tuple[Any, Dict[str, str]]]
SafeOutputPathInWorkspace = Callable[..., Path]
SplitValidatedHttpsUrl = Callable[..., Tuple[str, str, Dict[str, str]]]


@dataclass(frozen=True)
class DeepScanRequest:
    """Parameters for a DeepScan API open-issues request."""

    host: str
    path: str
    query: dict
    token: str
    findings: List[str]


def _load_security_imports() -> Any:
    try:
        return importlib.import_module("scripts.quality._security_imports")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_security_imports")


_security_imports = _load_security_imports()
request_json_https = cast(RequestJsonHttps, _security_imports.request_json_https)
safe_output_path_in_workspace = cast(
    SafeOutputPathInWorkspace,
    _security_imports.safe_output_path_in_workspace,
)
split_validated_https_url = cast(
    SplitValidatedHttpsUrl,
    _security_imports.split_validated_https_url,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert DeepScan has zero total open issues."
    )
    parser.add_argument(
        "--token",
        default="",
        help="DeepScan API token (falls back to DEEPSCAN_API_TOKEN env)",
    )
    parser.add_argument(
        "--out-json", default="deepscan-zero/deepscan.json", help="Output JSON path"
    )
    parser.add_argument(
        "--out-md", default="deepscan-zero/deepscan.md", help="Output markdown path"
    )
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


def _request_json(
    *, host: str, path: str, query: Dict[str, str], token: str
) -> Dict[str, Any]:
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


def _coerce_fetch_request(*args: Any, **kwargs: Any) -> DeepScanRequest:
    if args:
        if len(args) == 1 and isinstance(args[0], DeepScanRequest):
            if kwargs:
                raise TypeError(
                    "Pass either a request object or keyword arguments, not both."
                )
            return args[0]
        if len(args) == 5 and not kwargs:
            host, path, query, token, findings = args
            return DeepScanRequest(
                host=str(host),
                path=str(path),
                query=dict(query),
                token=str(token),
                findings=findings,
            )
        raise TypeError(
            "Pass a request object or keyword arguments, not positional arguments."
        )
    return DeepScanRequest(
        host=str(kwargs.pop("host")),
        path=str(kwargs.pop("path")),
        query=dict(kwargs.pop("query")),
        token=str(kwargs.pop("token")),
        findings=kwargs.pop("findings"),
    )


def _fetch_open_issues(*args: Any, **kwargs: Any) -> int | None:
    request = _coerce_fetch_request(*args, **kwargs)
    try:
        payload = _request_json(
            host=request.host,
            path=request.path,
            query=request.query,
            token=request.token,
        )
    except (
        urllib.error.URLError,
        RuntimeError,
        ValueError,
    ) as exc:  # pragma: no cover - network/runtime surface
        request.findings.append(f"DeepScan API request failed: {exc}")
        return None

    open_issues = extract_total_open(payload)
    if open_issues is None:
        request.findings.append(
            "DeepScan response did not include a parseable total issue count."
        )
        return None
    if open_issues != 0:
        request.findings.append(
            f"DeepScan reports {open_issues} open issues (expected 0)."
        )
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
        open_issues = _fetch_open_issues(
            host=host, path=path, query=query, token=token, findings=findings
        )

    status = "pass" if not findings else "fail"
    payload = {
        "status": status,
        "open_issues": open_issues,
        "open_issues_url": open_issues_url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    try:
        out_json = safe_output_path_in_workspace(
            args.out_json, "deepscan-zero/deepscan.json"
        )
        out_md = safe_output_path_in_workspace(args.out_md, "deepscan-zero/deepscan.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    out_md.write_text(_render_md(payload), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"), end="")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
