#!/usr/bin/env python3
"""Check deepscan zero module."""

import argparse
import os
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, cast
from collections.abc import Callable

TOTAL_KEYS = {"total", "totalItems", "total_items", "count", "hits", "open_issues"}

RequestJsonHttps = Callable[..., Tuple[Any, Dict[str, str]]]
SplitValidatedHttpsUrl = Callable[..., Tuple[str, str, Dict[str, str]]]


@dataclass(frozen=True)
class DeepScanRequest:
    """Parameters for a DeepScan API open-issues request."""

    host: str
    path: str
    query: Dict[str, str]
    token: str
    findings: List[str]


try:
    from ._module_loader import load_quality_module
except ImportError:  # pragma: no cover - direct script execution
    from _module_loader import load_quality_module  # type: ignore


_security_imports = load_quality_module(
    "scripts.quality._security_imports", "_security_imports"
)
request_json_https = cast(RequestJsonHttps, _security_imports.request_json_https)
split_validated_https_url = cast(
    SplitValidatedHttpsUrl,
    _security_imports.split_validated_https_url,
)
emit_zero_report = _security_imports.emit_zero_report
ZeroReportSpec = _security_imports.ZeroReportSpec
render_findings_md = _security_imports.render_findings_md


def _parse_args() -> argparse.Namespace:
    """Parse args."""
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
    """Extract total open."""
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
    """Request json."""
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
    """Resolve deepscan endpoint."""
    return split_validated_https_url(
        open_issues_url,
        allowed_host_suffixes={"deepscan.io"},
    )


def _coerce_fetch_request(*args: Any, **kwargs: Any) -> DeepScanRequest:
    """Coerce fetch request."""
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
    """Fetch open issues."""
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


def _render_md(payload: Dict[str, Any]) -> str:
    """Render md."""
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
    return render_findings_md(lines, payload.get("findings") or [])


def main() -> int:
    """Main."""
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

    return emit_zero_report(
        ZeroReportSpec(
            out_json_arg=args.out_json,
            out_md_arg=args.out_md,
            json_fallback="deepscan-zero/deepscan.json",
            md_fallback="deepscan-zero/deepscan.md",
            payload=payload,
            rendered_md=_render_md(payload),
            passed=status == "pass",
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
