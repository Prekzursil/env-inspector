#!/usr/bin/env python3
from __future__ import absolute_import, division

import argparse
import os
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SettledChecksRequest:
    owner_slug: str
    repo_slug: str
    repo_arg: str
    sha: str
    token: str
    required: List[str]
    timeout_seconds: int
    poll_seconds: int


try:
    from . import _required_checks_http as _http
except ImportError:  # pragma: no cover - direct script execution
    import _required_checks_http as _http  # type: ignore

GitHubRequest = _http.GitHubRequest
GITHUB_API_HOST = _http.GITHUB_API_HOST
_SHA_RE = _http._SHA_RE
_TRANSIENT_HTTP_CODES = _http._TRANSIENT_HTTP_CODES
_api_get_check_runs = _http._api_get_check_runs
_api_get_status = _http._api_get_status
_check_run_context = _http._check_run_context
_check_run_failure = _http._check_run_failure
_collect_contexts = _http._collect_contexts
_evaluate = _http._evaluate
_github_headers = _http._github_headers
_is_transient_http_error = _http._is_transient_http_error
_next_retry_wait = _http._next_retry_wait
_parse_repo = _http._parse_repo
_parse_sha = _http._parse_sha
_request_payload_with_retry = _http._request_payload_with_retry
_should_retry_http_error = _http._should_retry_http_error
_should_retry_url_error = _http._should_retry_url_error
_status_context = _http._status_context
_status_failure = _http._status_failure
encode_identifier = _http.encode_identifier
request_json_https = _http.request_json_https
safe_output_path_in_workspace = _http.safe_output_path_in_workspace


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wait for required GitHub check contexts and assert they are successful.")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--sha", required=True, help="commit SHA")
    parser.add_argument("--required-context", action="append", default=[], help="Required context name")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=20)
    parser.add_argument("--out-json", default="quality-zero-gate/required-checks.json")
    parser.add_argument("--out-md", default="quality-zero-gate/required-checks.md")
    return parser.parse_args()


def _render_md(payload: Dict[str, Any]) -> str:
    lines = [
        "# Quality Zero Gate - Required Contexts",
        "",
        f"- Status: `{payload['status']}`",
        f"- Repo/SHA: `{payload['repo']}@{payload['sha']}`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Missing contexts",
    ]

    missing = payload.get("missing") or []
    if missing:
        lines.extend(f"- `{name}`" for name in missing)
    else:
        lines.append("- None")

    lines.extend(["", "## Failed contexts"])
    failed = payload.get("failed") or []
    if failed:
        lines.extend(f"- {entry}" for entry in failed)
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def _required_contexts(args: argparse.Namespace) -> List[str]:
    required = [item.strip() for item in args.required_context if item.strip()]
    if not required:
        raise SystemExit("At least one --required-context is required")
    return required


def _github_token() -> str:
    token = (os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "")).strip()
    if not token:
        raise SystemExit("GITHUB_TOKEN or GH_TOKEN is required")
    return token


def _snapshot(
    *,
    repo_arg: str,
    sha: str,
    required: List[str],
    contexts: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    status, missing, failed = _evaluate(required, contexts)
    return {
        "status": status,
        "repo": repo_arg,
        "sha": sha,
        "required": required,
        "missing": missing,
        "failed": failed,
        "contexts": contexts,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def _has_in_progress_check_run(contexts: Dict[str, Dict[str, str]]) -> bool:
    for observed in contexts.values():
        if observed.get("source") == "check_run" and observed.get("state") != "completed":
            return True
    return False


def _should_wait(payload: Dict[str, Any]) -> bool:
    if payload["status"] == "pass":
        return False
    if payload["missing"]:
        return True
    return _has_in_progress_check_run(payload["contexts"])


def _collect_until_settled(request: SettledChecksRequest) -> Dict[str, Any]:
    deadline = time.time() + max(request.timeout_seconds, 1)
    final_payload: Optional[Dict[str, Any]] = None

    while time.time() <= deadline:
        check_runs = _api_get_check_runs(owner=request.owner_slug, repo=request.repo_slug, sha=request.sha, token=request.token)
        statuses = _api_get_status(owner=request.owner_slug, repo=request.repo_slug, sha=request.sha, token=request.token)
        contexts = _collect_contexts(check_runs, statuses)

        final_payload = _snapshot(repo_arg=request.repo_arg, sha=request.sha, required=request.required, contexts=contexts)
        if not _should_wait(final_payload):
            break
        time.sleep(max(request.poll_seconds, 1))

    if final_payload is None:
        raise SystemExit("No payload collected")
    return final_payload
