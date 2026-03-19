#!/usr/bin/env python3
from __future__ import absolute_import, division

from dataclasses import dataclass
import re
import time
from typing import Any, Dict, Optional, Tuple
import urllib.error

try:
    from ._security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace
except ImportError:  # pragma: no cover - direct script execution
    from _security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace

GITHUB_API_HOST = "api.github.com"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_TRANSIENT_HTTP_CODES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class GitHubRequest:
    owner: str
    repo: str
    sha: str
    token: str
    endpoint: str
    query: Optional[Dict[str, str]] = None
    attempts: int = 5


def _parse_repo(raw: str) -> Tuple[str, str]:
    text = (raw or "").strip()
    if "/" not in text:
        raise ValueError("Repo must be in owner/repo format.")
    owner, repo = text.split("/", 1)
    return (
        encode_identifier(owner, field_name="GitHub owner"),
        encode_identifier(repo, field_name="GitHub repo"),
    )


def _parse_sha(raw: str) -> str:
    sha = (raw or "").strip()
    if not _SHA_RE.fullmatch(sha):
        raise ValueError("Commit SHA must be a 7-64 char hex string.")
    return sha.lower()


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "reframe-quality-zero-gate",
    }


def _is_transient_http_error(exc: urllib.error.HTTPError) -> bool:
    return int(exc.code) in _TRANSIENT_HTTP_CODES


def _should_retry_http_error(*, exc: urllib.error.HTTPError, attempt: int, attempts: int) -> bool:
    return _is_transient_http_error(exc) and attempt < attempts


def _should_retry_url_error(*, attempt: int, attempts: int) -> bool:
    return attempt < attempts


def _next_retry_wait(wait_seconds: int) -> int:
    return min(wait_seconds * 2, 10)


def _request_payload_with_retry(request: GitHubRequest) -> Dict[str, Any]:
    wait_seconds = 1
    last_error: Optional[Exception] = None
    total_attempts = max(request.attempts, 1)

    for attempt in range(1, total_attempts + 1):
        try:
            payload, _headers = request_json_https(
                host=GITHUB_API_HOST,
                path=f"/repos/{request.owner}/{request.repo}/commits/{request.sha}/{request.endpoint}",
                headers={**_github_headers(request.token)},
                query=request.query,
                method="GET",
            )
            if not isinstance(payload, dict):
                raise RuntimeError(f"Unexpected GitHub {request.endpoint} response payload.")
            return payload
        except urllib.error.HTTPError as exc:
            last_error = exc
            if not _should_retry_http_error(exc=exc, attempt=attempt, attempts=total_attempts):
                raise
        except urllib.error.URLError as exc:
            last_error = exc
            if not _should_retry_url_error(attempt=attempt, attempts=total_attempts):
                raise

        time.sleep(wait_seconds)
        wait_seconds = _next_retry_wait(wait_seconds)

    if last_error is None:
        raise RuntimeError(f"Failed to query GitHub endpoint: {request.endpoint}")
    raise RuntimeError(f"Failed to query GitHub endpoint: {request.endpoint}") from last_error


def _api_get_check_runs(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _request_payload_with_retry(
        GitHubRequest(
            owner=owner,
            repo=repo,
            sha=sha,
            token=token,
            endpoint="check-runs",
            query={"per_page": "100"},
        )
    )


def _api_get_status(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _request_payload_with_retry(
        GitHubRequest(owner=owner, repo=repo, sha=sha, token=token, endpoint="status")
    )


def _check_run_context(run: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, str]]]:
    name = str(run.get("name") or "").strip()
    if not name:
        return None
    return name, {
        "state": str(run.get("status") or ""),
        "conclusion": str(run.get("conclusion") or ""),
        "source": "check_run",
    }


def _status_context(status: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, str]]]:
    name = str(status.get("context") or "").strip()
    if not name:
        return None
    state = str(status.get("state") or "")
    return name, {
        "state": state,
        "conclusion": state,
        "source": "status",
    }


def _collect_contexts(check_runs_payload: Dict[str, Any], status_payload: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    contexts: Dict[str, Dict[str, str]] = {}

    for run in check_runs_payload.get("check_runs", []) or []:
        entry = _check_run_context(run)
        if entry:
            key, value = entry
            contexts[key] = value

    for status in status_payload.get("statuses", []) or []:
        entry = _status_context(status)
        if entry:
            key, value = entry
            contexts[key] = value

    return contexts


def _check_run_failure(context: str, observed: Dict[str, str]) -> Optional[str]:
    state = observed.get("state")
    if state != "completed":
        return f"{context}: status={state}"

    conclusion = observed.get("conclusion")
    if conclusion != "success":
        return f"{context}: conclusion={conclusion}"
    return None


def _status_failure(context: str, observed: Dict[str, str]) -> Optional[str]:
    conclusion = observed.get("conclusion")
    if conclusion != "success":
        return f"{context}: state={conclusion}"
    return None


def _evaluate(required: list[str], contexts: Dict[str, Dict[str, str]]) -> tuple[str, list[str], list[str]]:
    missing: list[str] = []
    failed: list[str] = []

    for context in required:
        observed = contexts.get(context)
        if not observed:
            missing.append(context)
            continue

        if observed.get("source") == "check_run":
            failure = _check_run_failure(context, observed)
        else:
            failure = _status_failure(context, observed)
        if failure:
            failed.append(failure)

    status = "pass" if not missing and not failed else "fail"
    return status, missing, failed


__all__ = [
    "GITHUB_API_HOST",
    "GitHubRequest",
    "_SHA_RE",
    "_TRANSIENT_HTTP_CODES",
    "_api_get_check_runs",
    "_api_get_status",
    "_check_run_context",
    "_check_run_failure",
    "_collect_contexts",
    "_evaluate",
    "_github_headers",
    "_is_transient_http_error",
    "_next_retry_wait",
    "_parse_repo",
    "_parse_sha",
    "_request_payload_with_retry",
    "_should_retry_http_error",
    "_should_retry_url_error",
    "_status_context",
    "_status_failure",
    "encode_identifier",
    "request_json_https",
    "safe_output_path_in_workspace",
]
