#!/usr/bin/env python3
from __future__ import absolute_import

import argparse
import json
import os
import re
import sys
import time
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from ._security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace
except ImportError:  # pragma: no cover - direct script execution
    from _security_imports import encode_identifier, request_json_https, safe_output_path_in_workspace

GITHUB_API_HOST = "api.github.com"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_TRANSIENT_HTTP_CODES = {429, 500, 502, 503, 504}


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


def _request_payload_with_retry(
    *,
    owner: str,
    repo: str,
    sha: str,
    token: str,
    endpoint: str,
    query: Optional[Dict[str, str]] = None,
    attempts: int = 5,
) -> Dict[str, Any]:
    wait_seconds = 1
    last_error: Optional[Exception] = None
    total_attempts = max(attempts, 1)

    for attempt in range(1, total_attempts + 1):
        try:
            payload, _headers = request_json_https(
                host=GITHUB_API_HOST,
                path=f"/repos/{owner}/{repo}/commits/{sha}/{endpoint}",
                headers={**_github_headers(token)},
                query=query,
                method="GET",
            )
            if not isinstance(payload, dict):
                raise RuntimeError(f"Unexpected GitHub {endpoint} response payload.")
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
        raise RuntimeError(f"Failed to query GitHub endpoint: {endpoint}")
    raise RuntimeError(f"Failed to query GitHub endpoint: {endpoint}") from last_error


def _api_get_check_runs(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _request_payload_with_retry(
        owner=owner,
        repo=repo,
        sha=sha,
        token=token,
        endpoint="check-runs",
        query={"per_page": "100"},
    )


def _api_get_status(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _request_payload_with_retry(
        owner=owner,
        repo=repo,
        sha=sha,
        token=token,
        endpoint="status",
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


def _evaluate(required: List[str], contexts: Dict[str, Dict[str, str]]) -> Tuple[str, List[str], List[str]]:
    missing: List[str] = []
    failed: List[str] = []

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


def _collect_until_settled(
    *,
    owner_slug: str,
    repo_slug: str,
    repo_arg: str,
    sha: str,
    token: str,
    required: List[str],
    timeout_seconds: int,
    poll_seconds: int,
) -> Dict[str, Any]:
    deadline = time.time() + max(timeout_seconds, 1)
    final_payload: Optional[Dict[str, Any]] = None

    while time.time() <= deadline:
        check_runs = _api_get_check_runs(owner=owner_slug, repo=repo_slug, sha=sha, token=token)
        statuses = _api_get_status(owner=owner_slug, repo=repo_slug, sha=sha, token=token)
        contexts = _collect_contexts(check_runs, statuses)

        final_payload = _snapshot(repo_arg=repo_arg, sha=sha, required=required, contexts=contexts)
        if not _should_wait(final_payload):
            break
        time.sleep(max(poll_seconds, 1))

    if final_payload is None:
        raise SystemExit("No payload collected")
    return final_payload


def main() -> int:
    args = _parse_args()
    required = _required_contexts(args)
    token = _github_token()

    try:
        owner_slug, repo_slug = _parse_repo(args.repo)
        sha = _parse_sha(args.sha)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    final_payload = _collect_until_settled(
        owner_slug=owner_slug,
        repo_slug=repo_slug,
        repo_arg=args.repo,
        sha=sha,
        token=token,
        required=required,
        timeout_seconds=args.timeout_seconds,
        poll_seconds=args.poll_seconds,
    )

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "quality-zero-gate/required-checks.json")
        out_md = safe_output_path_in_workspace(args.out_md, "quality-zero-gate/required-checks.md")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(final_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(_render_md(final_payload), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"), end="")

    return 0 if final_payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

