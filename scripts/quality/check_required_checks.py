#!/usr/bin/env python3
from __future__ import absolute_import, division

import argparse
import importlib
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_impl() -> Any:
    try:
        return importlib.import_module("scripts.quality._required_checks_impl")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_required_checks_impl")


_impl = _load_impl()
GitHubRequest = _impl.GitHubRequest
SettledChecksRequest = _impl.SettledChecksRequest
GITHUB_API_HOST = _impl.GITHUB_API_HOST
_SHA_RE = _impl._SHA_RE
_TRANSIENT_HTTP_CODES = _impl._TRANSIENT_HTTP_CODES
encode_identifier = _impl.encode_identifier
request_json_https = _impl.request_json_https
safe_output_path_in_workspace = _impl.safe_output_path_in_workspace


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
    return _impl._parse_repo(raw)


def _parse_sha(raw: str) -> str:
    return _impl._parse_sha(raw)


def _github_headers(token: str) -> Dict[str, str]:
    return _impl._github_headers(token)


def _is_transient_http_error(exc: urllib.error.HTTPError) -> bool:
    return _impl._is_transient_http_error(exc)


def _should_retry_http_error(*, exc: urllib.error.HTTPError, attempt: int, attempts: int) -> bool:
    return _impl._should_retry_http_error(exc=exc, attempt=attempt, attempts=attempts)


def _should_retry_url_error(*, attempt: int, attempts: int) -> bool:
    return _impl._should_retry_url_error(attempt=attempt, attempts=attempts)


def _next_retry_wait(wait_seconds: int) -> int:
    return _impl._next_retry_wait(wait_seconds)


def _request_payload_with_retry(request: GitHubRequest) -> Dict[str, Any]:
    return _impl._request_payload_with_retry(request)


def _api_get_check_runs(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _impl._api_get_check_runs(owner=owner, repo=repo, sha=sha, token=token)


def _api_get_status(*, owner: str, repo: str, sha: str, token: str) -> Dict[str, Any]:
    return _impl._api_get_status(owner=owner, repo=repo, sha=sha, token=token)


def _check_run_context(run: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, str]]]:
    return _impl._check_run_context(run)


def _status_context(status: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, str]]]:
    return _impl._status_context(status)


def _collect_contexts(check_runs_payload: Dict[str, Any], status_payload: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    return _impl._collect_contexts(check_runs_payload, status_payload)


def _check_run_failure(context: str, observed: Dict[str, str]) -> Optional[str]:
    return _impl._check_run_failure(context, observed)


def _status_failure(context: str, observed: Dict[str, str]) -> Optional[str]:
    return _impl._status_failure(context, observed)


def _evaluate(required: List[str], contexts: Dict[str, Dict[str, str]]) -> Tuple[str, List[str], List[str]]:
    return _impl._evaluate(required, contexts)


def _render_md(payload: Dict[str, Any]) -> str:
    return _impl._render_md(payload)


def _required_contexts(args: argparse.Namespace) -> List[str]:
    return _impl._required_contexts(args)


def _github_token() -> str:
    return _impl._github_token()


def _snapshot(*args, **kwargs) -> Dict[str, Any]:
    return _impl._snapshot(*args, **kwargs)


def _has_in_progress_check_run(contexts: Dict[str, Dict[str, str]]) -> bool:
    return _impl._has_in_progress_check_run(contexts)


def _should_wait(payload: Dict[str, Any]) -> bool:
    return _impl._should_wait(payload)


def _collect_until_settled(request: SettledChecksRequest) -> Dict[str, Any]:
    return _impl._collect_until_settled(request)


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
        SettledChecksRequest(
            owner_slug=owner_slug,
            repo_slug=repo_slug,
            repo_arg=args.repo,
            sha=sha,
            token=token,
            required=required,
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
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
