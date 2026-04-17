#!/usr/bin/env python3
"""Required-check gate wrapper for the shared GitHub context helpers."""

import argparse
import importlib
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_impl() -> Any:
    """Load the reusable required-checks implementation module."""
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
encode_identifier = _impl.encode_identifier
request_json_https = _impl.request_json_https
safe_output_path_in_workspace = _impl.safe_output_path_in_workspace


def _impl_helper(name: str) -> Any:
    """Return a helper exported by the reusable required-checks module."""
    return getattr(_impl, name)


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the required-checks gate."""
    parser = argparse.ArgumentParser(
        description=(
            "Wait for required GitHub check contexts and assert they are successful."
        )
    )
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--sha", required=True, help="commit SHA")
    parser.add_argument(
        "--required-context",
        action="append",
        default=[],
        help="Required context name",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=20)
    parser.add_argument("--out-json", default="quality-zero-gate/required-checks.json")
    parser.add_argument("--out-md", default="quality-zero-gate/required-checks.md")
    return parser.parse_args()


def _parse_repo(raw: str) -> tuple[str, str]:
    """Validate and normalize an owner/repo argument for GitHub API calls."""
    return _impl_helper("_parse_repo")(raw)


def _parse_sha(raw: str) -> str:
    """Validate and normalize the target commit SHA."""
    return _impl_helper("_parse_sha")(raw)


def _github_headers(token: str) -> dict[str, str]:
    """Build GitHub API headers for the required-checks requests."""
    return _impl_helper("_github_headers")(token)


def _is_transient_http_error(exc: urllib.error.HTTPError) -> bool:
    """Return whether an HTTP error should be treated as retryable."""
    return _impl_helper("_is_transient_http_error")(exc)


def _should_retry_http_error(
    *,
    exc: urllib.error.HTTPError,
    attempt: int,
    attempts: int,
) -> bool:
    """Return whether the wrapper should retry after an HTTP error."""
    return _impl_helper("_should_retry_http_error")(
        exc=exc,
        attempt=attempt,
        attempts=attempts,
    )


def _should_retry_url_error(*, attempt: int, attempts: int) -> bool:
    """Return whether the wrapper should retry after a URL transport error."""
    return _impl_helper("_should_retry_url_error")(
        attempt=attempt,
        attempts=attempts,
    )


def _next_retry_wait(wait_seconds: int) -> int:
    """Calculate the next bounded retry delay."""
    return _impl_helper("_next_retry_wait")(wait_seconds)


def _request_payload_with_retry(request: Any) -> dict[str, Any]:
    """Fetch one GitHub payload with retry semantics applied."""
    return _impl_helper("_request_payload_with_retry")(request)


def _api_get_check_runs(
    *,
    owner: str,
    repo: str,
    sha: str,
    token: str,
) -> dict[str, Any]:
    """Fetch the check-run payload for the target commit SHA."""
    return _impl_helper("_api_get_check_runs")(
        owner=owner,
        repo=repo,
        sha=sha,
        token=token,
    )


def _api_get_status(*, owner: str, repo: str, sha: str, token: str) -> dict[str, Any]:
    """Fetch the commit-status payload for the target commit SHA."""
    return _impl_helper("_api_get_status")(
        owner=owner,
        repo=repo,
        sha=sha,
        token=token,
    )


def _check_run_context(run: dict[str, Any]) -> tuple[str, dict[str, str]] | None:
    """Normalize one check-run entry into the shared context shape."""
    return _impl_helper("_check_run_context")(run)


def _status_context(status: dict[str, Any]) -> tuple[str, dict[str, str]] | None:
    """Normalize one status entry into the shared context shape."""
    return _impl_helper("_status_context")(status)


def _collect_contexts(
    check_runs_payload: dict[str, Any],
    status_payload: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Merge check-run and status payloads into one context map."""
    return _impl_helper("_collect_contexts")(check_runs_payload, status_payload)


def _check_run_failure(context: str, observed: dict[str, str]) -> str | None:
    """Return the failure summary for a check-run context, if any."""
    return _impl_helper("_check_run_failure")(context, observed)


def _status_failure(context: str, observed: dict[str, str]) -> str | None:
    """Return the failure summary for a commit-status context, if any."""
    return _impl_helper("_status_failure")(context, observed)


def _evaluate(
    required: list[str],
    contexts: dict[str, dict[str, str]],
) -> tuple[str, list[str], list[str]]:
    """Evaluate whether every required context is present and successful."""
    return _impl_helper("_evaluate")(required, contexts)


def _render_md(payload: dict[str, Any]) -> str:
    """Render the markdown summary for the required-check gate."""
    return _impl_helper("_render_md")(payload)


def _required_contexts(args: argparse.Namespace) -> list[str]:
    """Return the normalized list of required check context names."""
    return _impl_helper("_required_contexts")(args)


def _github_token() -> str:
    """Load the GitHub token used for required-check polling."""
    return _impl_helper("_github_token")()


def _snapshot(*args, **kwargs) -> dict[str, Any]:
    """Build the current required-check snapshot payload."""
    return _impl_helper("_snapshot")(*args, **kwargs)


def _has_in_progress_check_run(contexts: dict[str, dict[str, str]]) -> bool:
    """Return whether any observed check run is still in progress."""
    return _impl_helper("_has_in_progress_check_run")(contexts)


def _should_wait(payload: dict[str, Any]) -> bool:
    """Return whether polling should continue for the current snapshot."""
    return _impl_helper("_should_wait")(payload)


def _collect_until_settled(request: Any) -> dict[str, Any]:
    """Poll GitHub until the required contexts settle or time out."""
    return _impl_helper("_collect_until_settled")(request)


def main() -> int:
    """Run the required-check gate and write its report artifacts."""
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
        out_json = safe_output_path_in_workspace(
            args.out_json,
            "quality-zero-gate/required-checks.json",
        )
        out_md = safe_output_path_in_workspace(
            args.out_md,
            "quality-zero-gate/required-checks.md",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(final_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out_md.write_text(_render_md(final_payload), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"), end="")

    return 0 if final_payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
