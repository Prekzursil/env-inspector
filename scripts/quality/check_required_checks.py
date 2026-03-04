#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import encode_identifier, request_json_https, safe_output_path_in_workspace

GITHUB_API_HOST = "api.github.com"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


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


def _parse_repo(raw: str) -> tuple[str, str]:
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


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "reframe-quality-zero-gate",
    }


def _api_get_check_runs(*, owner: str, repo: str, sha: str, token: str) -> dict[str, Any]:
    payload, _headers = request_json_https(
        host=GITHUB_API_HOST,
        path=f"/repos/{owner}/{repo}/commits/{sha}/check-runs",
        headers={
            **_github_headers(token),
        },
        query={"per_page": "100"},
        method="GET",
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected GitHub check-runs response payload.")
    return payload


def _api_get_status(*, owner: str, repo: str, sha: str, token: str) -> dict[str, Any]:
    payload, _headers = request_json_https(
        host=GITHUB_API_HOST,
        path=f"/repos/{owner}/{repo}/commits/{sha}/status",
        headers={
            **_github_headers(token),
        },
        method="GET",
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected GitHub status response payload.")
    return payload


def _collect_contexts(check_runs_payload: dict[str, Any], status_payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    contexts: dict[str, dict[str, str]] = {}

    for run in check_runs_payload.get("check_runs", []) or []:
        name = str(run.get("name") or "").strip()
        if not name:
            continue
        contexts[name] = {
            "state": str(run.get("status") or ""),
            "conclusion": str(run.get("conclusion") or ""),
            "source": "check_run",
        }

    for status in status_payload.get("statuses", []) or []:
        name = str(status.get("context") or "").strip()
        if not name:
            continue
        contexts[name] = {
            "state": str(status.get("state") or ""),
            "conclusion": str(status.get("state") or ""),
            "source": "status",
        }

    return contexts


def _evaluate(required: list[str], contexts: dict[str, dict[str, str]]) -> tuple[str, list[str], list[str]]:
    missing: list[str] = []
    failed: list[str] = []

    for context in required:
        observed = contexts.get(context)
        if not observed:
            missing.append(context)
            continue

        source = observed.get("source")
        if source == "check_run":
            state = observed.get("state")
            conclusion = observed.get("conclusion")
            if state != "completed":
                failed.append(f"{context}: status={state}")
            elif conclusion != "success":
                failed.append(f"{context}: conclusion={conclusion}")
        else:
            conclusion = observed.get("conclusion")
            if conclusion != "success":
                failed.append(f"{context}: state={conclusion}")

    status = "pass" if not missing and not failed else "fail"
    return status, missing, failed


def _render_md(payload: dict) -> str:
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


def main() -> int:
    args = _parse_args()
    token = (os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "")).strip()
    required = [item.strip() for item in args.required_context if item.strip()]

    if not required:
        raise SystemExit("At least one --required-context is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN or GH_TOKEN is required")
    try:
        owner_slug, repo_slug = _parse_repo(args.repo)
        sha = _parse_sha(args.sha)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    deadline = time.time() + max(args.timeout_seconds, 1)

    final_payload: dict[str, Any] | None = None
    while time.time() <= deadline:
        check_runs = _api_get_check_runs(owner=owner_slug, repo=repo_slug, sha=sha, token=token)
        statuses = _api_get_status(owner=owner_slug, repo=repo_slug, sha=sha, token=token)
        contexts = _collect_contexts(check_runs, statuses)
        status, missing, failed = _evaluate(required, contexts)

        final_payload = {
            "status": status,
            "repo": args.repo,
            "sha": sha,
            "required": required,
            "missing": missing,
            "failed": failed,
            "contexts": contexts,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

        if status == "pass":
            break

        # wait only while there are missing contexts or in-progress check-runs
        in_progress = any(v.get("state") != "completed" for v in contexts.values() if v.get("source") == "check_run")
        if not missing and not in_progress:
            break
        time.sleep(max(args.poll_seconds, 1))

    if final_payload is None:
        raise SystemExit("No payload collected")

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
