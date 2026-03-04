#!/usr/bin/env python3
from __future__ import annotations, absolute_import, division

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import safe_output_path_in_workspace

DEFAULT_REQUIRED_SECRETS = [
    "SONAR_TOKEN",
    "CODACY_API_TOKEN",
    "SNYK_TOKEN",
    "SENTRY_AUTH_TOKEN",
    "DEEPSCAN_API_TOKEN",
]

DEFAULT_REQUIRED_VARS = [
    "SENTRY_ORG",
    "SENTRY_PROJECT",
    "DEEPSCAN_OPEN_ISSUES_URL",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate required quality-gate secrets/variables are configured.")
    parser.add_argument("--required-secret", action="append", default=[], help="Additional required secret env var name")
    parser.add_argument("--required-var", action="append", default=[], help="Additional required variable env var name")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when required secrets/vars are missing. Default mode only reports missing items.",
    )
    parser.add_argument("--out-json", default="quality-secrets/secrets.json", help="Output JSON path")
    parser.add_argument("--out-md", default="quality-secrets/secrets.md", help="Output markdown path")
    return parser.parse_args()


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = str(item or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _apply_deepscan_policy(
    required_secrets: list[str],
    required_vars: list[str],
    *,
    policy_mode: str,
) -> tuple[list[str], list[str]]:
    if policy_mode != "github_check_context":
        return required_secrets, required_vars

    filtered_secrets = [name for name in required_secrets if name != "DEEPSCAN_API_TOKEN"]
    filtered_vars = [name for name in required_vars if name != "DEEPSCAN_OPEN_ISSUES_URL"]
    return filtered_secrets, filtered_vars


def evaluate_env(required_secrets: list[str], required_vars: list[str]) -> dict[str, list[str]]:
    missing_secrets = [name for name in required_secrets if not str(os.environ.get(name, "")).strip()]
    missing_vars = [name for name in required_vars if not str(os.environ.get(name, "")).strip()]
    present_secrets = [name for name in required_secrets if name not in missing_secrets]
    present_vars = [name for name in required_vars if name not in missing_vars]
    return {
        "missing_secrets": missing_secrets,
        "missing_vars": missing_vars,
        "present_secrets": present_secrets,
        "present_vars": present_vars,
    }


def _render_md(payload: dict) -> str:
    lines = [
        "# Quality Secrets Preflight",
        "",
        f"- Status: `{payload['status']}`",
        f"- Strict mode: `{payload.get('strict', False)}`",
        f"- DeepScan policy mode: `{payload.get('deepscan_policy_mode', '')}`",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        "",
        "## Missing secrets",
    ]
    missing_secrets = payload.get("missing_secrets") or []
    if missing_secrets:
        lines.extend(f"- `{name}`" for name in missing_secrets)
    else:
        lines.append("- None")

    lines.extend(["", "## Missing variables"])
    missing_vars = payload.get("missing_vars") or []
    if missing_vars:
        lines.extend(f"- `{name}`" for name in missing_vars)
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = _parse_args()
    deepscan_mode = str(os.environ.get("DEEPSCAN_POLICY_MODE", "provider_api")).strip().lower()

    required_secrets = _dedupe(DEFAULT_REQUIRED_SECRETS + list(args.required_secret or []))
    required_vars = _dedupe(DEFAULT_REQUIRED_VARS + list(args.required_var or []))
    required_secrets, required_vars = _apply_deepscan_policy(
        required_secrets,
        required_vars,
        policy_mode=deepscan_mode,
    )

    result = evaluate_env(required_secrets, required_vars)
    has_missing = bool(result["missing_secrets"] or result["missing_vars"])
    status = "fail" if args.strict and has_missing else "pass"
    payload = {
        "status": status,
        "strict": bool(args.strict),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "required_secrets": required_secrets,
        "required_vars": required_vars,
        "deepscan_policy_mode": deepscan_mode,
        **result,
    }

    try:
        out_json = safe_output_path_in_workspace(args.out_json, "quality-secrets/secrets.json")
        out_md = safe_output_path_in_workspace(args.out_md, "quality-secrets/secrets.md")
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
