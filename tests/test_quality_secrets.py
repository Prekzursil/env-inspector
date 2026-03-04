from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

from scripts.quality import check_quality_secrets as secrets_mod


def test_apply_deepscan_policy_keeps_provider_requirements_by_default():
    required_secrets = ["SONAR_TOKEN", "DEEPSCAN_API_TOKEN"]
    required_vars = ["SENTRY_PROJECT", "DEEPSCAN_OPEN_ISSUES_URL"]

    out_secrets, out_vars = secrets_mod._apply_deepscan_policy(
        required_secrets,
        required_vars,
        policy_mode="provider_api",
    )

    assert out_secrets == required_secrets
    assert out_vars == required_vars


def test_apply_deepscan_policy_removes_deepscan_requirements_for_context_mode():
    out_secrets, out_vars = secrets_mod._apply_deepscan_policy(
        ["SONAR_TOKEN", "DEEPSCAN_API_TOKEN"],
        ["SENTRY_PROJECT", "DEEPSCAN_OPEN_ISSUES_URL"],
        policy_mode="github_check_context",
    )

    assert "DEEPSCAN_API_TOKEN" not in out_secrets
    assert "DEEPSCAN_OPEN_ISSUES_URL" not in out_vars


def test_quality_secrets_main_respects_context_mode_and_reports_mode(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPSCAN_POLICY_MODE", "github_check_context")
    monkeypatch.setenv("SONAR_TOKEN", "tok")
    monkeypatch.setenv("CODACY_API_TOKEN", "tok")
    monkeypatch.setenv("SNYK_TOKEN", "tok")
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "tok")
    monkeypatch.setenv("SENTRY_ORG", "org")
    monkeypatch.setenv("SENTRY_PROJECT", "project")
    monkeypatch.delenv("DEEPSCAN_API_TOKEN", raising=False)
    monkeypatch.delenv("DEEPSCAN_OPEN_ISSUES_URL", raising=False)

    args = SimpleNamespace(
        required_secret=[],
        required_var=[],
        strict=True,
        out_json="reports/secrets.json",
        out_md="reports/secrets.md",
    )
    monkeypatch.setattr(secrets_mod, "_parse_args", lambda: args)

    rc = secrets_mod.main()

    assert rc == 0
    payload = json.loads((tmp_path / "reports" / "secrets.json").read_text(encoding="utf-8"))
    assert payload["status"] == "pass"
    assert payload["deepscan_policy_mode"] == "github_check_context"
    assert "DEEPSCAN_API_TOKEN" not in payload["required_secrets"]
    assert "DEEPSCAN_OPEN_ISSUES_URL" not in payload["required_vars"]


def test_quality_secrets_main_fails_when_provider_mode_missing_deepscan(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPSCAN_POLICY_MODE", "provider_api")
    monkeypatch.setenv("SONAR_TOKEN", "tok")
    monkeypatch.setenv("CODACY_API_TOKEN", "tok")
    monkeypatch.setenv("SNYK_TOKEN", "tok")
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "tok")
    monkeypatch.setenv("SENTRY_ORG", "org")
    monkeypatch.setenv("SENTRY_PROJECT", "project")
    monkeypatch.delenv("DEEPSCAN_API_TOKEN", raising=False)
    monkeypatch.delenv("DEEPSCAN_OPEN_ISSUES_URL", raising=False)

    args = SimpleNamespace(
        required_secret=[],
        required_var=[],
        strict=True,
        out_json="reports/secrets.json",
        out_md="reports/secrets.md",
    )
    monkeypatch.setattr(secrets_mod, "_parse_args", lambda: args)

    rc = secrets_mod.main()

    assert rc == 1
    payload = json.loads((tmp_path / "reports" / "secrets.json").read_text(encoding="utf-8"))
    assert payload["status"] == "fail"
    assert "DEEPSCAN_API_TOKEN" in payload["missing_secrets"]
    assert "DEEPSCAN_OPEN_ISSUES_URL" in payload["missing_vars"]