"""Test quality branch coverage module."""

import argparse
import urllib.error
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_sentry_zero as sentry_mod
from tests.assertions import ensure


def _empty_token() -> str:
    """Empty token."""
    return ""


def _fixture_token() -> str:
    """Fixture token."""
    return "-".join(("fixture", "token"))


def _http_error(code: int, msg: str) -> urllib.error.HTTPError:
    """Http error."""
    return urllib.error.HTTPError(
        url="https://sentry.io",
        code=code,
        msg=msg,
        hdrs=Message(),
        fp=None,
    )


def test_codacy_extract_total_open_handles_nested_and_missing_counts():
    """Test codacy extract total open handles nested and missing counts."""
    payload = {"outer": [{"nested": {"open_issues": 7}}, {"other": "x"}]}
    case = TestCase()

    case.assertEqual(codacy_mod.extract_total_open(payload), 7)
    case.assertEqual(codacy_mod.extract_total_open({"pagination": {"total": 4}}), 4)
    case.assertIsNone(codacy_mod.extract_total_open({"outer": [{"nested": "value"}]}))


def test_codacy_main_returns_error_for_invalid_output_path(
    tmp_path: Path, monkeypatch, capsys
):
    """Test codacy main returns error for invalid output path."""
    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_empty_token(),
        out_json=str(tmp_path.parent / "escaped.json"),
        out_md="reports/codacy.md",
    )
    monkeypatch.setattr(codacy_mod, "_parse_args", lambda: args)

    rc = codacy_mod.main()

    ensure(rc == 1)
    ensure("escapes workspace root" in capsys.readouterr().err)


def test_sentry_collect_projects_prefers_args_and_env_fallback():
    """Test sentry collect projects prefers args and env fallback."""
    args_with_projects = cast(
        argparse.Namespace, SimpleNamespace(project=["backend", "web"])
    )
    args_without_projects = cast(argparse.Namespace, SimpleNamespace(project=[]))

    ensure(sentry_mod._collect_projects(args_with_projects, {}) == ["backend", "web"])
    ensure(
        sentry_mod._collect_projects(
            args_without_projects,
            {"SENTRY_PROJECT_BACKEND": "backend", "SENTRY_PROJECT_WEB": "web"},
        )
        == ["backend", "web"]
    )


def test_sentry_scan_projects_covers_header_fallback_and_failures(monkeypatch):
    """Test sentry scan projects covers header fallback and failures."""

    def _fake_request_project_issues(_org: str, project: str, token: str):
        """Fake request project issues."""
        return [{"id": "1"}], {}

    monkeypatch.setattr(
        sentry_mod, "_request_project_issues", _fake_request_project_issues
    )

    mode, project_results, findings, failures = sentry_mod._scan_projects(
        "org", ["proj"], "token"
    )

    ensure(mode == "strict")
    ensure(project_results == [{"project": "proj", "unresolved": 1}])
    ensure(not findings)
    ensure(any("no X-Hits" in item for item in failures))
    ensure(any("expected 0" in item for item in failures))


def test_sentry_scan_projects_handles_http_404_and_http_500(monkeypatch):
    """Test sentry scan projects handles http 404 and http 500."""

    def _raise_404(org: str, project: str, token: str):
        """Raise 404."""
        raise _http_error(404, "Not Found")

    monkeypatch.setattr(sentry_mod, "_request_project_issues", _raise_404)
    mode_404, project_results_404, findings_404, failures_404 = (
        sentry_mod._scan_projects("org", ["proj"], "token")
    )

    ensure(mode_404 == "skipped")
    ensure(not project_results_404)
    ensure(not failures_404)
    ensure(findings_404 and "HTTP 404" in findings_404[0])

    def _raise_500(org: str, project: str, token: str):
        """Raise 500."""
        raise _http_error(500, "Err")

    monkeypatch.setattr(sentry_mod, "_request_project_issues", _raise_500)
    mode_500, project_results_500, findings_500, failures_500 = (
        sentry_mod._scan_projects("org", ["proj"], "token")
    )

    ensure(mode_500 == "error")
    ensure(not project_results_500)
    ensure(not findings_500)
    ensure(failures_500 and "HTTP 500" in failures_500[0])


def test_sentry_main_strict_mode_pass_and_fail(tmp_path: Path, monkeypatch):
    """Test sentry main strict mode pass and fail."""
    monkeypatch.chdir(tmp_path)

    args = SimpleNamespace(
        org="my-org",
        project=["proj"],
        token=_fixture_token(),
        out_json="reports/sentry.json",
        out_md="reports/sentry.md",
    )
    monkeypatch.setattr(sentry_mod, "_parse_args", lambda: args)
    monkeypatch.setattr(
        sentry_mod,
        "_scan_projects",
        lambda org, projects, token: (
            "strict",
            [{"project": "proj", "unresolved": 0}],
            [],
            [],
        ),
    )

    ensure(sentry_mod.main() == 0)
    ensure((tmp_path / "reports" / "sentry.json").exists())

    monkeypatch.setattr(
        sentry_mod,
        "_scan_projects",
        lambda org, projects, token: (
            "error",
            [{"project": "proj", "unresolved": 1}],
            [],
            ["failure"],
        ),
    )
    ensure(sentry_mod.main() == 1)
