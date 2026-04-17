"""Owned Sentry zero-gate regression tests from the PR 39 coverage set."""

import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.quality import check_sentry_zero as sentry_mod
from tests.assertions import ensure


def test_sentry_headers_and_unexpected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sentry helpers should parse headers and reject malformed payloads."""
    ensure(sentry_mod._hits_from_headers({}) is None)
    ensure(sentry_mod._hits_from_headers({"x-hits": "bad"}) is None)
    monkeypatch.setattr(
        sentry_mod,
        "request_json_https",
        lambda **kwargs: ({}, {"x-hits": "0"}),
    )
    with pytest.raises(RuntimeError, match="Unexpected Sentry response payload"):
        sentry_mod._request_project_issues("my-org", "proj", "token")


def test_sentry_main_rejects_workspace_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Sentry CLI should reject output paths that escape the workspace."""
    monkeypatch.chdir(tmp_path)
    invalid_args = SimpleNamespace(
        org="my-org",
        project=["proj"],
        token=f"{tmp_path.name}-token",
        out_json=str(tmp_path.parent / "escaped.json"),
        out_md="reports/sentry.md",
    )
    monkeypatch.setattr(sentry_mod, "_parse_args", lambda: invalid_args)
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
    ensure(sentry_mod.main() == 1)
    ensure("escapes workspace root" in capsys.readouterr().err)


def test_sentry_entrypoint_skips_when_config_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sentry entrypoint should exit successfully when configuration is absent."""
    helper_root = str(Path(sentry_mod.__file__).resolve().parent.parent)
    monkeypatch.setattr(
        sys,
        "path",
        [entry for entry in sys.path if entry != helper_root],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_sentry_zero.py",
            "--out-json",
            "reports/sentry.json",
            "--out-md",
            "reports/sentry.md",
        ],
    )
    monkeypatch.delenv("SENTRY_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_ORG", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_BACKEND", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT_WEB", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(Path(sentry_mod.__file__)), run_name="__main__")

    ensure(exc_info.value.code == 0)
