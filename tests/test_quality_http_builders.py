from __future__ import absolute_import

import pytest

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod
from scripts.quality import check_sentry_zero as sentry_mod


def test_codacy_request_json_uses_fixed_host_and_validated_segments(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"total": 0}, {}

    monkeypatch.setattr(codacy_mod, "request_json_https", _fake_request_json_https)
    payload = codacy_mod._request_json(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="sample_credential",
        method="POST",
        data={},
    )

    if not (payload == {"total": 0}):
        raise AssertionError()

    if not (captured["host"] == "api.codacy.com"):
        raise AssertionError()

    if not (captured["path"] == "/api/v3/analysis/organizations/gh/Prekzursil/repositories/env-inspector/issues/search"):
        raise AssertionError()

    if not (captured["query"] == {"limit": "1"}):
        raise AssertionError()



def test_codacy_request_json_rejects_unsafe_identifier():
    with pytest.raises(ValueError, match="unsupported characters"):
        codacy_mod._request_json(
            provider="gh",
            owner="Prekzursil",
            repo="env/inspector",
            token="sample_credential",
            method="POST",
            data={},
        )


def test_deepscan_request_json_uses_fixed_host(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"open_issues": 0}, {}

    monkeypatch.setattr(deepscan_mod, "request_json_https", _fake_request_json_https)
    payload = deepscan_mod._request_json(
        host="deepscan.io",
        path="/api/projects/123/issues/open",
        query={"limit": "1"},
        token="sample_credential",
    )

    if not (payload == {"open_issues": 0}):
        raise AssertionError()

    if not (captured["host"] == "deepscan.io"):
        raise AssertionError()

    if not (captured["path"] == "/api/projects/123/issues/open"):
        raise AssertionError()

    if not (captured["query"] == {"limit": "1"}):
        raise AssertionError()



def test_sentry_request_project_issues_uses_fixed_host(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return [], {"x-hits": "0"}

    monkeypatch.setattr(sentry_mod, "request_json_https", _fake_request_json_https)
    issues, headers = sentry_mod._request_project_issues("my-org", "my-project", "token")

    if not (issues == []):
        raise AssertionError()

    if not (headers["x-hits"] == "0"):
        raise AssertionError()

    if not (captured["host"] == "sentry.io"):
        raise AssertionError()

    if not (captured["path"] == "/api/0/projects/my-org/my-project/issues/"):
        raise AssertionError()

    if not (captured["query"] == {"query": "is:unresolved", "limit": "1"}):
        raise AssertionError()

