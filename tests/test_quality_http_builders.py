from __future__ import absolute_import, division

import os
import pytest

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod
from scripts.quality import check_sentry_zero as sentry_mod

def _expect(condition, message: str = "") -> None:
    if not condition: raise AssertionError(message)



def test_codacy_request_json_uses_fixed_host_and_validated_segments(monkeypatch):
    captured: dict[str, object] = {}
    auth_value = os.environ.get("QUALITY_GATE_TEST_AUTH", "placeholder-value")

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"total": 0}, {}

    monkeypatch.setattr(codacy_mod, "request_json_https", _fake_request_json_https)
    payload = codacy_mod._request_json(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=auth_value,
        method="POST",
        data={},
    )

    _expect(payload == {"total": 0})

    _expect(captured["host"] == "api.codacy.com")

    _expect(captured["path"] == "/api/v3/analysis/organizations/gh/Prekzursil/repositories/env-inspector/issues/search")

    _expect(captured["query"] == {"limit": "1"})



def test_codacy_request_json_rejects_unsafe_identifier():
    auth_value = os.environ.get("QUALITY_GATE_TEST_AUTH", "placeholder-value")
    with pytest.raises(ValueError, match="unsupported characters"):
        codacy_mod._request_json(
            provider="gh",
            owner="Prekzursil",
            repo="env/inspector",
            token=auth_value,
            method="POST",
            data={},
        )


def test_deepscan_request_json_uses_fixed_host(monkeypatch):
    captured: dict[str, object] = {}
    auth_value = os.environ.get("QUALITY_GATE_TEST_AUTH", "placeholder-value")

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"open_issues": 0}, {}

    monkeypatch.setattr(deepscan_mod, "request_json_https", _fake_request_json_https)
    payload = deepscan_mod._request_json(
        host="deepscan.io",
        path="/api/projects/123/issues/open",
        query={"limit": "1"},
        token=auth_value,
    )

    _expect(payload == {"open_issues": 0})

    _expect(captured["host"] == "deepscan.io")

    _expect(captured["path"] == "/api/projects/123/issues/open")

    _expect(captured["query"] == {"limit": "1"})



def test_sentry_request_project_issues_uses_fixed_host(monkeypatch):
    captured: dict[str, object] = {}
    auth_value = os.environ.get("QUALITY_GATE_TEST_AUTH", "placeholder-value")

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return [], {"x-hits": "0"}

    monkeypatch.setattr(sentry_mod, "request_json_https", _fake_request_json_https)
    issues, headers = sentry_mod._request_project_issues("my-org", "my-project", auth_value)

    _expect(issues == [])

    _expect(headers["x-hits"] == "0")

    _expect(captured["host"] == "sentry.io")

    _expect(captured["path"] == "/api/0/projects/my-org/my-project/issues/")

    _expect(captured["query"] == {"query": "is:unresolved", "limit": "1"})
