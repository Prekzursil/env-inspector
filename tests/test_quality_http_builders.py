from __future__ import annotations

from tests.conftest import ensure
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
        token="token",
        method="POST",
        data={},
    )

    ensure(payload == {'total': 0})
    ensure(captured['host'] == 'app.codacy.com')
    ensure(captured['path'] == '/api/v3/analysis/organizations/gh/Prekzursil/repositories/env-inspector/issues/search')
    ensure(captured['query'] == {'limit': '1'})


def test_codacy_request_json_overview_omits_limit_and_includes_branch(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"data": {"counts": {"levels": [{"name": "Error", "total": 0}]}}}, {}

    monkeypatch.setattr(codacy_mod, "request_json_https", _fake_request_json_https)
    payload = codacy_mod._request_json(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="token",
        branch="fix/true-zero-provider-parity-v2",
        endpoint="issues/overview",
        limit=None,
        method="POST",
        data={},
    )

    ensure(codacy_mod.extract_total_open(payload) == 0)
    ensure(captured['path'] == '/api/v3/analysis/organizations/gh/Prekzursil/repositories/env-inspector/issues/overview')
    ensure(captured['query'] == {})
    ensure(captured['data']['branchName'] == 'fix/true-zero-provider-parity-v2')


def test_codacy_request_json_rejects_unsafe_identifier():
    with pytest.raises(ValueError, match="unsupported characters"):
        codacy_mod._request_json(
            provider="gh",
            owner="Prekzursil",
            repo="env/inspector",
            token="token",
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
        token="token",
    )

    ensure(payload == {'open_issues': 0})
    ensure(captured['host'] == 'deepscan.io')
    ensure(captured['path'] == '/api/projects/123/issues/open')
    ensure(captured['query'] == {'limit': '1'})


def test_sentry_request_project_issues_uses_fixed_host(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return [], {"x-hits": "0"}

    monkeypatch.setattr(sentry_mod, "request_json_https", _fake_request_json_https)
    issues, headers = sentry_mod._request_project_issues("my-org", "my-project", "token")

    ensure(issues == [])
    ensure(headers['x-hits'] == '0')
    ensure(captured['host'] == 'sentry.io')
    ensure(captured['path'] == '/api/0/projects/my-org/my-project/issues/')
    ensure(captured['query'] == {'query': 'is:unresolved', 'limit': '1'})
