from __future__ import annotations

import sys
import urllib.error

import pytest

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod



def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="https://api.example", code=code, msg="err", hdrs=None, fp=None)


def test_codacy_parse_args_accepts_required_repo_fields(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--owner", "Prekzursil", "--repo", "env-inspector"])

    args = codacy_mod._parse_args()

    assert args.owner == "Prekzursil"
    assert args.repo == "env-inspector"


def test_codacy_request_json_applies_branch_name(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"total": 0}, {}

    monkeypatch.setattr(codacy_mod, "request_json_https", _fake_request_json_https)

    payload = codacy_mod._request_json(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="tok",
        branch="main",
        method="POST",
        data={"sample": 1},
    )

    assert payload == {"total": 0}
    assert captured["data"] == {"sample": 1, "branchName": "main"}


def test_codacy_request_json_rejects_non_dict_payload(monkeypatch):
    monkeypatch.setattr(codacy_mod, "request_json_https", lambda **_kwargs: ([], {}))

    with pytest.raises(RuntimeError, match="Unexpected Codacy response payload"):
        codacy_mod._request_json(provider="gh", owner="Prekzursil", repo="env-inspector", token="t")


def test_codacy_extract_helpers_cover_empty_and_fallback_paths():
    assert codacy_mod.extract_total_open([]) is None
    assert codacy_mod._provider_candidates("gh") == ["gh", "github"]
    assert codacy_mod._first_text({"a": ""}, ("a", "b")) == ""
    assert codacy_mod._format_issue_sample({"patternId": "", "filename": "", "message": ""}) is None
    assert codacy_mod._sample_issue_findings({"data": "not-a-list"}) == []



def test_codacy_sample_issue_findings_skips_invalid_items_and_honors_limit():
    payload = {
        "data": [
            "skip",
            {"patternId": "", "filename": "", "message": ""},
            {"patternId": "A", "filename": "a.py", "message": "m1"},
            {"patternId": "B", "filename": "b.py", "message": "m2"},
        ]
    }

    findings = codacy_mod._sample_issue_findings(payload, limit=1)

    assert len(findings) == 1
    assert "Sample issue" in findings[0]


def test_codacy_fetch_open_issues_handles_none_count(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: {"data": []})

    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )

    assert handled is True
    assert open_issues is None
    assert findings and "parseable total" in findings[0]
    assert error is None


def test_codacy_fetch_open_issues_handles_zero_and_non_zero(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: {"total": 0})

    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )
    assert handled is True
    assert open_issues == 0
    assert findings == []
    assert error is None

    calls = {"count": 0}

    def _fake_request_json(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"total": 2}
        return {"data": [{"patternId": "C901", "filename": "a.py", "message": "too complex"}]}

    monkeypatch.setattr(codacy_mod, "_request_json", _fake_request_json)
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )
    assert handled is True
    assert open_issues == 2
    assert any("Sample issue" in item for item in findings)
    assert error is None


def test_codacy_fetch_open_issues_handles_http_and_request_errors(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: (_ for _ in ()).throw(_http_error(404)))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )
    assert handled is False
    assert open_issues is None
    assert findings == []
    assert isinstance(error, urllib.error.HTTPError)

    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: (_ for _ in ()).throw(_http_error(500)))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )
    assert handled is True
    assert open_issues is None
    assert findings and "HTTP 500" in findings[0]
    assert isinstance(error, urllib.error.HTTPError)

    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: (_ for _ in ()).throw(ValueError("bad")))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )
    assert handled is True
    assert open_issues is None
    assert findings and "bad" in findings[0]
    assert isinstance(error, ValueError)


def test_codacy_query_open_issues_fallback_and_last_error(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_provider_candidates", lambda _preferred: ["gh", "github"])

    responses = [
        (False, None, [], _http_error(404)),
        (True, 0, [], None),
    ]
    monkeypatch.setattr(codacy_mod, "_fetch_open_issues_for_provider", lambda **_kwargs: responses.pop(0))

    open_issues, findings = codacy_mod._query_open_issues(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )

    assert open_issues == 0
    assert findings == []

    monkeypatch.setattr(codacy_mod, "_fetch_open_issues_for_provider", lambda **_kwargs: (False, None, [], _http_error(404)))
    open_issues, findings = codacy_mod._query_open_issues(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token="t",
        branch="",
    )

    assert open_issues is None
    assert any("endpoint was not found" in item for item in findings)
    assert any("Last Codacy API error" in item for item in findings)


def test_deepscan_extract_total_open_and_request_guard(monkeypatch):
    payload = {"outer": [{"nested": {"open_issues": 3}}, {"hits": 2}]}
    assert deepscan_mod.extract_total_open(payload) in {2, 3}

    monkeypatch.setattr(deepscan_mod, "request_json_https", lambda **_kwargs: ([], {}))
    with pytest.raises(RuntimeError, match="Unexpected DeepScan response payload"):
        deepscan_mod._request_json(host="deepscan.io", path="/api", query={}, token="t")


def test_deepscan_resolve_and_fetch_open_issues_paths(monkeypatch):
    host, path, query = deepscan_mod._resolve_deepscan_endpoint(
        "https://deepscan.io/api/projects/1/issues/open?scope=pull-request"
    )
    assert host == "deepscan.io"
    assert path == "/api/projects/1/issues/open"
    assert query == {"scope": "pull-request"}

    findings: list[str] = []
    monkeypatch.setattr(
        deepscan_mod,
        "_request_json",
        lambda **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("network")),
    )
    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token="t",
        findings=findings,
    )
    assert open_issues is None
    assert findings and "DeepScan API request failed" in findings[0]

    findings.clear()
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"open_issues": 2})
    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token="t",
        findings=findings,
    )
    assert open_issues == 2
    assert findings and "expected 0" in findings[0]


def test_deepscan_main_runs_fetch_when_inputs_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPSCAN_API_TOKEN", "tok")
    monkeypatch.setenv("DEEPSCAN_OPEN_ISSUES_URL", "https://deepscan.io/api/projects/1/issues/open")
    monkeypatch.setattr(
        deepscan_mod,
        "_parse_args",
        lambda: type("Args", (), {"token": "", "out_json": "o/deep.json", "out_md": "o/deep.md"})(),
    )
    monkeypatch.setattr(deepscan_mod, "_resolve_deepscan_endpoint", lambda _url: ("deepscan.io", "/api", {}))
    monkeypatch.setattr(deepscan_mod, "_fetch_open_issues", lambda **_kwargs: 0)

    rc = deepscan_mod.main()

    assert rc == 0


def test_deepscan_fetch_open_issues_handles_unparseable_total(monkeypatch):
    findings: list[str] = []
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"meta": {"count": "n/a"}})

    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token="t",
        findings=findings,
    )

    assert open_issues is None
    assert findings and "parseable total issue count" in findings[0]



def test_codacy_main_uses_query_path_when_token_present(tmp_path, monkeypatch):
    import unittest

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CODACY_API_TOKEN", "tok")
    monkeypatch.setattr(
        codacy_mod,
        "_parse_args",
        lambda: type(
            "Args",
            (),
            {
                "provider": "gh",
                "owner": "Prekzursil",
                "repo": "env-inspector",
                "branch": "main",
                "token": "",
                "out_json": "o/codacy.json",
                "out_md": "o/codacy.md",
            },
        )(),
    )
    monkeypatch.setattr(codacy_mod, "_query_open_issues", lambda **_kwargs: (0, []))

    rc = codacy_mod.main()

    case = unittest.TestCase()
    case.assertEqual(rc, 0)
