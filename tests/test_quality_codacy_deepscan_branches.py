from __future__ import absolute_import, division

from email.message import Message
import secrets
import sys
import unittest
import urllib.error

import pytest

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod


def _raise(exc):
    raise exc


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def _token() -> str:
    return secrets.token_hex(8)


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="https://api.example", code=code, msg="err", hdrs=Message(), fp=None)


def test_codacy_parse_args_accepts_required_repo_fields(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--owner", "Prekzursil", "--repo", "env-inspector"])

    args = codacy_mod._parse_args()

    case = _case()
    case.assertEqual(args.owner, "Prekzursil")
    case.assertEqual(args.repo, "env-inspector")


def test_codacy_request_json_applies_branch_name(monkeypatch):
    captured = {}

    def _fake_request_json_https(**kwargs):
        captured.update(kwargs)
        return {"total": 0}, {}

    monkeypatch.setattr(codacy_mod, "request_json_https", _fake_request_json_https)

    payload = codacy_mod._request_json(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="main",
        method="POST",
        data={"sample": 1},
    )

    case = _case()
    case.assertEqual(payload, {"total": 0})
    case.assertEqual(captured["data"], {"sample": 1, "branchName": "main"})


def test_codacy_request_json_rejects_non_dict_payload(monkeypatch):
    monkeypatch.setattr(codacy_mod, "request_json_https", lambda **_kwargs: ([], {}))

    with pytest.raises(RuntimeError, match="Unexpected Codacy response payload"):
        codacy_mod._request_json(provider="gh", owner="Prekzursil", repo="env-inspector", token=_token())


def test_codacy_extract_helpers_cover_empty_and_fallback_paths():
    case = _case()
    case.assertIsNone(codacy_mod.extract_total_open([]))
    case.assertEqual(codacy_mod._provider_candidates("gh"), ["gh", "github"])
    case.assertEqual(codacy_mod._first_text({"a": ""}, ("a", "b")), "")
    case.assertIsNone(codacy_mod._format_issue_sample({"patternId": "", "filename": "", "message": ""}))
    case.assertEqual(codacy_mod._sample_issue_findings({"data": "not-a-list"}), [])


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

    case = _case()
    case.assertEqual(len(findings), 1)
    case.assertIn("Sample issue", findings[0])


def test_codacy_fetch_open_issues_handles_none_count(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: {"data": []})

    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )

    case = _case()
    case.assertTrue(handled)
    case.assertIsNone(open_issues)
    case.assertTrue(bool(findings))
    case.assertIn("parseable total", findings[0])
    case.assertIsNone(error)


def test_codacy_fetch_open_issues_handles_zero_and_non_zero(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: {"total": 0})

    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )
    case = _case()
    case.assertTrue(handled)
    case.assertEqual(open_issues, 0)
    case.assertEqual(findings, [])
    case.assertIsNone(error)

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
        token=_token(),
        branch="",
    )
    case.assertTrue(handled)
    case.assertEqual(open_issues, 2)
    case.assertTrue(any("Sample issue" in item for item in findings))
    case.assertIsNone(error)


def test_codacy_fetch_open_issues_handles_http_and_request_errors(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: _raise(_http_error(404)))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )
    case = _case()
    case.assertFalse(handled)
    case.assertIsNone(open_issues)
    case.assertEqual(findings, [])
    case.assertIsInstance(error, urllib.error.HTTPError)

    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: _raise(_http_error(500)))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )
    case.assertTrue(handled)
    case.assertIsNone(open_issues)
    case.assertTrue(bool(findings))
    case.assertIn("HTTP 500", findings[0])
    case.assertIsInstance(error, urllib.error.HTTPError)

    monkeypatch.setattr(codacy_mod, "_request_json", lambda **_kwargs: _raise(ValueError("bad")))
    handled, open_issues, findings, error = codacy_mod._fetch_open_issues_for_provider(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )
    case.assertTrue(handled)
    case.assertIsNone(open_issues)
    case.assertTrue(bool(findings))
    case.assertIn("bad", findings[0])
    case.assertIsInstance(error, ValueError)


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
        token=_token(),
        branch="",
    )

    case = _case()
    case.assertEqual(open_issues, 0)
    case.assertEqual(findings, [])

    monkeypatch.setattr(codacy_mod, "_fetch_open_issues_for_provider", lambda **_kwargs: (False, None, [], _http_error(404)))
    open_issues, findings = codacy_mod._query_open_issues(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        token=_token(),
        branch="",
    )

    case.assertIsNone(open_issues)
    case.assertTrue(any("endpoint was not found" in item for item in findings))
    case.assertTrue(any("Last Codacy API error" in item for item in findings))


def test_deepscan_extract_total_open_and_request_guard(monkeypatch):
    payload = {"outer": [{"nested": {"open_issues": 3}}, {"hits": 2}]}
    case = _case()
    case.assertIn(deepscan_mod.extract_total_open(payload), {2, 3})

    monkeypatch.setattr(deepscan_mod, "request_json_https", lambda **_kwargs: ([], {}))
    with pytest.raises(RuntimeError, match="Unexpected DeepScan response payload"):
        deepscan_mod._request_json(host="deepscan.io", path="/api", query={}, token=_token())


def test_deepscan_resolve_and_fetch_open_issues_paths(monkeypatch):
    host, path, query = deepscan_mod._resolve_deepscan_endpoint(
        "https://deepscan.io/api/projects/1/issues/open?scope=pull-request"
    )
    case = _case()
    case.assertEqual(host, "deepscan.io")
    case.assertEqual(path, "/api/projects/1/issues/open")
    case.assertEqual(query, {"scope": "pull-request"})

    findings = []
    monkeypatch.setattr(
        deepscan_mod,
        "_request_json",
        lambda **_kwargs: _raise(urllib.error.URLError("network")),
    )
    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token=_token(),
        findings=findings,
    )
    case.assertIsNone(open_issues)
    case.assertTrue(bool(findings))
    case.assertIn("DeepScan API request failed", findings[0])

    findings.clear()
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"open_issues": 2})
    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token=_token(),
        findings=findings,
    )
    case.assertEqual(open_issues, 2)
    case.assertTrue(bool(findings))
    case.assertIn("expected 0", findings[0])


def test_deepscan_fetch_open_issues_handles_unparseable_total(monkeypatch):
    findings = []
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"meta": {"count": "n/a"}})

    open_issues = deepscan_mod._fetch_open_issues(
        host="deepscan.io",
        path="/api",
        query={},
        token=_token(),
        findings=findings,
    )

    case = _case()
    case.assertIsNone(open_issues)
    case.assertTrue(bool(findings))
    case.assertIn("parseable total issue count", findings[0])


def test_deepscan_main_runs_fetch_when_inputs_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEEPSCAN_API_TOKEN", _token())
    monkeypatch.setenv("DEEPSCAN_OPEN_ISSUES_URL", "https://deepscan.io/api/projects/1/issues/open")

    def _deepscan_args():
        return type("Args", (), {"token": "", "out_json": "o/deep.json", "out_md": "o/deep.md"})()

    monkeypatch.setattr(deepscan_mod, "_parse_args", _deepscan_args)
    monkeypatch.setattr(deepscan_mod, "_resolve_deepscan_endpoint", lambda _url: ("deepscan.io", "/api", {}))
    monkeypatch.setattr(deepscan_mod, "_fetch_open_issues", lambda **_kwargs: 0)

    rc = deepscan_mod.main()

    _case().assertEqual(rc, 0)


def test_codacy_main_uses_query_path_when_token_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CODACY_API_TOKEN", _token())

    def _codacy_args():
        return type(
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
        )()

    monkeypatch.setattr(codacy_mod, "_parse_args", _codacy_args)
    monkeypatch.setattr(codacy_mod, "_query_open_issues", lambda **_kwargs: (0, []))

    rc = codacy_mod.main()

    _case().assertEqual(rc, 0)
