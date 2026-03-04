from __future__ import annotations

from tests.conftest import ensure
import json
import runpy
from pathlib import Path
from types import SimpleNamespace
import urllib.error

import pytest

from scripts.quality import check_codacy_zero as codacy_mod
from scripts.quality import check_deepscan_zero as deepscan_mod


def test_codacy_parse_args_reads_branch(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "check_codacy_zero.py",
            "--owner",
            "Prekzursil",
            "--repo",
            "env-inspector",
            "--branch",
            "feature/x",
        ],
    )

    args = codacy_mod._parse_args()

    ensure(args.branch == 'feature/x')


def test_codacy_request_json_rejects_non_dict_payload(monkeypatch):
    monkeypatch.setattr(codacy_mod, "request_json_https", lambda **_kwargs: ([], {}))

    with pytest.raises(RuntimeError, match="Unexpected Codacy response payload"):
        codacy_mod._request_json("gh", "Prekzursil", "env-inspector", token="tok")


def test_codacy_extract_helpers_cover_fallback_paths():
    ensure(codacy_mod._sum_count_rows([{'total': 2}, {'total': 3}]) == 5)
    ensure(codacy_mod._sum_count_rows(['x', {'bad': 1}]) is None)
    ensure(codacy_mod._extract_overview_total({'data': {'counts': 'bad'}}) is None)
    ensure(codacy_mod.extract_total_open('bad') is None)

    payload = {
        "data": {
            "counts": {
                "categories": [
                    {"name": "Security", "total": 4},
                ]
            }
        }
    }
    ensure(codacy_mod.extract_total_open(payload) == 4)


def test_codacy_sample_helpers_and_provider_candidates():
    ensure(codacy_mod._provider_candidates('gh') == ['gh', 'github'])
    ensure(codacy_mod._first_text({'message': 'hello'}, ('title', 'message')) == 'hello')

    ensure(codacy_mod._format_issue_sample({}) is None)
    sample = codacy_mod._format_issue_sample({"pattern": "X", "path": "a.py", "message": "bad"})
    ensure(sample == 'Sample issue: `X` at `a.py` - bad')

    findings = codacy_mod._sample_issue_findings({"data": [{"pattern": "X", "path": "a.py", "message": "bad"}]})
    ensure(findings and findings[0].startswith('Sample issue'))


def test_codacy_scan_candidate_falls_back_to_search(monkeypatch):
    calls: list[str] = []

    def _fake_request_json(**kwargs):
        calls.append(kwargs["endpoint"])
        if kwargs["endpoint"] == "issues/overview":
            return {"data": {"counts": {"levels": []}}}
        if kwargs.get("limit") == 1:
            return {"pagination": {"total": 2}}
        return {"data": [{"pattern": "X", "path": "a.py", "message": "bad"}]}

    monkeypatch.setattr(codacy_mod, "_request_json", _fake_request_json)
    findings: list[str] = []

    open_issues = codacy_mod._scan_candidate("gh", "Prekzursil", "env-inspector", "tok", "feat", findings)

    ensure(open_issues == 2)
    ensure(calls == ['issues/overview', 'issues/search', 'issues/search'])
    ensure(any(('overview response' in item for item in findings)))
    ensure(any(('expected 0' in item for item in findings)))


def test_codacy_query_open_issues_handles_http_paths(monkeypatch):
    def _raise_404(**_kwargs):
        raise urllib.error.HTTPError(url="https://app.codacy.com", code=404, msg="missing", hdrs=None, fp=None)

    monkeypatch.setattr(codacy_mod, "_scan_candidate", _raise_404)
    open_issues, findings = codacy_mod._query_open_issues("gh", "Prekzursil", "env-inspector", "tok", "")
    ensure(open_issues is None)
    ensure(any(('endpoint was not found' in item for item in findings)))
    ensure(any(('Last Codacy API error' in item for item in findings)))

    def _raise_500(**_kwargs):
        raise urllib.error.HTTPError(url="https://app.codacy.com", code=500, msg="boom", hdrs=None, fp=None)

    monkeypatch.setattr(codacy_mod, "_scan_candidate", _raise_500)
    _open_issues_500, findings_500 = codacy_mod._query_open_issues("gh", "Prekzursil", "env-inspector", "tok", "")
    ensure(any(('HTTP 500' in item for item in findings_500)))


def test_codacy_query_open_issues_returns_candidate_value(monkeypatch):
    monkeypatch.setattr(codacy_mod, "_scan_candidate", lambda **_kwargs: 0)

    open_issues, findings = codacy_mod._query_open_issues("gh", "Prekzursil", "env-inspector", "tok", "")
    ensure(open_issues == 0)
    ensure(findings == [])


def test_codacy_main_success_and_output_path_error(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CODACY_API_TOKEN", "env-token")
    args = SimpleNamespace(
        provider="gh",
        owner="Prekzursil",
        repo="env-inspector",
        branch="feat",
        token="",
        out_json="reports/codacy.json",
        out_md="reports/codacy.md",
    )
    monkeypatch.setattr(codacy_mod, "_parse_args", lambda: args)
    monkeypatch.setattr(codacy_mod, "_query_open_issues", lambda **_kwargs: (0, []))

    ensure(codacy_mod.main() == 0)
    payload = json.loads((tmp_path / "reports" / "codacy.json").read_text(encoding="utf-8"))
    ensure(payload['open_issues'] == 0)

    args.out_json = str(tmp_path.parent / "escape.json")
    ensure(codacy_mod.main() == 1)
    ensure('escapes workspace root' in capsys.readouterr().err)


def test_deepscan_iter_and_extract_open_counts():
    nested = {"data": [{"open_issues": 3}], "other": [{"value": 1}]}
    nodes = list(deepscan_mod._iter_nested_nodes(nested))

    ensure(nested in nodes)
    ensure(deepscan_mod.extract_total_open(nested) == 3)
    ensure(deepscan_mod.extract_total_open({'data': []}) is None)


def test_deepscan_parse_open_issue_endpoint_paths():
    host, path, query, findings = deepscan_mod._parse_open_issue_endpoint(
        "https://deepscan.io/api/projects/1/issues/open?limit=1"
    )
    ensure(findings == [])
    ensure(host == 'deepscan.io')
    ensure(path == '/api/projects/1/issues/open')
    ensure(query == {'limit': '1'})

    host2, path2, query2, findings2 = deepscan_mod._parse_open_issue_endpoint("ssh://deepscan.io/x")
    ensure(host2 is None and path2 is None and (query2 is None))
    ensure(findings2)


def test_deepscan_evaluate_open_issues_paths(monkeypatch):
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"open_issues": 0})
    open_issues_ok, findings_ok = deepscan_mod._evaluate_open_issues(
        host="deepscan.io", path="/x", query={"limit": "1"}, token="tok"
    )
    ensure(open_issues_ok == 0)
    ensure(findings_ok == [])

    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"data": []})
    open_issues_none, findings_none = deepscan_mod._evaluate_open_issues(
        host="deepscan.io", path="/x", query={"limit": "1"}, token="tok"
    )
    ensure(open_issues_none is None)
    ensure(any(('parseable total' in item for item in findings_none)))

    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"open_issues": 2})
    open_issues_bad, findings_bad = deepscan_mod._evaluate_open_issues(
        host="deepscan.io", path="/x", query={"limit": "1"}, token="tok"
    )
    ensure(open_issues_bad == 2)
    ensure(any(('expected 0' in item for item in findings_bad)))

    def _raise_runtime(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(deepscan_mod, "_request_json", _raise_runtime)
    open_issues_error, findings_error = deepscan_mod._evaluate_open_issues(
        host="deepscan.io", path="/x", query={"limit": "1"}, token="tok"
    )
    ensure(open_issues_error is None)
    ensure(any(('request failed' in item for item in findings_error)))


def test_deepscan_main_and_module_entrypoint(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(
        token="tok",
        out_json="reports/deepscan.json",
        out_md="reports/deepscan.md",
    )
    monkeypatch.setenv("DEEPSCAN_OPEN_ISSUES_URL", "https://deepscan.io/api/projects/1/issues/open?limit=1")
    monkeypatch.setattr(deepscan_mod, "_parse_args", lambda: args)
    monkeypatch.setattr(deepscan_mod, "_request_json", lambda **_kwargs: {"open_issues": 0})

    ensure(deepscan_mod.main() == 0)

    args.out_json = str(tmp_path.parent / "escape.json")
    ensure(deepscan_mod.main() == 1)

    monkeypatch.setattr("sys.argv", ["check_deepscan_zero.py", "--out-json", "reports/d.json", "--out-md", "reports/d.md"])
    monkeypatch.delenv("DEEPSCAN_API_TOKEN", raising=False)
    monkeypatch.delenv("DEEPSCAN_OPEN_ISSUES_URL", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("scripts.quality.check_deepscan_zero", run_name="__main__")

    ensure(exc_info.value.code == 1)


def test_codacy_sample_issue_findings_handles_non_list_and_limit():
    ensure(codacy_mod._sample_issue_findings({'data': 'bad'}) == [])

    findings = codacy_mod._sample_issue_findings(
        {
            "data": [
                1,
                {},
                {"pattern": "A", "path": "a.py", "message": "first"},
                {"pattern": "B", "path": "b.py", "message": "second"},
            ]
        },
        limit=1,
    )

    ensure(findings == ['Sample issue: `A` at `a.py` - first'])


def test_codacy_scan_candidate_returns_none_when_totals_unparseable(monkeypatch):
    def _fake_request_json(**kwargs):
        if kwargs["endpoint"] == "issues/overview":
            return {"data": {"counts": {"levels": []}}}
        return {"data": []}

    monkeypatch.setattr(codacy_mod, "_request_json", _fake_request_json)
    findings: list[str] = []

    open_issues = codacy_mod._scan_candidate("gh", "Prekzursil", "env-inspector", "tok", "feat", findings)

    ensure(open_issues is None)
    ensure(any(('parseable total issue count' in item for item in findings)))

