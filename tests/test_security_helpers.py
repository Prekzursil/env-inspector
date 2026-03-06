from __future__ import absolute_import, division

import urllib.error

import pytest

from scripts import security_helpers as sec

from tests.assertions import ensure

def test_identifier_and_url_helpers():
    ensure(sec.require_identifier("owner.repo-1", field_name="owner") == "owner.repo-1")
    ensure(sec.encode_identifier("owner.repo-1", field_name="owner") == "owner.repo-1")

    with pytest.raises(ValueError, match="unsupported characters"):
        sec.require_identifier("owner/repo", field_name="owner")

    host, path, query = sec.split_validated_https_url(
        "https://api.codacy.com/api/v3/resource?limit=1&query=x",
        allowed_host_suffixes={"codacy.com"},
    )
    ensure(host == "api.codacy.com")
    ensure(path == "/api/v3/resource")
    ensure(query == {"limit": "1", "query": "x"})

def test_request_json_https_success(monkeypatch):
    recorded: dict[str, object] = {}

    class _Headers:
        def items(self):
            return [("X-Hits", "1")]

    class _Response:
        reason = "OK"
        headers = _Headers()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            recorded["closed"] = True
            return False

        def read(self):
            return b'{"ok":true}'

        def getcode(self):
            return 200

    def _urlopen(request, timeout=0, context=None):
        recorded["url"] = request.full_url
        recorded["method"] = request.get_method()
        recorded["headers"] = dict(request.header_items())
        recorded["body"] = request.data.decode("utf-8") if request.data is not None else None
        recorded["timeout"] = timeout
        recorded["context"] = context
        return _Response()

    monkeypatch.setattr(sec.urllib.request, "urlopen", _urlopen)

    payload, headers = sec.request_json_https(
        host="api.codacy.com",
        path="/api/v3/issues/search",
        method="POST",
        query={"limit": "1"},
        headers={"Accept": "application/json"},
        data={"x": 1},
    )

    ensure(payload == {"ok": True})
    ensure(headers["x-hits"] == "1")
    ensure(recorded["url"] == "https://api.codacy.com/api/v3/issues/search?limit=1")
    ensure(recorded["method"] == "POST")
    ensure(recorded["body"] == '{"x": 1}')
    ensure(recorded["closed"] is True)
    ensure(recorded["context"] is not None)
    ensure(recorded["context"].minimum_version == sec.ssl.TLSVersion.TLSv1_2)

def test_request_json_https_http_error(monkeypatch):
    def _urlopen(request, timeout=0, context=None):
        raise urllib.error.HTTPError(
            url=request.full_url,
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=None,
        )

    monkeypatch.setattr(sec.urllib.request, "urlopen", _urlopen)

    with pytest.raises(urllib.error.HTTPError, match="Forbidden") as exc_info:
        sec.request_json_https(
            host="sentry.io",
            path="/api/0/projects/org/proj/issues/",
            headers={"Accept": "application/json"},
        )
    ensure(exc_info.value.code == 403)

def test_safe_output_path_in_workspace_allows_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    resolved = sec.safe_output_path_in_workspace("reports/out.json", "fallback.json")

    ensure(resolved == (tmp_path / "reports" / "out.json").resolve(strict=False))

def test_safe_output_path_in_workspace_rejects_workspace_escape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "escaped.json"

    with pytest.raises(ValueError, match="escapes workspace root"):
        sec.safe_output_path_in_workspace(str(outside), "fallback.json")

def test_validate_hostname_allowlists_accepts_none_suffixes():
    sec._validate_hostname_allowlists("api.codacy.com", allowed_host_suffixes=None)

def test_validate_hostname_allowlists_rejects_mismatched_suffix():
    with pytest.raises(ValueError, match="suffix allowlist"):
        sec._validate_hostname_allowlists("api.codacy.com", allowed_host_suffixes={"example.com"})
