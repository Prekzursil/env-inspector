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

    class _Response:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"ok":true}'

        def getheaders(self):
            return [("X-Hits", "1")]

    class _Connection:
        def __init__(self, host: str, timeout: int):
            recorded["host"] = host
            recorded["timeout"] = timeout

        def request(self, method, path, body=None, headers=None):
            recorded["method"] = method
            recorded["path"] = path
            recorded["body"] = body
            recorded["headers"] = headers

        def getresponse(self):
            return _Response()

        def close(self):
            recorded["closed"] = True

    monkeypatch.setattr(sec.http.client, "HTTPSConnection", _Connection)

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
    ensure(recorded["host"] == "api.codacy.com")
    ensure(recorded["method"] == "POST")
    ensure(recorded["path"] == "/api/v3/issues/search?limit=1")
    ensure(recorded["body"] == '{"x": 1}')
    ensure(recorded["closed"] is True)

def test_request_json_https_http_error(monkeypatch):
    class _Response:
        status = 403
        reason = "Forbidden"

        def read(self):
            return b'{"message":"nope"}'

        def getheaders(self):
            return []

    class _Connection:
        def __init__(self, host: str, timeout: int):
            self.host = host
            self.timeout = timeout

        def request(self, method, path, body=None, headers=None):
            self.request_args = (method, path, body, headers)

        def getresponse(self):
            return _Response()

        def close(self):
            self.closed = True

    monkeypatch.setattr(sec.http.client, "HTTPSConnection", _Connection)

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
