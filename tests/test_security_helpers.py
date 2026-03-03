from __future__ import annotations

import urllib.error

import pytest

from scripts import security_helpers as sec


def test_identifier_and_url_helpers():
    assert sec.require_identifier("owner.repo-1", field_name="owner") == "owner.repo-1"
    assert sec.encode_identifier("owner.repo-1", field_name="owner") == "owner.repo-1"

    with pytest.raises(ValueError, match="unsupported characters"):
        sec.require_identifier("owner/repo", field_name="owner")

    host, path, query = sec.split_validated_https_url(
        "https://api.codacy.com/api/v3/resource?limit=1&query=x",
        allowed_host_suffixes={"codacy.com"},
    )
    assert host == "api.codacy.com"
    assert path == "/api/v3/resource"
    assert query == {"limit": "1", "query": "x"}


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

    assert payload == {"ok": True}
    assert headers["x-hits"] == "1"
    assert recorded["host"] == "api.codacy.com"
    assert recorded["method"] == "POST"
    assert recorded["path"] == "/api/v3/issues/search?limit=1"
    assert recorded["body"] == '{"x": 1}'
    assert recorded["closed"] is True


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
            pass

        def request(self, method, path, body=None, headers=None):
            pass

        def getresponse(self):
            return _Response()

        def close(self):
            pass

    monkeypatch.setattr(sec.http.client, "HTTPSConnection", _Connection)

    with pytest.raises(urllib.error.HTTPError, match="Forbidden") as exc_info:
        sec.request_json_https(
            host="sentry.io",
            path="/api/0/projects/org/proj/issues/",
            headers={"Accept": "application/json"},
        )
    assert exc_info.value.code == 403
