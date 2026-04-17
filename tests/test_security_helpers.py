"""Tests for HTTPS security helpers."""

import io
import urllib.error
from email.message import Message
from typing import Any, Dict

import pytest

from scripts import security_helpers as sec
from tests.assertions import ensure


def test_identifier_and_url_helpers():
    """Validate safe identifier and HTTPS URL parsing helpers."""
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
    """Return JSON and headers from a successful HTTPS request."""
    recorded: Dict[str, Any] = {}
    captured_context: Dict[str, sec.ssl.SSLContext] = {}

    class _Response:
        """Minimal HTTP response stub used by the HTTPS helper tests."""

        status = 200
        reason = "OK"
        headers = {"X-Hits": "1"}

        @staticmethod
        def read():
            """Return a serialized JSON response body."""
            return b'{"ok":true}'

        def __enter__(self):
            """Track context-manager entry and return the stub instance."""
            recorded["entered"] = True
            return self

        def __exit__(self, exc_type, exc, tb):
            """Track context-manager exit without suppressing exceptions."""
            recorded["closed"] = True
            return False

        def getcode(self):
            """Return the canned HTTP status code."""
            return self.status

    class _FakeOpener:
        """Opener stub that records outbound request details."""

        @staticmethod
        def open(request, timeout=0):
            """Capture request details and return a canned response."""
            recorded["url"] = request.full_url
            recorded["host"] = sec.urllib.parse.urlparse(request.full_url).hostname
            recorded["timeout"] = timeout
            recorded["method"] = request.get_method()
            recorded["headers"] = dict(request.header_items())
            recorded["body"] = (
                request.data.decode("utf-8") if request.data is not None else None
            )
            return _Response()

    monkeypatch.setattr(
        sec.urllib.request, "build_opener", lambda _handler: _FakeOpener()
    )
    monkeypatch.setattr(
        sec.urllib.request, "HTTPSHandler", lambda context=None: context
    )
    real_secure_context = sec._secure_ssl_context

    def _fake_secure_context():
        """Capture the SSL context created by the helper under test."""
        context = real_secure_context()
        captured_context["value"] = context
        return context

    monkeypatch.setattr(sec, "_secure_ssl_context", _fake_secure_context)

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
    ensure(recorded["url"] == "https://api.codacy.com/api/v3/issues/search?limit=1")
    ensure(recorded["method"] == "POST")
    ensure(recorded["body"] == '{"x": 1}')
    ensure(recorded["closed"] is True)
    ensure("value" in captured_context)
    ensure(
        getattr(captured_context["value"], "protocol", None) == sec.ssl.PROTOCOL_TLSv1_2
    )


def test_request_json_https_http_error(monkeypatch):
    """Re-raise HTTP errors emitted by the HTTPS request helper."""

    class _FakeOpener:
        """Opener stub that always raises an HTTP error."""

        @staticmethod
        def open(request, _timeout=0):
            """Raise a deterministic HTTP error for the request."""
            headers = Message()
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                "Forbidden",
                hdrs=headers,
                fp=io.BytesIO(b'{"error":"denied"}'),
            )

    monkeypatch.setattr(
        sec.urllib.request, "build_opener", lambda _handler: _FakeOpener()
    )
    monkeypatch.setattr(
        sec.urllib.request, "HTTPSHandler", lambda context=None: context
    )

    with pytest.raises(urllib.error.HTTPError, match="Forbidden") as exc_info:
        sec.request_json_https(
            host="sentry.io",
            path="/api/0/projects/org/proj/issues/",
            headers={"Accept": "application/json"},
        )
    ensure(exc_info.value.code == 403)


def test_secure_ssl_context_uses_tls_client_defaults():
    """Build a TLS client context with certificate validation enabled."""
    context = sec._secure_ssl_context()

    ensure(context.verify_mode == sec.ssl.CERT_REQUIRED)
    ensure(context.check_hostname is True)
    ensure(getattr(context, "protocol", None) == sec.ssl.PROTOCOL_TLSv1_2)


def test_safe_output_path_in_workspace_allows_relative_path(tmp_path, monkeypatch):
    """Resolve relative output paths inside the current workspace root."""
    monkeypatch.chdir(tmp_path)

    resolved = sec.safe_output_path_in_workspace("reports/out.json", "fallback.json")

    ensure(resolved == (tmp_path / "reports" / "out.json").resolve(strict=False))


def test_safe_output_path_in_workspace_rejects_workspace_escape(tmp_path, monkeypatch):
    """Reject output paths that escape the active workspace."""
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "escaped.json"

    with pytest.raises(ValueError, match="escapes workspace root"):
        sec.safe_output_path_in_workspace(str(outside), "fallback.json")


def test_validate_hostname_allowlists_accepts_none_suffixes():
    """Allow hostname validation when no suffix allowlist is configured."""
    sec._validate_hostname_allowlists("api.codacy.com", allowed_host_suffixes=None)


def test_validate_hostname_allowlists_rejects_mismatched_suffix():
    """Reject hostnames that do not match the configured suffix allowlist."""
    with pytest.raises(ValueError, match="suffix allowlist"):
        sec._validate_hostname_allowlists(
            "api.codacy.com", allowed_host_suffixes={"example.com"}
        )
