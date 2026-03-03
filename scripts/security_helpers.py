from __future__ import annotations

import http.client
import ipaddress
import json
import re
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def normalize_https_url(
    raw_url: str,
    *,
    allowed_hosts: set[str] | None = None,
    allowed_host_suffixes: set[str] | None = None,
    strip_query: bool = False,
) -> str:
    """Validate user-provided URLs for CLI scripts.

    Rules:
    - https scheme only,
    - no embedded credentials,
    - reject localhost/private/link-local IP targets,
    - optional hostname allowlist.
    - optional hostname suffix allowlist.
    """

    parsed = urlparse((raw_url or "").strip())
    if parsed.scheme != "https":
        raise ValueError(f"Only https URLs are allowed: {raw_url!r}")
    if not parsed.hostname:
        raise ValueError(f"URL is missing a hostname: {raw_url!r}")
    if parsed.username or parsed.password:
        raise ValueError(f"URL credentials are not allowed: {raw_url!r}")

    hostname = parsed.hostname.lower().strip(".")
    if allowed_hosts is not None and hostname not in {host.lower().strip(".") for host in allowed_hosts}:
        raise ValueError(f"URL host is not in allowlist: {hostname}")
    if allowed_host_suffixes is not None:
        suffixes = {suffix.lower().strip(".") for suffix in allowed_host_suffixes if suffix.strip(".")}
        if suffixes and not any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes):
            raise ValueError(f"URL host is not in suffix allowlist: {hostname}")

    try:
        ip_value = ipaddress.ip_address(hostname)
    except ValueError:
        ip_value = None

    if ip_value is not None and (
        ip_value.is_private
        or ip_value.is_loopback
        or ip_value.is_link_local
        or ip_value.is_reserved
        or ip_value.is_multicast
    ):
        raise ValueError(f"Private or local addresses are not allowed: {hostname}")

    if hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost URLs are not allowed.")

    sanitized = parsed._replace(fragment="", params="")
    if strip_query:
        sanitized = sanitized._replace(query="")
    return urlunparse(sanitized)


def require_identifier(raw: str, *, field_name: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError(f"{field_name} is required.")
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"{field_name} contains unsupported characters. Allowed: letters, digits, dot, underscore, dash."
        )
    return value


def encode_identifier(raw: str, *, field_name: str) -> str:
    value = require_identifier(raw, field_name=field_name)
    return urllib.parse.quote(value, safe="")


def split_validated_https_url(
    raw_url: str,
    *,
    allowed_hosts: set[str] | None = None,
    allowed_host_suffixes: set[str] | None = None,
) -> tuple[str, str, dict[str, str]]:
    safe_url = normalize_https_url(
        raw_url,
        allowed_hosts=allowed_hosts,
        allowed_host_suffixes=allowed_host_suffixes,
    )
    parsed = urllib.parse.urlparse(safe_url)
    host = (parsed.hostname or "").strip().lower()
    path = parsed.path or "/"
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    query = {str(k): str(v) for k, v in query_pairs}
    return host, path, query


def _normalize_https_host(host: str) -> str:
    return require_identifier((host or "").strip().lower(), field_name="HTTPS host")


def _normalize_https_path(path: str) -> str:
    safe_path = path if path.startswith("/") else f"/{path}"
    if "://" in safe_path or "\n" in safe_path or "\r" in safe_path:
        raise ValueError(f"Invalid HTTPS path: {path!r}")
    return safe_path


def _build_request_target(path: str, query: dict[str, str] | None) -> str:
    query_text = urllib.parse.urlencode(query or {}, doseq=False)
    return path + (f"?{query_text}" if query_text else "")


def _json_body_or_none(data: dict[str, Any] | None) -> str | None:
    return json.dumps(data) if data is not None else None


def _execute_https_request(
    *,
    host: str,
    method: str,
    request_target: str,
    headers: dict[str, str],
    body: str | None,
    timeout: int,
) -> tuple[int, str, str, dict[str, str]]:
    connection = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        connection.request(method.upper(), request_target, body=body, headers=headers)
        response = connection.getresponse()
        raw_body = response.read().decode("utf-8")
        response_headers = {str(k).lower(): str(v) for k, v in response.getheaders()}
        return int(response.status), str(response.reason or "HTTP error"), raw_body, response_headers
    finally:
        connection.close()


def request_json_https(
    *,
    host: str,
    path: str,
    headers: dict[str, str],
    method: str = "GET",
    query: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = 30,
) -> tuple[Any, dict[str, str]]:
    validated_host = _normalize_https_host(host)
    normalized_path = _normalize_https_path(path)
    request_target = _build_request_target(normalized_path, query)
    body = _json_body_or_none(data)
    status, reason, raw_body, response_headers = _execute_https_request(
        host=validated_host,
        method=method,
        request_target=request_target,
        headers=headers,
        body=body,
        timeout=timeout,
    )
    if status >= 400:
        raise urllib.error.HTTPError(
            url=f"https://{validated_host}{request_target}",
            code=status,
            msg=reason,
            hdrs=response_headers,
            fp=None,
        )

    return json.loads(raw_body), response_headers


def safe_output_path_in_workspace(raw: str, fallback: str, base: Path | None = None) -> Path:
    root = (base or Path.cwd()).resolve()
    candidate = Path((raw or "").strip() or fallback).expanduser()  # codeql[py/path-injection] constrained to workspace
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Output path escapes workspace root: {candidate}") from exc
    return resolved
