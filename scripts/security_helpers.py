from __future__ import absolute_import, division

import ipaddress
import json
from email.message import Message
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_LOCAL_IP_FLAGS = ("is_private", "is_loopback", "is_link_local", "is_reserved", "is_multicast")


def _parse_https_url(raw_url: str):
    parsed = urlparse((raw_url or "").strip())
    if parsed.scheme != "https":
        raise ValueError(f"Only https URLs are allowed: {raw_url!r}")
    if not parsed.hostname:
        raise ValueError(f"URL is missing a hostname: {raw_url!r}")
    if parsed.username or parsed.password:
        raise ValueError(f"URL credentials are not allowed: {raw_url!r}")
    return parsed


def _normalized_hosts(values: Optional[Set[str]]) -> Set[str]:
    if not values:
        return set()
    return {value.lower().strip(".") for value in values if value.strip(".")}


def _hostname_matches_suffix(hostname: str, suffixes: Set[str]) -> bool:
    return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes)


def _validate_hostname_allowlists(
    hostname: str,
    *,
    allowed_hosts: Optional[Set[str]] = None,
    allowed_host_suffixes: Optional[Set[str]] = None,
) -> None:
    exact_hosts = _normalized_hosts(allowed_hosts)
    if exact_hosts and hostname not in exact_hosts:
        raise ValueError(f"URL host is not in allowlist: {hostname}")

    suffixes = _normalized_hosts(allowed_host_suffixes)
    if suffixes and not _hostname_matches_suffix(hostname, suffixes):
        raise ValueError(f"URL host is not in suffix allowlist: {hostname}")


def _is_local_or_private_ip(hostname: str) -> bool:
    try:
        ip_value = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return any(bool(getattr(ip_value, flag)) for flag in _LOCAL_IP_FLAGS)


def _reject_local_targets(hostname: str) -> None:
    if _is_local_or_private_ip(hostname):
        raise ValueError(f"Private or local addresses are not allowed: {hostname}")

    if hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost URLs are not allowed.")


def normalize_https_url(
    raw_url: str,
    *,
    allowed_hosts: Optional[Set[str]] = None,
    allowed_host_suffixes: Optional[Set[str]] = None,
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

    parsed = _parse_https_url(raw_url)
    hostname = parsed.hostname.lower().strip(".")
    _validate_hostname_allowlists(
        hostname,
        allowed_hosts=allowed_hosts,
        allowed_host_suffixes=allowed_host_suffixes,
    )
    _reject_local_targets(hostname)

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
    allowed_hosts: Optional[Set[str]] = None,
    allowed_host_suffixes: Optional[Set[str]] = None,
) -> Tuple[str, str, Dict[str, str]]:
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


def _build_request_target(path: str, query: Optional[Dict[str, str]]) -> str:
    query_text = urllib.parse.urlencode(query or {}, doseq=False)
    return path + (f"?{query_text}" if query_text else "")


def _json_body_or_none(data: Optional[Dict[str, Any]]) -> Optional[str]:
    return json.dumps(data) if data is not None else None


def _secure_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)
    return context


def _read_https_success(response) -> Tuple[int, str, str, Dict[str, str]]:
    raw_body = response.read().decode("utf-8")
    response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    status = int(getattr(response, "status", response.getcode()))
    reason = str(getattr(response, "reason", "") or "HTTP error")
    return status, reason, raw_body, response_headers


def _read_https_error(exc: urllib.error.HTTPError) -> Tuple[int, str, str, Dict[str, str]]:
    raw_body = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
    error_headers = tuple(exc.headers.items()) if exc.headers else ()
    response_headers = {str(k).lower(): str(v) for k, v in error_headers}
    status = int(exc.code)
    reason = str(exc.reason or "HTTP error")
    return status, reason, raw_body, response_headers


def _execute_https_request(
    *,
    host: str,
    method: str,
    request_target: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: int,
) -> Tuple[int, str, str, Dict[str, str]]:
    request = urllib.request.Request(
        url=f"https://{host}{request_target}",
        data=body.encode("utf-8") if body is not None else None,
        headers=headers,
        method=method.upper(),
    )
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_secure_ssl_context()))
        with opener.open(request, timeout=timeout) as response:
            status, reason, raw_body, response_headers = _read_https_success(response)
    except urllib.error.HTTPError as exc:
        status, reason, raw_body, response_headers = _read_https_error(exc)
    return status, reason, raw_body, response_headers


def request_json_https(
    *,
    host: str,
    path: str,
    headers: Dict[str, str],
    method: str = "GET",
    query: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
) -> Tuple[Any, Dict[str, str]]:
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
        error_headers = Message()
        for header_name, header_value in response_headers.items():
            error_headers[header_name] = header_value
        raise urllib.error.HTTPError(
            url=f"https://{validated_host}{request_target}",
            code=status,
            msg=reason,
            hdrs=error_headers,
            fp=None,
        )

    return json.loads(raw_body), response_headers


def safe_output_path_in_workspace(raw: str, fallback: str, base: Optional[Path] = None) -> Path:
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


def safe_input_file_path_in_workspace(raw: str, *, base: Optional[Path] = None) -> Path:
    root = (base or Path.cwd()).resolve()
    candidate = Path((raw or "").strip()).expanduser()  # codeql[py/path-injection] constrained to workspace
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Input file path escapes workspace root: {candidate}") from exc
    if not resolved.exists() or not resolved.is_file():
        raise ValueError(f"Input file does not exist: {resolved}")
    return resolved
