from __future__ import annotations, absolute_import, division

import re

_SECRET_MARKERS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "private_key",
    "client_secret",
    "pat",
    "auth",
)
GITHUB_TOKEN_RE = re.compile(r"^(gh[pousr]_\w{20,}|github_pat_\w{20,})$")
BASE64ISH_RE = re.compile(r"^[\w+/=.-]{32,}$")


def _name_suggests_secret(name: str) -> bool:
    normalized = (name or "").strip().lower().replace("-", "_")
    if not normalized:
        return False
    padded = f"_{normalized}_"
    return any(f"_{marker}_" in padded for marker in _SECRET_MARKERS)


def _is_path_like(candidate: str) -> bool:
    return candidate.startswith(("/", "./", "../")) or "://" in candidate or "\\" in candidate or ":" in candidate


def _is_base64_secret(candidate: str) -> bool:
    if len(candidate) < 48 or not BASE64ISH_RE.match(candidate):
        return False
    return not _is_path_like(candidate)


def looks_secret(name: str, value: str) -> bool:
    if _name_suggests_secret(name):
        return True

    candidate = value.strip()
    if GITHUB_TOKEN_RE.match(candidate):
        return True

    return _is_base64_secret(candidate)


def mask_value(value: str, reveal: bool = False) -> str:
    if reveal:
        return value
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"
