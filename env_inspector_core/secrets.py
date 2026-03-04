from __future__ import annotations

import re

SECRET_NAME_RE = re.compile(
    r"(^|[_-])(token|secret|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret|pat|auth)([_-]|$)",
    re.IGNORECASE,
)
GITHUB_TOKEN_RE = re.compile(r"^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_\-.]{32,}$")


def _looks_path_like(value: str) -> bool:
    return value.startswith(("/", "./", "../")) or "://" in value or "\\" in value or ":" in value


def _looks_high_entropy_value(value: str) -> bool:
    return len(value) >= 48 and BASE64ISH_RE.match(value) is not None and not _looks_path_like(value)


def looks_secret(name: str, value: str) -> bool:
    stripped_value = value.strip()
    return (
        SECRET_NAME_RE.search(name) is not None
        or GITHUB_TOKEN_RE.match(stripped_value) is not None
        or _looks_high_entropy_value(stripped_value)
    )


def mask_value(value: str, reveal: bool = False) -> str:
    if reveal:
        return value
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"