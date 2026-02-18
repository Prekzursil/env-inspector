from __future__ import annotations

import re

SECRET_NAME_RE = re.compile(
    r"(^|[_-])(token|secret|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret|pat|auth)([_-]|$)",
    re.IGNORECASE,
)
GITHUB_TOKEN_RE = re.compile(r"^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_\-.]{32,}$")


def looks_secret(name: str, value: str) -> bool:
    if SECRET_NAME_RE.search(name):
        return True
    v = value.strip()
    if GITHUB_TOKEN_RE.match(v):
        return True
    if len(v) >= 48 and BASE64ISH_RE.match(v):
        if v.startswith(("/", "./", "../")) or "://" in v or "\\" in v or ":" in v:
            return False
        return True
    return False


def mask_value(value: str, reveal: bool = False) -> str:
    if reveal:
        return value
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"
