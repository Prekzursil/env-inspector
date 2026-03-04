from __future__ import annotations

import re
from collections.abc import Callable

_ENV_KEY_PATTERN = r"[A-Za-z_]\w*"
ENV_KEY_RE = re.compile(rf"^{_ENV_KEY_PATTERN}$")
EXPORT_LINE_RE = re.compile(rf"^\s*export\s+({_ENV_KEY_PATTERN})=(.*)$")
ASSIGN_LINE_RE = re.compile(rf"^\s*({_ENV_KEY_PATTERN})=(.*)$")
POWERSHELL_ENV_RE = re.compile(rf"^\s*\$env:({_ENV_KEY_PATTERN})\s*=", re.IGNORECASE)


def validate_env_key(key: str) -> None:
    if not key:
        raise ValueError("Environment key cannot be empty.")
    if not ENV_KEY_RE.match(key):
        raise ValueError("Invalid key format. Use [A-Za-z_][A-Za-z0-9_]*.")


def validate_env_value(value: str) -> None:
    if "\x00" in value:
        raise ValueError("Environment value cannot contain null bytes.")


def strip_outer_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == "'") or (v[0] == v[-1] == '"')):
        v = v[1:-1]
    return v.replace("'\"'\"'", "'")


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render_upsert(lines: list[str], had_trailing_newline: bool) -> str:
    text = "\n".join(lines)
    if had_trailing_newline or lines:
        text += "\n"
    return text


def _render_remove(lines: list[str], had_trailing_newline: bool) -> str:
    text = "\n".join(lines)
    if had_trailing_newline and lines:
        text += "\n"
    return text


def _append_with_optional_blank(lines: list[str], new_line: str) -> None:
    if lines and lines[-1].strip():
        lines.append("")
    lines.append(new_line)


def _replace_first_match(
    lines: list[str],
    *,
    replacement: str,
    matcher: Callable[[str], bool],
) -> tuple[list[str], bool]:
    out: list[str] = []
    replaced = False
    for line in lines:
        if matcher(line):
            if not replaced:
                out.append(replacement)
                replaced = True
            continue
        out.append(line)
    return out, replaced


def _matches_export_key(line: str, key: str) -> bool:
    match = EXPORT_LINE_RE.match(line)
    return bool(match and match.group(1) == key)


def _matches_assign_key(line: str, key: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    match = ASSIGN_LINE_RE.match(stripped)
    return bool(match and match.group(1) == key)


def _line_assigns_key(line: str, key: str) -> bool:
    stripped = line.strip()
    assign_match = ASSIGN_LINE_RE.match(stripped)
    if assign_match and assign_match.group(1) == key:
        return True
    export_match = EXPORT_LINE_RE.match(stripped)
    return bool(export_match and export_match.group(1) == key)


def _matches_powershell_key(line: str, key: str) -> bool:
    match = POWERSHELL_ENV_RE.match(line)
    return bool(match and match.group(1).lower() == key.lower())


def parse_dotenv_text(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = strip_outer_quotes(value.strip())
        if not key or not ENV_KEY_RE.match(key):
            continue
        rows.append((key, value))
    return rows


def parse_bash_exports(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = EXPORT_LINE_RE.match(line)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2).strip()
        values[key] = strip_outer_quotes(raw_value)
    return values


def parse_etc_environment(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGN_LINE_RE.match(stripped)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2)
        values[key] = strip_outer_quotes(raw_value)
    return values


def upsert_export(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    export_line = f"export {key}={shell_single_quote(value)}"
    lines = content.splitlines()
    out, replaced = _replace_first_match(lines, replacement=export_line, matcher=lambda line: _matches_export_key(line, key))
    if not replaced:
        _append_with_optional_blank(out, export_line)
    return _render_upsert(out, content.endswith("\n"))


def remove_export(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    out = [line for line in lines if not _matches_export_key(line, key)]
    return _render_remove(out, content.endswith("\n"))


def upsert_key_value(content: str, key: str, value: str, *, quote: bool = False) -> str:
    validate_env_key(key)
    validate_env_value(value)
    line_out = f"{key}={shell_single_quote(value) if quote else value}"
    lines = content.splitlines()
    out, replaced = _replace_first_match(lines, replacement=line_out, matcher=lambda line: _matches_assign_key(line, key))
    if not replaced:
        _append_with_optional_blank(out, line_out)
    return _render_upsert(out, content.endswith("\n"))


def remove_key_value(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    out = [line for line in lines if not _line_assigns_key(line, key)]
    return _render_remove(out, content.endswith("\n"))


def upsert_powershell_env(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    line_out = f"$env:{key} = '{value.replace("'", "''")}'"
    lines = content.splitlines()
    out, replaced = _replace_first_match(lines, replacement=line_out, matcher=lambda line: _matches_powershell_key(line, key))
    if not replaced:
        _append_with_optional_blank(out, line_out)
    return _render_upsert(out, content.endswith("\n"))


def remove_powershell_env(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    out = [line for line in lines if not _matches_powershell_key(line, key)]
    return _render_remove(out, content.endswith("\n"))
