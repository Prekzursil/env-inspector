from __future__ import annotations

import re

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


def _append_with_spacing(out: list[str], line_out: str) -> None:
    if out and out[-1].strip():
        out.append("")
    out.append(line_out)


def _match_key_assignment(stripped: str, key: str) -> bool:
    assign_match = ASSIGN_LINE_RE.match(stripped)
    if assign_match and assign_match.group(1) == key:
        return True
    export_match = EXPORT_LINE_RE.match(stripped)
    return bool(export_match and export_match.group(1) == key)


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
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    replaced = False
    for line in lines:
        match = EXPORT_LINE_RE.match(line)
        if match and match.group(1) == key:
            if not replaced:
                out.append(export_line)
                replaced = True
            continue
        out.append(line)

    if not replaced:
        _append_with_spacing(out, export_line)

    text = "\n".join(out)
    if had_trailing_newline or out:
        text += "\n"
    return text


def remove_export(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    for line in lines:
        match = EXPORT_LINE_RE.match(line)
        if match and match.group(1) == key:
            continue
        out.append(line)

    text = "\n".join(out)
    if had_trailing_newline and out:
        text += "\n"
    return text


def _upsert_assignment_line(line: str, *, key: str, line_out: str, replaced: bool) -> tuple[str | None, bool]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line, replaced

    match = ASSIGN_LINE_RE.match(stripped)
    if not match or match.group(1) != key:
        return line, replaced

    if replaced:
        return None, replaced
    return line_out, True


def upsert_key_value(content: str, key: str, value: str, *, quote: bool = False) -> str:
    validate_env_key(key)
    validate_env_value(value)
    new_value = shell_single_quote(value) if quote else value
    line_out = f"{key}={new_value}"
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    replaced = False
    for line in lines:
        next_line, replaced = _upsert_assignment_line(line, key=key, line_out=line_out, replaced=replaced)
        if next_line is None:
            continue
        out.append(next_line)

    if not replaced:
        _append_with_spacing(out, line_out)

    text = "\n".join(out)
    if had_trailing_newline or out:
        text += "\n"
    return text


def remove_key_value(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if _match_key_assignment(stripped, key):
            continue
        out.append(line)

    text = "\n".join(out)
    if had_trailing_newline and out:
        text += "\n"
    return text


def upsert_powershell_env(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    escaped = value.replace("'", "''")
    line_out = f"$env:{key} = '{escaped}'"

    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    replaced = False
    for line in lines:
        match = POWERSHELL_ENV_RE.match(line)
        if match and match.group(1).lower() == key.lower():
            if not replaced:
                out.append(line_out)
                replaced = True
            continue
        out.append(line)

    if not replaced:
        _append_with_spacing(out, line_out)

    text = "\n".join(out)
    if had_trailing_newline or out:
        text += "\n"
    return text


def remove_powershell_env(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out: list[str] = []
    for line in lines:
        match = POWERSHELL_ENV_RE.match(line)
        if match and match.group(1).lower() == key.lower():
            continue
        out.append(line)

    text = "\n".join(out)
    if had_trailing_newline and out:
        text += "\n"
    return text
