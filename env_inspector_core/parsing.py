from __future__ import annotations

import re
from collections.abc import Callable

ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
EXPORT_LINE_RE = re.compile(r"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
ASSIGN_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
POWERSHELL_ENV_RE = re.compile(r"^\s*\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=", re.IGNORECASE)


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


def _is_blank_or_comment(stripped_line: str) -> bool:
    return (not stripped_line) or stripped_line.startswith("#")


def _first_group(match: re.Match[str] | None) -> str | None:
    return match.group(1) if match else None


def _export_key(line: str) -> str | None:
    return _first_group(EXPORT_LINE_RE.match(line))


def _assign_key(line: str) -> str | None:
    return _first_group(ASSIGN_LINE_RE.match(line))


def _powershell_key(line: str) -> str | None:
    return _first_group(POWERSHELL_ENV_RE.match(line))


def _replace_first_and_drop_rest(
    lines: list[str], *, replacement: str, should_replace: Callable[[str], bool]
) -> tuple[list[str], bool]:
    out: list[str] = []
    replaced = False
    for line in lines:
        if should_replace(line):
            if replaced:
                continue
            out.append(replacement)
            replaced = True
            continue
        out.append(line)
    return out, replaced


def _append_line_with_spacing(out: list[str], line: str) -> None:
    if out and out[-1].strip():
        out.append("")
    out.append(line)


def _line_targets_key(line: str, key: str) -> bool:
    stripped = line.strip()
    return _assign_key(stripped) == key or _export_key(stripped) == key


def _update_assignment_line(
    out: list[str],
    replaced: bool,
    *,
    stripped_line: str,
    key: str,
    line_out: str,
    original_line: str,
) -> tuple[list[str], bool]:
    if _assign_key(stripped_line) != key:
        out.append(original_line)
        return out, replaced
    if not replaced:
        out.append(line_out)
    return out, True


def upsert_export(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    export_line = f"export {key}={shell_single_quote(value)}"
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")

    out, replaced = _replace_first_and_drop_rest(
        lines,
        replacement=export_line,
        should_replace=lambda line: _export_key(line) == key,
    )

    if not replaced:
        _append_line_with_spacing(out, export_line)

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
        stripped = line.strip()
        if _is_blank_or_comment(stripped):
            out.append(line)
            continue
        out, replaced = _update_assignment_line(
            out,
            replaced,
            stripped_line=stripped,
            key=key,
            line_out=line_out,
            original_line=line,
        )

    if not replaced:
        _append_line_with_spacing(out, line_out)

    text = "\n".join(out)
    if had_trailing_newline or out:
        text += "\n"
    return text


def remove_key_value(content: str, key: str) -> str:
    validate_env_key(key)
    lines = content.splitlines()
    had_trailing_newline = content.endswith("\n")
    out = [line for line in lines if not _line_targets_key(line, key)]

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
    target_key = key.lower()

    out, replaced = _replace_first_and_drop_rest(
        lines,
        replacement=line_out,
        should_replace=lambda line: (_powershell_key(line) or "").lower() == target_key,
    )

    if not replaced:
        _append_line_with_spacing(out, line_out)

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
