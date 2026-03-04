from __future__ import annotations

import re
from typing import Callable, List, Tuple

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
    stripped = value.strip()
    if len(stripped) >= 2 and ((stripped[0] == stripped[-1] == "'") or (stripped[0] == stripped[-1] == '"')):
        stripped = stripped[1:-1]
    return stripped.replace("'\"'\"'", "'")


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _split_content(content: str) -> Tuple[List[str], bool]:
    return content.splitlines(), content.endswith("\n")


def _join_lines(lines: List[str], *, keep_trailing_newline: bool) -> str:
    text = "\n".join(lines)
    if keep_trailing_newline and lines:
        return text + "\n"
    return text


def _append_with_separator(lines: List[str], line: str) -> None:
    if lines and lines[-1].strip():
        lines.append("")
    lines.append(line)


def _upsert_lines(
    content: str,
    *,
    new_line: str,
    matches_key: Callable[[str], bool],
) -> str:
    lines, had_trailing_newline = _split_content(content)
    output: List[str] = []
    replaced = False

    for line in lines:
        if matches_key(line):
            if not replaced:
                output.append(new_line)
                replaced = True
            continue
        output.append(line)

    if not replaced:
        _append_with_separator(output, new_line)

    return _join_lines(output, keep_trailing_newline=had_trailing_newline or bool(output))


def _remove_lines(content: str, *, should_remove: Callable[[str], bool]) -> str:
    lines, had_trailing_newline = _split_content(content)
    output = [line for line in lines if not should_remove(line)]
    return _join_lines(output, keep_trailing_newline=had_trailing_newline and bool(output))


def _extract_assignment_key(stripped_line: str) -> str:
    match = ASSIGN_LINE_RE.match(stripped_line)
    return match.group(1) if match else ""


def _extract_export_key(stripped_line: str) -> str:
    match = EXPORT_LINE_RE.match(stripped_line)
    return match.group(1) if match else ""


def _is_comment_or_blank(stripped_line: str) -> bool:
    return not stripped_line or stripped_line.startswith("#")


def parse_dotenv_text(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if _is_comment_or_blank(stripped):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = strip_outer_quotes(value.strip())
        if key and ENV_KEY_RE.match(key):
            rows.append((key, value))
    return rows


def parse_bash_exports(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = EXPORT_LINE_RE.match(line)
        if match:
            key, raw_value = match.group(1), match.group(2).strip()
            values[key] = strip_outer_quotes(raw_value)
    return values


def parse_etc_environment(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if _is_comment_or_blank(stripped):
            continue
        match = ASSIGN_LINE_RE.match(stripped)
        if match:
            key, raw_value = match.group(1), match.group(2)
            values[key] = strip_outer_quotes(raw_value)
    return values


def upsert_export(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    export_line = f"export {key}={shell_single_quote(value)}"
    return _upsert_lines(content, new_line=export_line, matches_key=lambda line: _extract_export_key(line) == key)


def remove_export(content: str, key: str) -> str:
    validate_env_key(key)
    return _remove_lines(content, should_remove=lambda line: _extract_export_key(line) == key)


def upsert_key_value(content: str, key: str, value: str, *, quote: bool = False) -> str:
    validate_env_key(key)
    validate_env_value(value)
    line_out = f"{key}={shell_single_quote(value) if quote else value}"
    lines, had_trailing_newline = _split_content(content)
    output: List[str] = []
    replaced = False

    for line in lines:
        stripped = line.strip()
        if _is_comment_or_blank(stripped):
            output.append(line)
            continue
        if _extract_assignment_key(stripped) == key:
            if not replaced:
                output.append(line_out)
                replaced = True
            continue
        output.append(line)

    if not replaced:
        _append_with_separator(output, line_out)

    return _join_lines(output, keep_trailing_newline=had_trailing_newline or bool(output))


def remove_key_value(content: str, key: str) -> str:
    validate_env_key(key)

    def _should_remove(line: str) -> bool:
        stripped = line.strip()
        return _extract_assignment_key(stripped) == key or _extract_export_key(stripped) == key

    return _remove_lines(content, should_remove=_should_remove)


def upsert_powershell_env(content: str, key: str, value: str) -> str:
    validate_env_key(key)
    validate_env_value(value)
    escaped = value.replace("'", "''")
    line_out = f"$env:{key} = '{escaped}'"

    def _matches_key(line: str) -> bool:
        match = POWERSHELL_ENV_RE.match(line)
        return bool(match and match.group(1).lower() == key.lower())

    return _upsert_lines(content, new_line=line_out, matches_key=_matches_key)


def remove_powershell_env(content: str, key: str) -> str:
    validate_env_key(key)

    def _should_remove(line: str) -> bool:
        match = POWERSHELL_ENV_RE.match(line)
        return bool(match and match.group(1).lower() == key.lower())

    return _remove_lines(content, should_remove=_should_remove)