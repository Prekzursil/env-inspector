"""Coverage tests for parsing.py — validation and parsing edge cases."""

from __future__ import absolute_import, division
from tests.assertions import ensure

import pytest

from env_inspector_core.parsing import (
    validate_env_key,
    validate_env_value,
    parse_dotenv_text,
    parse_etc_environment,
    _render_upsert,
    _render_remove,
    _replace_first_match,
    upsert_export,
)


# Line 18: validate_env_key empty key
def test_validate_env_key_empty() -> None:
    """validate_env_key raises ValueError for empty key."""
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_env_key("")


# Line 20: validate_env_key invalid format
def test_validate_env_key_invalid_format() -> None:
    """validate_env_key raises ValueError for invalid key format."""
    with pytest.raises(ValueError, match="Invalid key format"):
        validate_env_key("1INVALID")


# Line 26: validate_env_value null byte
def test_validate_env_value_null_byte() -> None:
    """validate_env_value raises ValueError for values with null bytes."""
    with pytest.raises(ValueError, match="null bytes"):
        validate_env_value("bad\x00value")


# Line 130: parse_dotenv_text skips invalid keys
def test_parse_dotenv_text_skips_invalid_key() -> None:
    """parse_dotenv_text skips lines with invalid key format."""
    text = "1BAD_KEY=value\nGOOD_KEY=value\n"
    result = parse_dotenv_text(text)
    ensure(len(result) == 1)
    ensure(result[0][0] == "GOOD_KEY")


# Line 156: parse_etc_environment skips non-matching lines
def test_parse_etc_environment_skips_non_matching_lines() -> None:
    """parse_etc_environment skips lines that don't match KEY=value pattern."""
    text = "VALID=1\nnot a valid line\n# comment\n\n"
    result = parse_etc_environment(text)
    assert len(result) == 1
    ensure(result["VALID"] == "1")


# Branch 45->47: _render_upsert with empty lines and no trailing newline
def test_render_upsert_empty_lines_no_trailing() -> None:
    """_render_upsert empty lines, no trailing newline gives empty string (branch 45->47)."""
    result = _render_upsert([], False)
    # "\n".join([]) = "", then `False or []` is falsy, so no newline
    ensure(result == "")


# Branch 53->55: _render_remove with trailing newline but empty lines
def test_render_remove_trailing_newline_empty_lines() -> None:
    """_render_remove with trailing newline but empty lines (branch 53->55)."""
    result = _render_remove([], True)
    # "\n".join([]) = "", had_trailing_newline=True, lines=[] (falsy)
    # condition: True and [] -> falsy -> no newline
    assert result == ""


# Branch 76->79: _replace_first_match with duplicate matching lines
def test_replace_first_match_drops_duplicates() -> None:
    """_replace_first_match replaces first match and drops later duplicates (branch 76->79)."""
    lines = ["export A='1'", "export B='2'", "export A='3'"]
    out, replaced = _replace_first_match(
        lines,
        replacement="export A='new'",
        matcher=lambda line: "export A=" in line,
    )
    ensure(replaced is True)
    ensure(out == ["export A='new'", "export B='2'"])
    # The second "export A='3'" line was dropped


def test_upsert_export_replaces_duplicates() -> None:
    """upsert_export handles content with duplicate export lines."""
    content = "export A='1'\nexport B='2'\nexport A='3'\n"
    result = upsert_export(content, "A", "new")
    ensure(result.count("export A=") == 1)
    ensure("export A='new'" in result)
    ensure("export B='2'" in result)
