"""Tests for env-file parsing and mutation helpers."""

import unittest

import env_inspector_core.parsing as parsing


def _case() -> unittest.TestCase:
    """Return a lightweight unittest assertion helper."""
    return unittest.TestCase()


def test_parse_dotenv_text_supports_export_comments_and_quotes():
    """Parse dotenv text while preserving valid exports and quoted values."""
    text = """
# comment
export API_TOKEN='fixture-value'
PLAIN=value
QUOTED="hello world"
INVALID_LINE
"""
    records = parsing.parse_dotenv_text(text)
    names = [r[0] for r in records]
    case = _case()
    case.assertEqual(names, ["API_TOKEN", "PLAIN", "QUOTED"])
    case.assertEqual(dict(records)["API_TOKEN"], "fixture-value")
    case.assertEqual(dict(records)["QUOTED"], "hello world")


def test_parse_bash_exports_only_reads_export_lines():
    """Ignore non-export assignments when parsing shell exports."""
    text = """
export A=1
B=2
 export C='three'
"""
    parsed = parsing.parse_bash_exports(text)
    _case().assertEqual(parsed, {"A": "1", "C": "three"})


def test_parse_etc_environment_ignores_comments_and_blank_lines():
    """Ignore comments and blank lines in `/etc/environment` style files."""
    text = """
# header
LANG=en_US.UTF-8
PATH="/usr/local/bin:/usr/bin"

"""
    parsed = parsing.parse_etc_environment(text)
    _case().assertEqual(
        parsed, {"LANG": "en_US.UTF-8", "PATH": "/usr/local/bin:/usr/bin"}
    )


def test_upsert_and_remove_export_roundtrip():
    """Round-trip exported variables through insert, replace, and removal."""
    base = "export A='1'\n"
    updated = parsing.upsert_export(base, "B", "two")
    case = _case()
    case.assertIn("export B='two'", updated)

    replaced = parsing.upsert_export(updated, "A", "9")
    case.assertIn("export A='9'", replaced)
    case.assertEqual(replaced.count("export A="), 1)

    removed = parsing.remove_export(replaced, "B")
    case.assertNotIn("export B=", removed)


def test_remove_key_value_handles_assign_export_and_comments():
    """Remove matching assignments without disturbing unrelated lines."""
    base = "# keep me\n\nA=1\n export A='2'\nB=3\n"

    removed = parsing.remove_key_value(base, "A")

    case = _case()
    case.assertNotIn("A=1", removed)
    case.assertNotIn("export A='2'", removed)
    case.assertIn("# keep me", removed)
    case.assertIn("B=3", removed)


def test_upsert_and_remove_powershell_env_roundtrip():
    """Round-trip PowerShell environment assignments through mutation helpers."""
    base = "$env:API_TOKEN = 'old'\nWrite-Host 'hi'\n"
    updated = parsing.upsert_powershell_env(base, "API_TOKEN", "new")
    case = _case()
    case.assertIn("$env:API_TOKEN = 'new'", updated)
    case.assertEqual(updated.count("$env:API_TOKEN"), 1)

    appended = parsing.upsert_powershell_env(updated, "NEW_KEY", "v")
    case.assertIn("$env:NEW_KEY = 'v'", appended)

    removed = parsing.remove_powershell_env(appended, "api_token")
    case.assertNotIn("$env:API_TOKEN", removed)


def test_upsert_key_value_ignores_blank_and_comment_lines_when_matching():
    """Append new key/value pairs without clobbering comments or blanks."""
    base = "# keep\n\nA=1\n"

    updated = parsing.upsert_key_value(base, "NEW_KEY", "v", quote=False)

    case = _case()
    case.assertIn("# keep", updated)
    case.assertIn("A=1", updated)
    case.assertIn("NEW_KEY=v", updated)
