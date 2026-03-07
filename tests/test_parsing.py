from __future__ import absolute_import, division
from env_inspector_core.parsing import (
    parse_dotenv_text,
    parse_bash_exports,
    parse_etc_environment,
    upsert_export,
    upsert_key_value,
    remove_export,
    remove_key_value,
    remove_powershell_env,
    upsert_powershell_env,
)
import unittest


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_parse_dotenv_text_supports_export_comments_and_quotes():
    text = """
# comment
export API_TOKEN='fixture-value'
PLAIN=value
QUOTED="hello world"
INVALID_LINE
"""
    records = parse_dotenv_text(text)
    names = [r[0] for r in records]
    case = _case()
    case.assertEqual(names, ["API_TOKEN", "PLAIN", "QUOTED"])
    case.assertEqual(dict(records)["API_TOKEN"], "fixture-value")
    case.assertEqual(dict(records)["QUOTED"], "hello world")


def test_parse_bash_exports_only_reads_export_lines():
    text = """
export A=1
B=2
 export C='three'
"""
    parsed = parse_bash_exports(text)
    _case().assertEqual(parsed, {"A": "1", "C": "three"})


def test_parse_etc_environment_ignores_comments_and_blank_lines():
    text = """
# header
LANG=en_US.UTF-8
PATH="/usr/local/bin:/usr/bin"

"""
    parsed = parse_etc_environment(text)
    _case().assertEqual(parsed, {"LANG": "en_US.UTF-8", "PATH": "/usr/local/bin:/usr/bin"})


def test_upsert_and_remove_export_roundtrip():
    base = "export A='1'\n"
    updated = upsert_export(base, "B", "two")
    case = _case()
    case.assertIn("export B='two'", updated)

    replaced = upsert_export(updated, "A", "9")
    case.assertIn("export A='9'", replaced)
    case.assertEqual(replaced.count("export A="), 1)

    removed = remove_export(replaced, "B")
    case.assertNotIn("export B=", removed)


def test_remove_key_value_handles_assign_export_and_comments():
    base = "# keep me\n\nA=1\n export A='2'\nB=3\n"

    removed = remove_key_value(base, "A")

    case = _case()
    case.assertNotIn("A=1", removed)
    case.assertNotIn("export A='2'", removed)
    case.assertIn("# keep me", removed)
    case.assertIn("B=3", removed)


def test_upsert_and_remove_powershell_env_roundtrip():
    base = "$env:API_TOKEN = 'old'\nWrite-Host 'hi'\n"
    updated = upsert_powershell_env(base, "API_TOKEN", "new")
    case = _case()
    case.assertIn("$env:API_TOKEN = 'new'", updated)
    case.assertEqual(updated.count("$env:API_TOKEN"), 1)

    appended = upsert_powershell_env(updated, "NEW_KEY", "v")
    case.assertIn("$env:NEW_KEY = 'v'", appended)

    removed = remove_powershell_env(appended, "api_token")
    case.assertNotIn("$env:API_TOKEN", removed)


def test_upsert_key_value_ignores_blank_and_comment_lines_when_matching():
    base = "# keep\n\nA=1\n"

    updated = upsert_key_value(base, "NEW_KEY", "v", quote=False)

    case = _case()
    case.assertIn("# keep", updated)
    case.assertIn("A=1", updated)
    case.assertIn("NEW_KEY=v", updated)
