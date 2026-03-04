from __future__ import absolute_import, division

from env_inspector_core.parsing import (
    parse_dotenv_text,
    parse_bash_exports,
    parse_etc_environment,
    upsert_export,
    remove_export,
    remove_powershell_env,
    upsert_powershell_env,
)


def test_parse_dotenv_text_supports_export_comments_and_quotes():
    text = """
# comment
export API_TOKEN='abc123'
PLAIN=value
QUOTED=\"hello world\"
INVALID_LINE
"""
    records = parse_dotenv_text(text)
    names = [r[0] for r in records]
    assert names == ["API_TOKEN", "PLAIN", "QUOTED"]
    assert dict(records)["API_TOKEN"] == "abc123"
    assert dict(records)["QUOTED"] == "hello world"


def test_parse_bash_exports_only_reads_export_lines():
    text = """
export A=1
B=2
 export C='three'
"""
    parsed = parse_bash_exports(text)
    assert parsed == {"A": "1", "C": "three"}


def test_parse_etc_environment_ignores_comments_and_blank_lines():
    text = """
# header
LANG=en_US.UTF-8
PATH=\"/usr/local/bin:/usr/bin\"

"""
    parsed = parse_etc_environment(text)
    assert parsed == {"LANG": "en_US.UTF-8", "PATH": "/usr/local/bin:/usr/bin"}


def test_upsert_and_remove_export_roundtrip():
    base = "export A='1'\n"
    updated = upsert_export(base, "B", "two")
    assert "export B='two'" in updated

    replaced = upsert_export(updated, "A", "9")
    assert "export A='9'" in replaced
    assert replaced.count("export A=") == 1

    removed = remove_export(replaced, "B")
    assert "export B=" not in removed


def test_upsert_and_remove_powershell_env_roundtrip():
    base = "$env:API_TOKEN = 'old'\nWrite-Host 'hi'\n"
    updated = upsert_powershell_env(base, "API_TOKEN", "new")
    assert "$env:API_TOKEN = 'new'" in updated
    assert updated.count("$env:API_TOKEN") == 1

    appended = upsert_powershell_env(updated, "NEW_KEY", "v")
    assert "$env:NEW_KEY = 'v'" in appended

    removed = remove_powershell_env(appended, "API_TOKEN")
    assert "$env:API_TOKEN" not in removed
