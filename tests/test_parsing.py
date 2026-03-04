from tests.conftest import ensure
from env_inspector_core import parsing
from env_inspector_core.parsing import (
    parse_dotenv_text,
    parse_bash_exports,
    parse_etc_environment,
    remove_key_value,
    remove_export,
    remove_powershell_env,
    upsert_export,
    upsert_key_value,
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
    ensure(names == ['API_TOKEN', 'PLAIN', 'QUOTED'])
    ensure(dict(records)['API_TOKEN'] == 'abc123')
    ensure(dict(records)['QUOTED'] == 'hello world')


def test_parse_bash_exports_only_reads_export_lines():
    text = """
export A=1
B=2
 export C='three'
"""
    parsed = parse_bash_exports(text)
    ensure(parsed == {'A': '1', 'C': 'three'})


def test_parse_etc_environment_ignores_comments_and_blank_lines():
    text = """
# header
LANG=en_US.UTF-8
PATH=\"/usr/local/bin:/usr/bin\"

"""
    parsed = parse_etc_environment(text)
    ensure(parsed == {'LANG': 'en_US.UTF-8', 'PATH': '/usr/local/bin:/usr/bin'})


def test_upsert_and_remove_export_roundtrip():
    base = "export A='1'\n"
    updated = upsert_export(base, "B", "two")
    ensure("export B='two'" in updated)

    replaced = upsert_export(updated, "A", "9")
    ensure("export A='9'" in replaced)
    ensure(replaced.count('export A=') == 1)

    removed = remove_export(replaced, "B")
    ensure('export B=' not in removed)


def test_upsert_and_remove_powershell_env_roundtrip():
    base = "$env:API_TOKEN = 'old'\nWrite-Host 'hi'\n"
    updated = upsert_powershell_env(base, "API_TOKEN", "new")
    ensure("$env:API_TOKEN = 'new'" in updated)
    ensure(updated.count('$env:API_TOKEN') == 1)

    appended = upsert_powershell_env(updated, "NEW_KEY", "v")
    ensure("$env:NEW_KEY = 'v'" in appended)

    removed = remove_powershell_env(appended, "API_TOKEN")
    ensure('$env:API_TOKEN' not in removed)


def test_upsert_key_value_preserves_comments_and_appends_when_missing():
    base = "# keep\nA=1\n"
    updated = upsert_key_value(base, "B", "2", quote=False)

    ensure(updated.startswith('# keep\n'))
    ensure('B=2' in updated)


def test_remove_key_value_strips_assignment_and_export_variants():
    text = "A=1\nexport A=2\nB=3\n"

    removed = remove_key_value(text, "A")

    ensure(removed == 'B=3\n')


def test_join_lines_handles_no_trailing_newline_case():
    ensure(parsing._join_lines(['A=1'], keep_trailing_newline=False) == 'A=1')
