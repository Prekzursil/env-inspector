from __future__ import absolute_import, division

from env_inspector_core.providers import parse_powershell_profile_text


def test_parse_powershell_profile_env_assignments():
    text = """
# comment
$env:API_TOKEN = "abc123"
$env:PATH = '/usr/bin'
$env:EMPTY = ""
Write-Host "ignore"
"""
    rows = parse_powershell_profile_text(text)
    parsed = dict(rows)
    assert parsed["API_TOKEN"] == "abc123"
    assert parsed["PATH"] == "/usr/bin"
    assert parsed["EMPTY"] == ""

def test_parse_powershell_profile_ignores_invalid_env_assignments():
    text = """
$env:VALID_KEY = "ok"
$env:1INVALID = "skip"
$env:MISSING_EQUALS
$Env:CASE_OK = 'works'
$env:ALSO_OK = value ;
"""

    rows = dict(parse_powershell_profile_text(text))

    assert rows["VALID_KEY"] == "ok"
    assert rows["CASE_OK"] == "works"
    assert rows["ALSO_OK"] == "value"
    assert "1INVALID" not in rows
    assert "MISSING_EQUALS" not in rows

