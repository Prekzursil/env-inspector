from __future__ import absolute_import, division

from env_inspector_core.providers import parse_powershell_profile_text

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



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
    _expect(parsed["API_TOKEN"] == "abc123")

    _expect(parsed["PATH"] == "/usr/bin")

    _expect(parsed["EMPTY"] == "")
