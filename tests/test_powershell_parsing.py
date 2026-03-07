from __future__ import absolute_import, division
from env_inspector_core.providers import parse_powershell_profile_text

from tests.assertions import ensure

def test_parse_powershell_profile_env_assignments():
    text = """
# comment
$env:API_TOKEN = "fixture-value"
$env:PATH = '/usr/bin'
$env:EMPTY = ""
Write-Host "ignore"
"""
    rows = parse_powershell_profile_text(text)
    parsed = dict(rows)
    ensure(parsed["API_TOKEN"] == "fixture-value")
    ensure(parsed["PATH"] == "/usr/bin")
    ensure(parsed["EMPTY"] == "")
