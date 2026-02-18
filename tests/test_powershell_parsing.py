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
