from env_inspector_core import secrets


def test_looks_path_like_detects_colon_and_backslash_patterns():
    assert secrets._looks_path_like("/opt/app/file") is True
    assert secrets._looks_path_like("C:\\Program Files\\file") is True
    assert secrets._looks_path_like("https://example.com") is True
    assert secrets._looks_path_like("plain-token-value") is False

