from env_inspector_core.secrets import looks_secret, mask_value


def test_looks_secret_handles_empty_name_and_non_secret_value():
    assert looks_secret("", "plain-value") is False


def test_looks_secret_detects_base64ish_non_path_value():
    candidate = "A" * 64
    assert looks_secret("RANDOM", candidate) is True


def test_looks_secret_rejects_path_like_base64_candidate():
    candidate = "C:/" + ("A" * 61)
    assert looks_secret("RANDOM", candidate) is False


def test_mask_value_short_and_long_cases():
    assert mask_value("secret") == "******"
    masked = mask_value("abcdefghijklmnop")
    assert masked.startswith("abc") and masked.endswith("nop")
