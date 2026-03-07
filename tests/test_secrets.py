from __future__ import absolute_import, division

import unittest

from env_inspector_core.secrets import looks_secret, mask_value


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_looks_secret_handles_empty_name_and_non_secret_value():
    _case().assertFalse(looks_secret("", "plain-value"))


def test_looks_secret_detects_base64ish_non_path_value():
    candidate = "A" * 64
    _case().assertTrue(looks_secret("RANDOM", candidate))


def test_looks_secret_rejects_path_like_base64_candidate():
    candidate = "C:/" + ("A" * 61)
    _case().assertFalse(looks_secret("RANDOM", candidate))


def test_mask_value_short_and_long_cases():
    case = _case()
    case.assertEqual(mask_value("secret"), "******")
    masked = mask_value("abcdefghijklmnop")
    case.assertTrue(masked.startswith("abc"))
    case.assertTrue(masked.endswith("nop"))
