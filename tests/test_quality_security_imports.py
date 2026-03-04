import importlib
import unittest

from scripts.quality import _security_imports as security_imports


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_security_imports_reloads_and_exposes_helpers():
    reloaded = importlib.reload(security_imports)

    case = _case()
    case.assertTrue(callable(reloaded.normalize_https_url))
    case.assertTrue(callable(reloaded.request_json_https))
    case.assertTrue(callable(reloaded.safe_output_path_in_workspace))
