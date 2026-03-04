import importlib
from pathlib import Path
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



def test_security_imports_fallback_loader_inserts_helper_root(monkeypatch):
    import types

    case = _case()
    helper_root = str(Path(security_imports.__file__).resolve().parent.parent)
    monkeypatch.setattr(security_imports.sys, "path", [entry for entry in security_imports.sys.path if entry != helper_root])

    def _fake_import_module(name: str):
        if name == "scripts.security_helpers":
            raise ModuleNotFoundError("scripts package unavailable")
        return types.SimpleNamespace(
            encode_identifier=lambda *args, **kwargs: "ok",
            normalize_https_url=lambda *args, **kwargs: "ok",
            request_json_https=lambda *args, **kwargs: ({}, {}),
            safe_input_file_path_in_workspace=lambda *args, **kwargs: Path("."),
            safe_output_path_in_workspace=lambda *args, **kwargs: Path("."),
            split_validated_https_url=lambda *args, **kwargs: ("host", "/", {}),
        )

    monkeypatch.setattr(security_imports.importlib, "import_module", _fake_import_module)

    loaded = security_imports._load_helpers_module()

    case.assertTrue(hasattr(loaded, "request_json_https"))
    case.assertIn(helper_root, security_imports.sys.path)
