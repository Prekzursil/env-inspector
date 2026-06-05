"""Test quality security imports module."""

import importlib
import unittest
from pathlib import Path

from scripts.quality import _security_imports as security_imports


def _case() -> unittest.TestCase:
    """Case."""
    return unittest.TestCase()


def test_security_imports_reloads_and_exposes_helpers():
    """Test security imports reloads and exposes helpers."""
    reloaded = importlib.reload(security_imports)

    case = _case()
    case.assertTrue(callable(reloaded.normalize_https_url))
    case.assertTrue(callable(reloaded.request_json_https))
    case.assertTrue(callable(reloaded.safe_output_path_in_workspace))


def test_security_imports_fallback_loader_inserts_helper_root(monkeypatch):
    """Test security imports fallback loader inserts helper root."""
    import types

    case = _case()
    helper_root = str(Path(security_imports.__file__).resolve().parent.parent)
    monkeypatch.setattr(
        security_imports.sys,
        "path",
        [entry for entry in security_imports.sys.path if entry != helper_root],
    )

    def _fake_import_module(name: str):
        """Fake import module."""
        if name == "scripts.security_helpers":
            raise ModuleNotFoundError("scripts package unavailable")
        return types.SimpleNamespace(
            encode_identifier=lambda *args, **kwargs: "ok",
            normalize_https_url=lambda *args, **kwargs: "ok",
            request_json_https=lambda *args, **kwargs: ({}, {}),
            safe_input_file_path_in_workspace=lambda *args, **kwargs: Path("."),
            safe_output_path_in_workspace=lambda *args, **kwargs: Path("."),
            split_validated_https_url=lambda *args, **kwargs: ("host", "/", {}),
            write_zero_report=lambda *args, **kwargs: None,
            emit_zero_report=lambda *args, **kwargs: 0,
            ZeroReportSpec=object,
            render_findings_md=lambda *args, **kwargs: "",
        )

    monkeypatch.setattr(
        security_imports.importlib, "import_module", _fake_import_module
    )

    loaded = security_imports._load_helpers_module()

    case.assertTrue(hasattr(loaded, "request_json_https"))
    case.assertIn(helper_root, security_imports.sys.path)


def test_load_quality_module_prefers_qualified_name():
    """Return the package-qualified module when it imports successfully."""
    from scripts.quality import _module_loader

    case = _case()
    loaded = _module_loader.load_quality_module(
        "scripts.quality._security_imports", "_security_imports"
    )

    case.assertTrue(hasattr(loaded, "emit_zero_report"))


def test_load_quality_module_falls_back_to_bare_name(monkeypatch):
    """Insert the helper root and import the bare name when qualified fails."""
    import types

    from scripts.quality import _module_loader

    case = _case()
    helper_root = str(Path(_module_loader.__file__).resolve().parent)
    monkeypatch.setattr(
        _module_loader.sys,
        "path",
        [entry for entry in _module_loader.sys.path if entry != helper_root],
    )
    sentinel = types.SimpleNamespace(loaded=True)

    def _fake_import_module(name: str):
        """Fake import module."""
        if name == "scripts.quality._missing":
            raise ModuleNotFoundError("package form unavailable")
        case.assertEqual(name, "_missing")
        return sentinel

    monkeypatch.setattr(_module_loader.importlib, "import_module", _fake_import_module)

    loaded = _module_loader.load_quality_module("scripts.quality._missing", "_missing")

    case.assertIs(loaded, sentinel)
    case.assertIn(helper_root, _module_loader.sys.path)
