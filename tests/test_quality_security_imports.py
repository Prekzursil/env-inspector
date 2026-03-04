from __future__ import annotations

import importlib
import sys
from pathlib import Path

from scripts.quality import _security_imports as security_imports


def test_security_imports_adds_helper_root_to_sys_path(monkeypatch):
    helper_root = str(Path(security_imports.__file__).resolve().parent.parent)
    monkeypatch.setattr(sys, "path", [entry for entry in sys.path if entry != helper_root])

    reloaded = importlib.reload(security_imports)

    assert helper_root in sys.path
    assert callable(reloaded.normalize_https_url)
