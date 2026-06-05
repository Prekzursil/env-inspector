"""Shared sibling-module loader for quality-gate scripts.

Quality scripts run both as package modules (``scripts.quality.x``) and as
bare scripts (``python check_x.py``) inside CI. Each form needs a different
import strategy, so this module centralises the package-then-bare fallback
that every gate script previously reimplemented.
"""

import importlib
import sys
from pathlib import Path
from typing import Any


def load_quality_module(qualified_name: str, bare_name: str) -> Any:
    """Import a sibling quality module by qualified or bare name.

    Tries the fully qualified ``scripts.quality.<name>`` import first (package
    execution). When that module is unavailable (direct script execution),
    ensures the ``scripts/quality`` directory is importable and falls back to
    the bare module name. Returns the imported module object.
    """
    try:
        return importlib.import_module(qualified_name)
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module(bare_name)
