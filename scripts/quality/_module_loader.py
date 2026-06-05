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

    Security note: ``qualified_name``/``bare_name`` are NOT untrusted input.
    Every call site passes a pair of hard-coded string literals naming a
    sibling quality-gate module (e.g. ``"scripts.quality._codacy_zero_impl"``
    / ``"_codacy_zero_impl"``); the values never derive from CLI args, env,
    network, or the filesystem. Opengrep/Semgrep's ``non-literal-import``
    audit rule is purely syntactic and fires on any non-literal argument, so
    the two ``import_module`` calls below carry a ``# nosemgrep`` annotation
    rather than a refactor (no allowlist guard can make the rule pass while
    keeping a variable module name).
    """
    try:
        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        return importlib.import_module(qualified_name)
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        return importlib.import_module(bare_name)
