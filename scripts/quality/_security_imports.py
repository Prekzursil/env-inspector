from __future__ import annotations, absolute_import, division

import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_HELPER_ROOT = _SCRIPT_DIR if (_SCRIPT_DIR / "security_helpers.py").exists() else _SCRIPT_DIR.parent
if str(_HELPER_ROOT) not in sys.path:
    sys.path.insert(0, str(_HELPER_ROOT))

from security_helpers import (
    encode_identifier,
    normalize_https_url,
    request_json_https,
    safe_input_file_path_in_workspace,
    safe_output_path_in_workspace,
    split_validated_https_url,
)

__all__ = [
    "encode_identifier",
    "normalize_https_url",
    "request_json_https",
    "safe_input_file_path_in_workspace",
    "safe_output_path_in_workspace",
    "split_validated_https_url",
]

