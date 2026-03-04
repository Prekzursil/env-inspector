from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_security_helpers() -> ModuleType:
    helper_path = Path(__file__).resolve().parent.parent / "security_helpers.py"
    spec = importlib.util.spec_from_file_location("security_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load security helpers from {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HELPERS = _load_security_helpers()

encode_identifier = _HELPERS.encode_identifier
normalize_https_url = _HELPERS.normalize_https_url
request_json_https = _HELPERS.request_json_https
safe_input_file_path_in_workspace = _HELPERS.safe_input_file_path_in_workspace
safe_output_path_in_workspace = _HELPERS.safe_output_path_in_workspace
split_validated_https_url = _HELPERS.split_validated_https_url

__all__ = [
    "encode_identifier",
    "normalize_https_url",
    "request_json_https",
    "safe_input_file_path_in_workspace",
    "safe_output_path_in_workspace",
    "split_validated_https_url",
]
