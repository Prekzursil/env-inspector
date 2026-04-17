"""Security imports module."""

import importlib
import sys
from pathlib import Path


def _load_helpers_module():
    """Load helpers module."""
    try:
        return importlib.import_module("scripts.security_helpers")
    except ModuleNotFoundError:
        helper_root = Path(__file__).resolve().parent.parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("security_helpers")


_helpers = _load_helpers_module()
encode_identifier = _helpers.encode_identifier
normalize_https_url = _helpers.normalize_https_url
request_json_https = _helpers.request_json_https
safe_input_file_path_in_workspace = _helpers.safe_input_file_path_in_workspace
safe_output_path_in_workspace = _helpers.safe_output_path_in_workspace
split_validated_https_url = _helpers.split_validated_https_url


__all__ = [
    "encode_identifier",
    "normalize_https_url",
    "request_json_https",
    "safe_input_file_path_in_workspace",
    "safe_output_path_in_workspace",
    "split_validated_https_url",
]
