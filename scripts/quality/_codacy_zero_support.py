#!/usr/bin/env python3
from __future__ import absolute_import, division

from dataclasses import dataclass, replace
import importlib
from pathlib import Path
import sys
import urllib.error
from typing import Any, Callable, Dict, List, Tuple, cast

TOTAL_KEYS = ("total", "totalItems", "total_items", "count", "hits", "open_issues")
CODACY_API_HOST = "api.codacy.com"
CODACY_REQUEST_EXCEPTIONS = (urllib.error.URLError, ValueError, TypeError, RuntimeError)

RequestJsonHttps = Callable[..., Tuple[Any, Dict[str, str]]]
EncodeIdentifier = Callable[..., str]
SafeOutputPathInWorkspace = Callable[..., Path]


@dataclass(frozen=True)
class CodacyRequest:
    """Parameters for a Codacy API issue-search request."""

    provider: str
    owner: str
    repo: str
    token: str
    branch: str = ""
    limit: int = 1
    method: str = "GET"
    data: Dict[str, Any] | None = None


def _load_security_imports() -> Any:
    try:
        return importlib.import_module("scripts.quality._security_imports")
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        helper_root = Path(__file__).resolve().parent
        helper_root_str = str(helper_root)
        if helper_root_str not in sys.path:
            sys.path.insert(0, helper_root_str)
        return importlib.import_module("_security_imports")


_security_imports = _load_security_imports()
encode_identifier = cast(EncodeIdentifier, _security_imports.encode_identifier)
request_json_https = cast(RequestJsonHttps, _security_imports.request_json_https)
safe_output_path_in_workspace = cast(
    SafeOutputPathInWorkspace,
    _security_imports.safe_output_path_in_workspace,
)


def _public_codacy_module() -> Any | None:
    return sys.modules.get("scripts.quality.check_codacy_zero")

__all__ = [
    "CODACY_API_HOST",
    "CODACY_REQUEST_EXCEPTIONS",
    "TOTAL_KEYS",
    "CodacyRequest",
    "_fetch_sample_payload",
    "_format_issue_sample",
    "_first_text",
    "_provider_candidates",
    "_request_json",
    "_sample_issue_findings",
    "encode_identifier",
    "request_json_https",
    "safe_output_path_in_workspace",
]


def _request_json(request: CodacyRequest | None = None, **kwargs: Any) -> Dict[str, Any]:
    if request is None:
        request = CodacyRequest(**kwargs)
    elif kwargs:
        raise TypeError("Pass either a CodacyRequest or keyword arguments, not both.")

    headers = {
        "Accept": "application/json",
        "api-token": request.token,
        "User-Agent": "reframe-codacy-zero-gate",
    }
    if request.data is not None:
        headers["Content-Type"] = "application/json"

    public = _public_codacy_module()
    request_json_fn = cast(RequestJsonHttps, getattr(public, "request_json_https", request_json_https))
    encode_identifier_fn = cast(EncodeIdentifier, getattr(public, "encode_identifier", encode_identifier))

    provider_slug = encode_identifier_fn(request.provider, field_name="Codacy provider")
    owner_slug = encode_identifier_fn(request.owner, field_name="Codacy owner")
    repo_slug = encode_identifier_fn(request.repo, field_name="Codacy repository")

    payload_data: Dict[str, Any] = dict(request.data or {})
    branch_name = str(request.branch or "").strip()
    if branch_name:
        payload_data = {**payload_data, "branchName": branch_name}

    payload, _headers = request_json_fn(
        host=CODACY_API_HOST,
        path=f"/api/v3/analysis/organizations/{provider_slug}/{owner_slug}/repositories/{repo_slug}/issues/search",
        headers=headers,
        method=request.method,
        query={"limit": str(max(request.limit, 1))},
        data=payload_data,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Codacy response payload.")
    return payload


def _provider_candidates(preferred: str) -> List[str]:
    values = [preferred, "gh", "github"]
    return list(dict.fromkeys(item for item in values if item))


def _first_text(issue: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = str(issue.get(key) or "").strip()
        if value:
            return value
    return ""


def _format_issue_sample(issue: dict) -> str | None:
    pattern = _first_text(issue, ("patternId", "pattern"))
    path = _first_text(issue, ("filename", "filePath", "path"))
    message = _first_text(issue, ("message", "title"))
    if not (pattern or path or message):
        return None

    identity = pattern or "pattern:unknown"
    location = path or "file:unknown"
    suffix = f" - {message}" if message else ""
    return f"Sample issue: `{identity}` at `{location}`{suffix}"


def _sample_issue_findings(payload: dict, limit: int = 5) -> List[str]:
    data = payload.get("data")
    if not isinstance(data, list):
        return []

    findings: List[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        sample = _format_issue_sample(item)
        if not sample:
            continue
        findings.append(sample)
        if len(findings) >= limit:
            break
    return findings


def _fetch_sample_payload(request: CodacyRequest) -> dict:
    return _request_json(request=replace(request, limit=20, method="POST", data={}))
