"""Coverage tests for service_ops_request.py — request normalization edge cases."""

from __future__ import absolute_import, division
from tests.assertions import ensure

import types

import pytest

from env_inspector_core.service_ops_request import (
    _raise_mixed_request_usage,
    _extract_request_object,
    _target_operation_batch_payload,
    _coerce_string,
    _coerce_optional_string,
    _require_values,
    normalize_target_operation_request,
    normalize_target_operation_batch,
)


# Line 7: _raise_mixed_request_usage
def test_raise_mixed_request_usage() -> None:
    """_raise_mixed_request_usage raises TypeError."""
    with pytest.raises(
        TypeError, match="Pass either a request object or legacy arguments"
    ):
        _raise_mixed_request_usage()


# Line 19: mixed usage — request kwarg with extra kwargs
def test_extract_request_object_raises_on_mixed_kwargs() -> None:
    """_extract_request_object raises when request kwarg is mixed with other kwargs."""
    with pytest.raises(
        TypeError, match="Pass either a request object or legacy arguments"
    ):
        _extract_request_object(
            args=(),
            kwargs={"request": object(), "extra": "bad"},
            required_attributes=("target",),
        )


# Line 19: mixed usage — request kwarg with extra positional args
def test_extract_request_object_raises_on_mixed_args() -> None:
    """_extract_request_object raises when request kwarg is mixed with positional args."""
    with pytest.raises(
        TypeError, match="Pass either a request object or legacy arguments"
    ):
        _extract_request_object(
            args=("extra",),
            kwargs={"request": object()},
            required_attributes=("target",),
        )


# Line 28: single arg without required attributes returns None
def test_extract_request_object_returns_none_for_non_request() -> None:
    """_extract_request_object returns None when single arg lacks required attributes."""
    result = _extract_request_object(
        args=("just_a_string",),
        kwargs={},
        required_attributes=("target", "key"),
    )
    ensure(result is None)


# Line 42: _target_operation_batch_payload
def test_target_operation_batch_payload() -> None:
    """_target_operation_batch_payload extracts correct fields."""
    req = types.SimpleNamespace(
        action="set",
        key="A",
        value="1",
        targets=["t1"],
        scope_roots=None,
    )
    result = _target_operation_batch_payload(req)
    ensure(result["action"] == "set")
    ensure(result["targets"] == ["t1"])
    ensure(result["scope_roots"] is None)


def test_target_operation_batch_payload_with_scope_roots() -> None:
    """_target_operation_batch_payload converts scope_roots to list."""
    req = types.SimpleNamespace(
        action="set",
        key="A",
        value="1",
        targets=["t1"],
        scope_roots=("/root",),
    )
    result = _target_operation_batch_payload(req)
    ensure(result["scope_roots"] == ["/root"])


# Line 61: _coerce_string and _coerce_optional_string
def test_coerce_string_converts_non_string() -> None:
    """_coerce_string converts non-string values."""
    ensure(_coerce_string(42) == "42")


def test_coerce_optional_string_returns_none() -> None:
    """_coerce_optional_string returns None for None input."""
    ensure(_coerce_optional_string(None) is None)


def test_coerce_optional_string_converts_value() -> None:
    """_coerce_optional_string converts non-None values."""
    ensure(_coerce_optional_string(42) == "42")


# Line 92: unexpected kwargs in normalize_target_operation_request
def test_normalize_target_operation_request_unexpected_kwargs() -> None:
    """normalize_target_operation_request raises on unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword arguments"):
        normalize_target_operation_request(
            target="t",
            key="k",
            action="set",
            bogus="bad",
        )


# Line 110: normalize_target_operation_batch with request object
def test_normalize_target_operation_batch_with_request() -> None:
    """normalize_target_operation_batch accepts a request object."""
    req = types.SimpleNamespace(
        action="set",
        key="A",
        value="1",
        targets=["t1"],
        scope_roots=None,
    )
    result = normalize_target_operation_batch(req)
    assert result["action"] == "set"
    ensure(result["key"] == "A")


# Line 118: unexpected kwargs in normalize_target_operation_batch
def test_normalize_target_operation_batch_unexpected_kwargs() -> None:
    """normalize_target_operation_batch raises on unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword arguments"):
        normalize_target_operation_batch(
            action="set",
            key="k",
            targets=["t"],
            bogus="bad",
        )


# _require_values raises on None
def test_require_values_raises_on_none() -> None:
    """_require_values raises TypeError when any value is None."""
    with pytest.raises(TypeError, match="missing"):
        _require_values("missing", target=None, key="k")
