from __future__ import absolute_import, division

from typing import Any, Dict, Tuple


def _raise_mixed_request_usage() -> None:
    raise TypeError("Pass either a request object or legacy arguments, not both.")


def _extract_request_object(
    *,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    required_attributes: Tuple[str, ...],
) -> Any | None:
    if "request" in kwargs:
        request = kwargs.pop("request")
        if kwargs or args:
            _raise_mixed_request_usage()
        return request

    if len(args) != 1 or kwargs:
        return None

    request = args[0]
    if all(hasattr(request, attribute) for attribute in required_attributes):
        return request
    return None


def _target_operation_payload(request: Any) -> Dict[str, Any]:
    return {
        "target": request.target,
        "key": request.key,
        "value": request.value,
        "action": request.action,
        "scope_roots": list(request.scope_roots),
    }


def _target_operation_batch_payload(request: Any) -> Dict[str, Any]:
    return {
        "action": request.action,
        "key": request.key,
        "value": request.value,
        "targets": list(request.targets),
        "scope_roots": None if request.scope_roots is None else list(request.scope_roots),
    }


def _coerce_string(value: Any) -> str:
    return str(value)


def _coerce_optional_string(value: Any) -> str | None:
    return None if value is None else _coerce_string(value)


def _require_values(message: str, **values: Any) -> None:
    if any(value is None for value in values.values()):
        raise TypeError(message)


def _resolve_operation_inputs(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    field_names: Tuple[str, ...],
) -> Tuple[Any, ...]:
    if args and isinstance(args[0], str):
        return tuple(
            args[index] if len(args) > index else kwargs.pop(name, None)
            for index, name in enumerate(field_names)
        )
    return tuple(kwargs.pop(name, None) for name in field_names)


def normalize_target_operation_request(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    request = _extract_request_object(
        args=args,
        kwargs=kwargs,
        required_attributes=("target", "key", "value", "action", "scope_roots"),
    )
    if request is not None:
        return _target_operation_payload(request)
    target, key, value, action, scope_roots = _resolve_operation_inputs(
        args,
        kwargs,
        ("target", "key", "value", "action", "scope_roots"),
    )

    if kwargs:
        raise TypeError("Unexpected keyword arguments for target operation request.")
    _require_values("Target, key, and action are required.", target=target, key=key, action=action)

    return {
        "target": _coerce_string(target),
        "key": _coerce_string(key),
        "value": _coerce_optional_string(value),
        "action": _coerce_string(action),
        "scope_roots": list(scope_roots or []),
    }

def normalize_target_operation_batch(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    request = _extract_request_object(
        args=args,
        kwargs=kwargs,
        required_attributes=("action", "key", "value", "targets", "scope_roots"),
    )
    if request is not None:
        return _target_operation_batch_payload(request)
    action, key, value, targets, scope_roots = _resolve_operation_inputs(
        args,
        kwargs,
        ("action", "key", "value", "targets", "scope_roots"),
    )

    if kwargs:
        raise TypeError("Unexpected keyword arguments for target operation batch.")
    _require_values("Action, key, and targets are required.", action=action, key=key, targets=targets)

    return {
        "action": _coerce_string(action),
        "key": _coerce_string(key),
        "value": _coerce_optional_string(value),
        "targets": list(targets),
        "scope_roots": None if scope_roots is None else list(scope_roots),
    }
