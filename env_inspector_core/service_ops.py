"""Service ops module."""

import difflib
from dataclasses import dataclass
from typing import Tuple, Type

from . import service_ops_request as _service_ops_request
from .models import OperationResult
from .secrets import mask_value

normalize_target_operation_batch = _service_ops_request.normalize_target_operation_batch
normalize_target_operation_request = (
    _service_ops_request.normalize_target_operation_request
)


@dataclass(frozen=True)
class OperationResultInput:
    """Raw inputs for constructing an operation result."""

    operation_id: str
    target: str
    action: str
    success: bool
    backup_path: str | None
    preview_only: bool
    diff_preview: str
    error_message: str | None
    value_masked: str | None


def diff_text(before: str, after: str, target: str) -> str:
    """Diff text."""
    diff = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"{target} (before)",
        tofile=f"{target} (after)",
        lineterm="",
    )
    return "\n".join(diff)


def masked_value(*, secret_operation: bool, value: str | None) -> str | None:
    """Masked value."""
    if not secret_operation or value is None:
        return None
    return mask_value(value)


def make_operation_result(payload: OperationResultInput) -> OperationResult:
    """Make operation result."""
    return OperationResult(
        operation_id=payload.operation_id,
        target=payload.target,
        action=payload.action,
        success=payload.success,
        backup_path=(
            None if payload.preview_only and payload.success else payload.backup_path
        ),
        diff_preview=payload.diff_preview,
        error_message=payload.error_message,
        value_masked=payload.value_masked,
    )


def operation_result(payload: OperationResultInput) -> OperationResult:
    """Operation result."""
    return make_operation_result(payload)


def operation_error_types() -> tuple[type[BaseException], ...]:
    """Operation error types."""
    return (
        RuntimeError,
        ValueError,
        TypeError,
        OSError,
        PermissionError,
    )
