from __future__ import absolute_import, division

from dataclasses import dataclass
import difflib
from typing import Tuple, Type

from .models import OperationResult
from .secrets import mask_value


@dataclass(frozen=True)
class OperationResultInput:
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
    diff = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"{target} (before)",
        tofile=f"{target} (after)",
        lineterm="",
    )
    return "\n".join(diff)


def masked_value(*, secret_operation: bool, value: str | None) -> str | None:
    if not secret_operation or value is None:
        return None
    return mask_value(value)


def make_operation_result(
    *,
    operation_id: str,
    target: str,
    action: str,
    success: bool,
    backup_path: str | None,
    diff_preview: str,
    error_message: str | None,
    value_masked: str | None,
) -> OperationResult:
    return OperationResult(
        operation_id=operation_id,
        target=target,
        action=action,
        success=success,
        backup_path=backup_path,
        diff_preview=diff_preview,
        error_message=error_message,
        value_masked=value_masked,
    )


def operation_result(payload: OperationResultInput) -> OperationResult:
    return make_operation_result(
        operation_id=payload.operation_id,
        target=payload.target,
        action=payload.action,
        success=payload.success,
        backup_path=(None if payload.preview_only and payload.success else payload.backup_path),
        diff_preview=payload.diff_preview,
        error_message=payload.error_message,
        value_masked=payload.value_masked,
    )


def operation_error_types() -> Tuple[Type[BaseException], ...]:
    return (
        RuntimeError,
        ValueError,
        TypeError,
        OSError,
        PermissionError,
    )
