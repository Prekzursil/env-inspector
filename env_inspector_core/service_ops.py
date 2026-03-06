import difflib
from typing import Tuple, Type

from .models import OperationResult
from .secrets import mask_value


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


def operation_result(
    *,
    operation_id: str,
    target: str,
    action: str,
    success: bool,
    backup_path: str | None,
    preview_only: bool,
    diff_preview: str,
    error_message: str | None,
    value_masked: str | None,
) -> OperationResult:
    return make_operation_result(
        operation_id=operation_id,
        target=target,
        action=action,
        success=success,
        backup_path=(None if preview_only and success else backup_path),
        diff_preview=diff_preview,
        error_message=error_message,
        value_masked=value_masked,
    )


def operation_error_types() -> Tuple[Type[BaseException], ...]:
    return (
        RuntimeError,
        ValueError,
        TypeError,
        OSError,
        PermissionError,
    )
