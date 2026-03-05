from __future__ import annotations, absolute_import, division

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class EnvRecord:
    source_type: str
    source_id: str
    source_path: str
    context: str
    name: str
    value: str
    is_secret: bool
    is_persistent: bool
    is_mutable: bool
    precedence_rank: int
    writable: bool
    requires_privilege: bool
    last_error: str | None = None

    def to_dict(self, include_value: bool = True) -> dict[str, Any]:
        payload = asdict(self)
        if not include_value:
            payload["value"] = ""
        return payload


@dataclass
class OperationResult:
    operation_id: str
    target: str
    action: str
    success: bool
    backup_path: str | None
    diff_preview: str
    error_message: str | None
    value_masked: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
