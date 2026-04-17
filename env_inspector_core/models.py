"""Models module."""

from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class EnvRecord:
    """Environment variable record from any source."""

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
        """To dict."""
        payload = asdict(self)
        if not include_value:
            payload["value"] = ""
        return payload


@dataclass
class OperationResult:
    """Result of a set, remove, or restore operation."""

    operation_id: str
    target: str
    action: str
    success: bool
    backup_path: str | None
    diff_preview: str
    error_message: str | None
    value_masked: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """To dict."""
        return asdict(self)
