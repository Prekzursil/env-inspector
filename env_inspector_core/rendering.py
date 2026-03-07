from __future__ import absolute_import, division

import csv
import io
import json
from typing import Any, Dict, List

from .models import OperationResult


def audit_safe_result(result: OperationResult, *, redact: bool) -> OperationResult:
    if not redact:
        return result
    return OperationResult(
        operation_id=result.operation_id,
        target=result.target,
        action=result.action,
        success=result.success,
        backup_path=result.backup_path,
        diff_preview="[secret diff masked]",
        error_message=result.error_message,
        value_masked=result.value_masked,
    )


def export_rows(rows: List[Dict[str, Any]], *, output: str) -> str:
    if output == "json":
        return json.dumps(rows, ensure_ascii=True, indent=2)

    if output == "csv":
        if not rows:
            return ""
        keys = sorted(rows[0].keys())
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()

    lines = [f"{row['context']}\t{row['source_type']}\t{row['name']}\t{row['value']}" for row in rows]
    return "\n".join(lines) + ("\n" if lines else "")
