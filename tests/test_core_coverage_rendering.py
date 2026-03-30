"""Coverage tests for rendering.py — CSV, table, and JSON export paths."""

from __future__ import absolute_import, division

from env_inspector_core.rendering import export_rows


def test_export_rows_json_output() -> None:
    """export_rows returns valid JSON for output='json'."""
    rows = [{"context": "linux", "source_type": "dotenv", "name": "A", "value": "1"}]
    result = export_rows(rows, output="json")
    assert '"A"' in result
    assert '"1"' in result


def test_export_rows_csv_output() -> None:
    """export_rows returns CSV with header and data for output='csv'."""
    rows = [{"context": "linux", "source_type": "dotenv", "name": "A", "value": "1"}]
    result = export_rows(rows, output="csv")
    assert "context" in result
    assert "linux" in result


def test_export_rows_csv_empty() -> None:
    """export_rows returns empty string for CSV with no rows (line 32)."""
    result = export_rows([], output="csv")
    assert result == ""


def test_export_rows_table_output() -> None:
    """export_rows returns tab-separated table for output='table' (lines 40-41)."""
    rows = [{"context": "linux", "source_type": "dotenv", "name": "A", "value": "1"}]
    result = export_rows(rows, output="table")
    assert "linux\tdotenv\tA\t1" in result
    assert result.endswith("\n")


def test_export_rows_table_empty() -> None:
    """export_rows returns empty-ish string for table with no rows."""
    result = export_rows([], output="table")
    assert result == ""
