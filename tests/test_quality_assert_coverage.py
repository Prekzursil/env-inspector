"""Test quality assert coverage module."""

from pathlib import Path

import pytest

from scripts import security_helpers as sec
from scripts.quality import _security_imports as security_imports
from scripts.quality import assert_coverage_100 as coverage_mod
from tests.assertions import ensure


def test_parse_named_path_accepts_workspace_file(tmp_path: Path, monkeypatch):
    """Test parse named path accepts workspace file."""
    monkeypatch.chdir(tmp_path)
    coverage_file = tmp_path / "coverage.xml"
    coverage_file.write_text(
        '<coverage lines-valid="1" lines-covered="1" />\n', encoding="utf-8"
    )

    name, path = coverage_mod.parse_named_path("python=coverage.xml")

    ensure(name == "python")
    ensure(path == coverage_file.resolve(strict=False))


def test_parse_named_path_rejects_missing_format():
    """Test parse named path rejects missing format."""
    with pytest.raises(ValueError, match="Expected format"):
        coverage_mod.parse_named_path("python")


def test_parse_named_path_rejects_empty_name_format(tmp_path: Path, monkeypatch):
    """Test parse named path rejects empty name format."""
    monkeypatch.chdir(tmp_path)
    coverage_file = tmp_path / "coverage.xml"
    coverage_file.write_text(
        '<coverage lines-valid="1" lines-covered="1" />\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Expected format"):
        coverage_mod.parse_named_path("=coverage.xml")


def test_parse_named_path_rejects_workspace_escape(tmp_path: Path, monkeypatch):
    """Test parse named path rejects workspace escape."""
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "outside-coverage.xml"
    outside.write_text(
        '<coverage lines-valid="1" lines-covered="1" />\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="escapes workspace root"):
        coverage_mod.parse_named_path(f"python={outside}")


def test_parse_named_path_rejects_missing_file(tmp_path: Path, monkeypatch):
    """Test parse named path rejects missing file."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="Input file does not exist"):
        coverage_mod.parse_named_path("python=missing.xml")


def test_safe_input_file_path_in_workspace_allows_relative_file(
    tmp_path: Path, monkeypatch
):
    """Test safe input file path in workspace allows relative file."""
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data.txt"
    data.write_text("ok\n", encoding="utf-8")

    resolved = sec.safe_input_file_path_in_workspace("data.txt")

    ensure(resolved == data.resolve(strict=False))


def test_safe_input_file_path_in_workspace_rejects_escape(tmp_path: Path, monkeypatch):
    """Test safe input file path in workspace rejects escape."""
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "leak.txt"
    outside.write_text("nope\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes workspace root"):
        sec.safe_input_file_path_in_workspace(str(outside))


def test_normalize_source_path_handles_empty_and_workspace_absolute_paths(
    tmp_path: Path, monkeypatch
):
    """Test normalize source path handles empty and workspace absolute paths."""
    monkeypatch.chdir(tmp_path)
    inside_file = tmp_path / "env_inspector.py"
    inside_file.write_text("print('ok')\n", encoding="utf-8")

    ensure(coverage_mod.normalize_source_path("") == "")
    ensure(coverage_mod.normalize_source_path(str(tmp_path)) == "")
    ensure(coverage_mod.normalize_source_path(str(inside_file)) == "env_inspector.py")


def test_normalize_source_path_handles_empty_normpath_result(monkeypatch):
    """Test normalize source path handles empty normpath result."""
    monkeypatch.setattr(coverage_mod.posixpath, "normpath", lambda _value: "")
    ensure(coverage_mod.normalize_source_path("ignored") == "")


def test_assert_coverage_uses_shared_security_import_helpers():
    """Keep the coverage script aligned with the shared security import surface."""
    ensure(
        coverage_mod.SAFE_INPUT_FILE_PATH_IN_WORKSPACE
        is security_imports.safe_input_file_path_in_workspace
    )
    ensure(
        coverage_mod.SAFE_OUTPUT_PATH_IN_WORKSPACE
        is security_imports.safe_output_path_in_workspace
    )
