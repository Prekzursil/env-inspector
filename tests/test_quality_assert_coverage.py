from __future__ import annotations, absolute_import, division

from pathlib import Path

import pytest

from scripts.quality import assert_coverage_100 as coverage_mod
from scripts import security_helpers as sec


def test_parse_named_path_accepts_workspace_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    coverage_file = tmp_path / "coverage.xml"
    coverage_file.write_text("<coverage lines-valid=\"1\" lines-covered=\"1\" />\n", encoding="utf-8")

    name, path = coverage_mod.parse_named_path("python=coverage.xml")

    assert name == "python"
    assert path == coverage_file.resolve(strict=False)


def test_parse_named_path_rejects_missing_format():
    with pytest.raises(ValueError, match="Expected format"):
        coverage_mod.parse_named_path("python")


def test_parse_named_path_rejects_empty_name_format(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    coverage_file = tmp_path / "coverage.xml"
    coverage_file.write_text("<coverage lines-valid=\"1\" lines-covered=\"1\" />\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Expected format"):
        coverage_mod.parse_named_path("=coverage.xml")


def test_parse_named_path_rejects_workspace_escape(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "outside-coverage.xml"
    outside.write_text("<coverage lines-valid=\"1\" lines-covered=\"1\" />\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes workspace root"):
        coverage_mod.parse_named_path(f"python={outside}")


def test_parse_named_path_rejects_missing_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="Input file does not exist"):
        coverage_mod.parse_named_path("python=missing.xml")


def test_safe_input_file_path_in_workspace_allows_relative_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data.txt"
    data.write_text("ok\n", encoding="utf-8")

    resolved = sec.safe_input_file_path_in_workspace("data.txt")

    assert resolved == data.resolve(strict=False)


def test_safe_input_file_path_in_workspace_rejects_escape(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "leak.txt"
    outside.write_text("nope\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes workspace root"):
        sec.safe_input_file_path_in_workspace(str(outside))


