"""Coverage tests for env_inspector_gui.path_actions — missing lines 10, 21-24, 37-38, 48."""

from __future__ import absolute_import, division

from pathlib import Path

from env_inspector_gui.path_actions import is_openable_local_path, open_source_path

from tests.assertions import ensure


def test_is_openable_empty_string():
    """Line 10: empty string returns False."""
    ensure(is_openable_local_path("") is False)


def test_is_openable_pseudo_path_with_multiple_colons():
    """Lines 21-24: pseudo form distro:/path with 2+ colons."""
    ensure(is_openable_local_path("distro:extra:/some/path") is False)


def test_is_openable_windows_drive_path_not_pseudo():
    """Line 21: Windows drive letter (C:) should NOT be treated as pseudo form."""
    # C:\\path has exactly one colon at position 1, so it falls through
    # This won't exist on Linux, but it tests the branch
    ensure(is_openable_local_path("C:\\nonexistent\\file") is False)


def test_is_openable_lowered_prefixes():
    """Line 17: lowered prefix checks."""
    ensure(is_openable_local_path("Windows:something") is False)
    ensure(is_openable_local_path("PowerShell:something") is False)


def test_open_source_path_opener_returns_false(tmp_path: Path):
    """Line 48: opener returns False, raises RuntimeError."""
    local_file = tmp_path / "test.env"
    local_file.write_text("A=1\n", encoding="utf-8")

    ok, err = open_source_path(str(local_file), open_uri=lambda _uri: False)
    ensure(ok is False)
    ensure(err is not None)
    ensure("Failed" in err)


def test_open_source_path_opener_raises_oserror(tmp_path: Path):
    """Lines 37-38: opener raises OSError."""
    local_file = tmp_path / "test.env"
    local_file.write_text("A=1\n", encoding="utf-8")

    def bad_opener(uri: str) -> bool:
        raise OSError("disk error")

    ok, err = open_source_path(str(local_file), open_uri=bad_opener)
    ensure(ok is False)
    ensure("disk error" in (err or ""))
