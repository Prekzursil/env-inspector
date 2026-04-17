"""Test gui path actions module."""

from pathlib import Path
from typing import List

from env_inspector_gui.path_actions import is_openable_local_path, open_source_path
from tests.assertions import ensure


def test_is_openable_local_path_handles_real_and_pseudo_paths(tmp_path: Path):
    """Test is openable local path handles real and pseudo paths."""
    local_file = tmp_path / ".env"
    local_file.write_text("A=1\n", encoding="utf-8")

    ensure(is_openable_local_path(str(local_file)) is True)
    ensure(is_openable_local_path("wsl:Ubuntu:/etc/environment") is False)
    ensure(is_openable_local_path("registry:HKCU\\Environment") is False)


def test_open_source_path_uses_resolved_file_uri(tmp_path: Path):
    """Test open source path uses resolved file uri."""
    local_file = tmp_path / "a.env"
    local_file.write_text("A=1\n", encoding="utf-8")

    calls: List[str] = []

    def fake_opener(uri: str) -> bool:
        """Fake opener."""
        calls.append(uri)
        return True

    ok, err = open_source_path(str(local_file), open_uri=fake_opener)

    ensure(ok is True)
    ensure(err is None)
    ensure(calls == [local_file.resolve().as_uri()])


def test_open_source_path_rejects_non_local_path():
    """Test open source path rejects non local path."""
    ok, err = open_source_path(
        "wsl:Ubuntu:/etc/environment", open_uri=lambda _uri: True
    )
    ensure(ok is False)
    ensure("Cannot open" in (err or ""))
