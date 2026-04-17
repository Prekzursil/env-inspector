"""Test qlty config module."""

from pathlib import Path

import tomllib

from tests.assertions import ensure


def test_qlty_config_enables_blocking_smells() -> None:
    """Test qlty config enables blocking smells."""
    config_path = Path(".qlty/qlty.toml")
    ensure(config_path.exists())

    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))

    ensure(payload["config_version"] == "0")
    ensure(payload["smells"]["mode"] == "block")
    ensure(any(source.get("default") for source in payload.get("source", [])))
