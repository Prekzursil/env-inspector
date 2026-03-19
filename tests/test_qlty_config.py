from __future__ import absolute_import, division

from pathlib import Path
import tomllib


def test_qlty_config_enables_blocking_smells() -> None:
    config_path = Path(".qlty/qlty.toml")
    assert config_path.exists()

    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))

    assert payload["config_version"] == "0"
    assert payload["smells"]["mode"] == "block"
    assert any(source.get("default") for source in payload.get("source", []))
