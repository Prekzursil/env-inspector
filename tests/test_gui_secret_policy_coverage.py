"""Coverage tests for env_inspector_gui.secret_policy — missing line 58."""

from __future__ import absolute_import, division

from env_inspector_core.models import EnvRecord
from env_inspector_gui.secret_policy import (
    build_visible_value,
    is_record_secret,
    resolve_load_value,
)

from tests.assertions import ensure


def _non_secret_record() -> EnvRecord:
    return EnvRecord(
        source_type="dotenv",
        source_id="dotenv:/workspace/.env",
        source_path="/workspace/.env",
        context="windows",
        name="PUBLIC",
        value="hello",
        is_secret=False,
        is_persistent=False,
        is_mutable=True,
        precedence_rank=50,
        writable=True,
        requires_privilege=False,
    )


def test_is_record_secret_false_for_non_secret():
    rec = _non_secret_record()
    ensure(is_record_secret(rec) is False)


def test_build_visible_value_non_secret_returns_value():
    rec = _non_secret_record()
    ensure(build_visible_value(rec, show_secrets=False) == "hello")


def test_resolve_load_value_non_secret_returns_value_directly():
    """Line 58: non-secret with show_secrets=False should return value directly."""
    rec = _non_secret_record()
    loaded, raw = resolve_load_value(rec, show_secrets=False, confirm_raw=lambda: False)
    ensure(loaded == "hello")
    ensure(raw is True)
