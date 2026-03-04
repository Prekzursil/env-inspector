from __future__ import absolute_import

from env_inspector_core.models import EnvRecord
from env_inspector_gui.secret_policy import build_search_value, resolve_copy_payload, resolve_load_value


def _secret_record() -> EnvRecord:
    return EnvRecord(
        source_type="dotenv",
        source_id="dotenv:/workspace/.env",
        source_path="/workspace/.env",
        context="windows",
        name="API_TOKEN",
        value="supersecretvalue",
        is_secret=True,
        is_persistent=False,
        is_mutable=True,
        precedence_rank=50,
        writable=True,
        requires_privilege=False,
    )


def test_search_value_uses_masked_representation_when_hidden():
    rec = _secret_record()
    hidden = build_search_value(rec, show_secrets=False)
    shown = build_search_value(rec, show_secrets=True)

    if not ("supersecretvalue" not in hidden):
        raise AssertionError()

    if not ("supersecretvalue" in shown):
        raise AssertionError()



def test_copy_payload_confirms_raw_secret_or_falls_back_to_masked():
    rec = _secret_record()

    masked, masked_raw = resolve_copy_payload(rec, show_secrets=False, confirm_raw=lambda: False, as_pair=False)
    raw, raw_used = resolve_copy_payload(rec, show_secrets=False, confirm_raw=lambda: True, as_pair=False)

    if not (masked_raw is False):
        raise AssertionError()

    if not ("supersecretvalue" not in masked):
        raise AssertionError()

    if not (raw_used is True):
        raise AssertionError()

    if not (raw == "supersecretvalue"):
        raise AssertionError()



def test_load_value_blocks_hidden_secret_without_confirmation():
    rec = _secret_record()

    blocked, blocked_raw = resolve_load_value(rec, show_secrets=False, confirm_raw=lambda: False)
    allowed, allowed_raw = resolve_load_value(rec, show_secrets=False, confirm_raw=lambda: True)

    if not (blocked is None):
        raise AssertionError()

    if not (blocked_raw is False):
        raise AssertionError()

    if not (allowed == "supersecretvalue"):
        raise AssertionError()

    if not (allowed_raw is True):
        raise AssertionError()

