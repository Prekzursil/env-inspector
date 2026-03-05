from __future__ import annotations, absolute_import, division

from collections.abc import Callable

from env_inspector_core.models import EnvRecord
from env_inspector_core.secrets import mask_value


def build_visible_value(record: EnvRecord, *, show_secrets: bool) -> str:
    if show_secrets or not record.is_secret:
        return record.value
    return mask_value(record.value)


def build_search_value(record: EnvRecord, *, show_secrets: bool) -> str:
    value = build_visible_value(record, show_secrets=show_secrets)
    return " ".join(
        [
            record.context,
            record.source_type,
            record.name,
            value,
            record.source_path,
        ]
    ).lower()


def resolve_copy_payload(
    record: EnvRecord,
    *,
    show_secrets: bool,
    confirm_raw: Callable[[], bool],
    as_pair: bool,
) -> tuple[str, bool]:
    use_raw = show_secrets or not record.is_secret
    if record.is_secret and not show_secrets:
        use_raw = confirm_raw()

    value = record.value if use_raw else mask_value(record.value)
    payload = f"{record.name}={value}" if as_pair else value
    return payload, use_raw


def resolve_load_value(
    record: EnvRecord,
    *,
    show_secrets: bool,
    confirm_raw: Callable[[], bool],
) -> tuple[str | None, bool]:
    if show_secrets or not record.is_secret:
        return record.value, True

    if confirm_raw():
        return record.value, True

    return None, False
