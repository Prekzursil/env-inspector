from __future__ import absolute_import, annotations, division


def ensure(condition: bool, message: str | None = None) -> None:
    if not condition:
        raise AssertionError(message or "Expected condition to be true.")
