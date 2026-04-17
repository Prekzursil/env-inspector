"""Assertions module."""


def ensure(condition: bool, message: str | None = None) -> None:
    """Ensure."""
    if not condition:
        raise AssertionError(message or "Expected condition to be true.")
