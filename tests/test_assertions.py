from __future__ import absolute_import, annotations, division

import pytest

from tests.assertions import ensure


def test_ensure_allows_true_conditions() -> None:
    ensure(True)


def test_ensure_raises_for_false_conditions() -> None:
    with pytest.raises(AssertionError, match="custom message"):
        ensure(False, "custom message")
