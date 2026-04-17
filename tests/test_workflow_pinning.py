"""Tests for workflow action pinning requirements."""

from __future__ import absolute_import, division
import re
from pathlib import Path

from tests.assertions import ensure


def test_release_workflow_pins_third_party_actions_to_shas():
    """Require third-party workflow actions to be pinned to commit SHAs."""
    workflow = Path(".github/workflows/env-inspector-exe-release.yml")
    lines = workflow.read_text(encoding="utf-8").splitlines()
    uses_values = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("uses: "):
            uses_values.append(stripped.split("uses: ", 1)[1].strip())

    ensure(
        bool(uses_values),
        "Expected at least one uses: entry in release workflow.",
    )

    sha_pin = re.compile(r"^[^@]+@[\da-f]{40}(?:\s+#\s+v\d[\w.-]*)?$")
    unpinned = [
        value
        for value in uses_values
        if value and not value.startswith("./") and not sha_pin.match(value)
    ]
    ensure(not unpinned, f"Unpinned action refs found: {unpinned}")
