from __future__ import absolute_import, division

import re
from pathlib import Path

def _expect(condition, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)



def test_release_workflow_pins_third_party_actions_to_shas():
    workflow = Path(".github/workflows/env-inspector-exe-release.yml")
    lines = workflow.read_text(encoding="utf-8").splitlines()
    uses_values = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("uses: "):
            uses_values.append(stripped.split("uses: ", 1)[1].strip())

    _expect(uses_values, "Expected at least one uses: entry in release workflow.")


    sha_pin = re.compile(r"^[^@]+@[0-9a-f]{40}(?:\s+#\s+v\d[\w.\-]*)?$")
    unpinned = [value for value in uses_values if value and not value.startswith("./") and not sha_pin.match(value)]
    _expect(not unpinned, f"Unpinned action refs found: {unpinned}")


def test_expect_helper_raises_on_false():
    raised = False
    try:
        _expect(False, "expected")
    except AssertionError:
        raised = True
    _expect(raised is True)

