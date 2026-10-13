"""The rule the Detection Engineer is shown as an example is the one shoc ships (DET-8)."""

from __future__ import annotations

from pathlib import Path

from shoc.agents.detection_engineer import EXAMPLE_RULE
from shoc.detect import rules

SHIPPED = Path(__file__).parents[2] / "content/rules" / f"{EXAMPLE_RULE['id']}.yaml"


def test_the_example_rule_is_calibrated_as_the_shipped_one():
    """The model copies the example, so a stale severity is inherited by every new rule."""
    shipped = rules.load_file(SHIPPED)
    assert EXAMPLE_RULE["severity"] == shipped.severity
    assert EXAMPLE_RULE["confidence"] == shipped.confidence
