"""What keeps the replayed scenarios honest: no company's logs in the tree, and
every replay in the suite lands in the backend under test."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from evals.capture import capture
from evals.run import SCENARIOS
from shoc.errors import ValidationError
from tests.support import ROOT

MARKER = "# Captured from a real case"
EXPECTED = sorted(SCENARIOS.glob("*/expected.yaml"))


@pytest.mark.parametrize("expected", EXPECTED, ids=lambda p: p.parent.name)
def test_no_scenario_is_a_capture_nobody_scrubbed(expected: Path):
    assert MARKER not in expected.read_text(), (
        f"{expected.parent.name} is a company's own logs; replace every value first"
    )


@pytest.mark.parametrize("out", [SCENARIOS, ROOT / "tests" / "fixtures", ROOT])
def test_a_capture_is_never_written_into_the_repository(out: Path):
    with pytest.raises(ValidationError, match="elsewhere"):
        capture(None, "CASE-1", out)


def _unstored(path: Path) -> list[str]:
    """`replay` and `malicious_case` calls that leave the store out."""
    out = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in ("replay", "malicious_case"):
            continue
        stored = any(k.arg == "store" for k in node.keywords)
        if not stored and not (name == "malicious_case" and len(node.args) >= 4):
            out.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return out


def test_every_replay_in_the_suite_goes_to_the_store_under_test():
    """Without it, replay opens the backend SHOC_BACKEND names (STO-1)."""
    missing = [hit for p in sorted((ROOT / "tests").rglob("*.py")) for hit in _unstored(p)]
    assert not missing, missing
