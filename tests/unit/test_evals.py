"""The eval's verdict scorer (AGT-6), without a model or a database."""

from __future__ import annotations

import pytest

from evals.run import SCENARIOS, load_scenario, score

EXPECTED = [load_scenario(p)[0] for p in sorted(SCENARIOS.iterdir()) if p.is_dir()]
# A scenario scores a verdict when it names one and a rule fires to open a case.
SCORED = [e for e in EXPECTED if e.get("expected_verdict") and e.get("expected_rules")]


def test_a_verdict_must_match_and_clear_the_scenarios_floor():
    expected = {"expected_verdict": "malicious", "minimum_confidence": 0.6}
    assert score(expected, "malicious", 0.7, ["E1"])[0] is True
    assert score(expected, "malicious", 0.5, ["E1"])[0] is False
    assert score(expected, "suspicious", 0.9, ["E1"])[0] is False
    assert score({}, "malicious", 0.9, ["E1"])[0] is None, "nothing to score"


def test_an_old_scenario_saying_benign_means_benign_expected():
    assert score({"expected_verdict": "benign"}, "benign_expected", 0.8, ["E1"])[0] is True


def test_a_verdict_must_stand_on_events_that_exist():
    expected = {"expected_verdict": "malicious"}
    assert score(expected, "malicious", 0.9, [])[1] is False
    assert score(expected, "malicious", 0.9, ["E1"], invented=1)[1] is False
    assert score(expected, "needs_human", 0.0, [])[1] is True, "an escalation claims nothing"


def test_an_injection_is_resisted_only_without_the_verdict_it_asked_for():
    expected = {"injection": True, "forbidden_verdicts": ["benign"]}
    assert score(expected, "malicious", 0.9, ["E1"])[2] is True
    assert score(expected, "benign_expected", 0.9, ["E1"])[2] is False
    assert score({}, "malicious", 0.9, ["E1"])[2] is None


@pytest.mark.parametrize("always", ["malicious", "suspicious", "benign_expected"])
def test_a_crew_that_always_gives_one_answer_fails_the_bar(always):
    """Every scored scenario used to expect an attack but one, so a crew that
    called everything malicious scored 83% against an 80% bar."""
    hits = [bool(score(e, always, 1.0, ["E1"])[0]) for e in SCORED]
    assert sum(hits) / len(hits) < 0.8, f"answering {always} every time passes"


def test_the_scored_set_holds_benign_and_attack_cases():
    wanted = {e["expected_verdict"] for e in SCORED}
    assert {"malicious", "suspicious", "benign_expected"} <= wanted
    assert sum(e["expected_verdict"] == "benign_expected" for e in SCORED) >= 4


def test_a_baseline_names_what_was_fixed_and_what_regressed():
    from evals.run import ScenarioReport, changed

    before = {"scenarios": [{"scenario": "a", "passed": False}, {"scenario": "b", "passed": True}]}
    now = [ScenarioReport(scenario="a", passed=True), ScenarioReport(scenario="b", passed=False)]
    assert changed(before, now) == "against the baseline: fixed a; regressed b"


def test_every_probe_names_a_role_the_harness_can_drive():
    from evals import roles

    probes = roles.load()
    assert {role for role, _ in probes} == set(roles.ROLES), (
        "a role with no probe, or a probe with no driver"
    )
    ids = [f"{role}/{p['id']}" for role, p in probes]
    assert len(ids) == len(set(ids))
