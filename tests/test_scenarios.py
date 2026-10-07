"""The replayed scenarios: detection quality, noise and the v0.1 exit criterion."""

from __future__ import annotations

import pytest

from evals.run import SCENARIOS, load_scenario, replay, run_all

pytestmark = pytest.mark.postgres

NAMES = sorted(p.name for p in SCENARIOS.iterdir() if p.is_dir())


def test_the_release_ships_scenarios_for_every_source():
    sources = {load_scenario(SCENARIOS / n)[0]["source"] for n in NAMES}
    assert {"aws_cloudtrail", "okta", "github", "entra", "google_workspace", "m365"} <= sources
    assert len(NAMES) >= 9


def test_the_eval_set_includes_quiet_days_as_well_as_attacks():
    benign = [n for n in NAMES if not load_scenario(SCENARIOS / n)[0]["expected_rules"]]
    assert len(benign) >= 2, "recall means nothing without something to measure noise against"


@pytest.mark.parametrize("name", NAMES)
def test_scenario_is_detected_as_expected(name, config, conn, store, clean):
    report = replay(SCENARIOS / name, tenant_id=config.tenant_id)
    assert report.missing == [], f"{name}: rules that should have fired did not"
    assert report.unexpected == [], f"{name}: unrelated rules fired"
    assert report.uncited_findings == [], "every finding must cite the events behind it"


@pytest.mark.parametrize("name", ["benign_ci_day", "benign_admin_day"])
def test_an_ordinary_day_produces_no_findings(name, config, conn, store, clean):
    report = replay(SCENARIOS / name, tenant_id=config.tenant_id)
    assert report.rules_fired == [], f"false positives on a normal day: {report.rules_fired}"
    assert report.cases_opened == 0, "a quiet day must not page anyone"


def test_the_whole_suite_is_green_and_quiet():
    reports, summary = run_all()
    assert summary["passed"] == summary["scenarios"]
    assert summary["mean_recall"] == 1.0
    assert summary["false_positives"] == 0, [r.false_positives for r in reports]
    assert summary["uncited_findings"] == 0


def test_the_leaked_key_scenario_is_the_v01_exit_criterion(config, conn, store, clean):
    report = replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id)
    assert report.recall == 1.0
    assert report.cases_opened == 1, "one stolen key is one case, not five pages"


def test_findings_can_be_answered_over_the_ask_capability(config, conn, store, clean, ctx):
    from shoc.capabilities.registry import call

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id)
    answer = call(
        "ask", ctx, {"question": "what happened with AKIAIOSFODNN7EXAMPLE?", "since": "-1h"}
    )
    assert answer.citations, "an answer without citations must never be returned as a verdict"
    assert not answer.data.needs_human
    assert any(f["rule_id"] == "aws_s3_mass_object_read" for f in answer.data.findings)

    found = call("search", ctx, {"question": "AKIAIOSFODNN7EXAMPLE", "since": "-1h"})
    assert found.data.intent == "search", "search never hands the question to a model"
    assert any(f["rule_id"] == "aws_s3_mass_object_read" for f in found.data.findings)


def test_mcp_clients_see_the_findings_but_get_no_write_tools(config, conn, store, clean, ctx):
    import json

    from shoc.api.mcp import EXTERNAL_AGENT, invoke, tool_definitions

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id)
    names = {t["name"] for t in tool_definitions(EXTERNAL_AGENT)}
    assert {"finding_list", "events_query", "ask", "case_list"} <= names
    assert "source_configure" not in names
    assert "case_set_state" not in names
    payload = json.loads(invoke("finding_list", {"since": "-1h"}, config, EXTERNAL_AGENT))
    assert payload["data"]["count"] >= 5
    assert payload["citations"]


def test_the_harness_scores_what_the_detection_engineer_merges(config, conn, store, clean):
    """D77: the closure's item is worked, the narrowing passes its gate, the
    routine rotation goes quiet and the same role from elsewhere still fires."""
    report = replay(SCENARIOS / "backup_tool_false_positive", tenant_id=config.tenant_id)
    assert report.closure == []


def test_a_merge_the_gate_refuses_fails_the_scenario(config, conn, store, clean, monkeypatch):
    import evals.run as harness

    expected, events = load_scenario(SCENARIOS / "backup_tool_false_positive")
    # An exclusion on the role alone, with no address, is one the gate refuses.
    expected["de"]["merge"]["exclude"] = [
        {"actor.user.uid": "arn:aws:iam::123456789012:role/backup"}
    ]
    monkeypatch.setattr(harness, "load_scenario", lambda directory: (expected, events))
    report = replay(SCENARIOS / "backup_tool_false_positive", tenant_id=config.tenant_id)
    assert any("expected merged=True" in c for c in report.closure)
    assert any("bk-after-routine" in c for c in report.closure), "the routine rotation still fires"
