"""The replayed scenarios: detection quality, noise and the v0.1 exit criterion."""

from __future__ import annotations

import os

import pytest

from evals.run import SCENARIOS, load_scenario, replay

pytestmark = pytest.mark.postgres

NAMES = sorted(p.name for p in SCENARIOS.iterdir() if p.is_dir())


def test_the_release_ships_scenarios_for_every_source():
    sources = {load_scenario(SCENARIOS / n)[0]["source"] for n in NAMES}
    assert {"aws_cloudtrail", "okta", "github", "entra", "google_workspace", "m365"} <= sources
    assert len(NAMES) >= 9


def test_the_eval_set_includes_quiet_days_as_well_as_attacks():
    benign = [n for n in NAMES if not load_scenario(SCENARIOS / n)[0]["expected_rules"]]
    assert len(benign) >= 2, "recall means nothing without something to measure noise against"


def test_a_replay_calls_no_model_unless_the_run_asks_for_one(config):
    """A shell with an instance's settings exported must not spend its model credit (AGT-6)."""
    from shoc.config import Config

    if os.environ.get("SHOC_TEST_ALLOW_MODEL") == "1":
        pytest.skip("SHOC_TEST_ALLOW_MODEL=1: this run may call the configured model")
    assert config.llm_provider == "none" and config.dry_run is None
    assert Config.load().llm_provider == "none", "replay builds its own Config"


@pytest.mark.parametrize("name", NAMES)
def test_scenario_is_detected_as_expected(name, config, conn, store, clean):
    report = replay(SCENARIOS / name, tenant_id=config.tenant_id, store=store)
    assert report.missing == [], f"{name}: rules that should have fired did not"
    assert report.unexpected == [], f"{name}: unrelated rules fired"
    assert report.false_positives == [], f"{name}: rules outside expected_rules fired"
    assert report.uncited_findings == [], "every finding must cite the events behind it"


@pytest.mark.parametrize("name", ["benign_ci_day", "benign_admin_day"])
def test_an_ordinary_day_produces_no_findings(name, config, conn, store, clean):
    report = replay(SCENARIOS / name, tenant_id=config.tenant_id, store=store)
    assert report.rules_fired == [], f"false positives on a normal day: {report.rules_fired}"
    assert report.cases_opened == 0, "a quiet day must not page anyone"


def test_a_rule_outside_expected_rules_fails_the_scenario(config, conn, store, clean, monkeypatch):
    """`python -m evals.run` is the one replay of the whole set in CI, so its
    exit code must count noise as a failure."""
    import evals.run as harness

    expected, events = load_scenario(SCENARIOS / "leaked_aws_key")
    noise = expected["expected_rules"][0]
    expected = {**expected, "expected_rules": expected["expected_rules"][1:]}
    monkeypatch.setattr(harness, "load_scenario", lambda directory: (expected, events))
    report = replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    assert report.missing == [] and report.false_positives == [noise]
    assert not report.passed


def test_the_leaked_key_scenario_is_the_v01_exit_criterion(config, conn, store, clean):
    report = replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    assert report.recall == 1.0
    assert report.cases_opened == 1, "one stolen key is one case, not five pages"


def test_findings_can_be_answered_over_the_ask_capability(config, conn, store, clean, ctx):
    from shoc.capabilities.registry import call

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
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

    from shoc.api.mcp import EXTERNAL_AGENT, invoke, tool, tool_definitions

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    names = {t["name"] for t in tool_definitions(EXTERNAL_AGENT)}
    assert {"finding_list", "events_query", "ask", "case_list"} <= names
    assert "source_configure" not in names
    assert "case_set_state" not in names
    payload = json.loads(invoke(tool("finding_list"), {"since": "-1h"}, config, EXTERNAL_AGENT))
    assert payload["data"]["count"] >= 5
    assert payload["citations"]


def test_the_harness_scores_what_the_detection_engineer_merges(config, conn, store, clean):
    """D77: the closure's item is worked, the narrowing passes its gate, the
    routine rotation goes quiet and the same role from elsewhere still fires."""
    report = replay(
        SCENARIOS / "backup_tool_false_positive", tenant_id=config.tenant_id, store=store
    )
    assert report.closure == []


def test_a_merge_the_gate_refuses_fails_the_scenario(config, conn, store, clean, monkeypatch):
    import evals.run as harness

    expected, events = load_scenario(SCENARIOS / "backup_tool_false_positive")
    # An exclusion on the role alone, with no address, is one the gate refuses.
    expected["de"]["merge"]["exclude"] = [
        {"actor.user.uid": "arn:aws:iam::123456789012:role/backup"}
    ]
    monkeypatch.setattr(harness, "load_scenario", lambda directory: (expected, events))
    report = replay(
        SCENARIOS / "backup_tool_false_positive", tenant_id=config.tenant_id, store=store
    )
    assert any("expected merged=True" in c for c in report.closure)
    assert any("bk-after-routine" in c for c in report.closure), "the routine rotation still fires"
