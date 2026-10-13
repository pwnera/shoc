"""The four dispositions and where each one goes (AGT-3, docs/agent-specs.md §2, §6).

Two of these tests are the whole point of the split: a case closed because the
environment is unusual produces an expiring suppression, and a case closed
because the rule is wrong produces a detection defect. They are different
repairs, and nothing routes to both.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from shoc.agents.llm import NoLLM, ScriptedClient
from shoc.agents.loop import run_case
from shoc.cases import engine, routing
from shoc.db.pool import fetch_all, fetch_one

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db,
        "SELECT case_uid, severity, entity_key FROM shoc.cases WHERE tenant_id = %s LIMIT 1",
        (config.tenant_id,),
    )
    assert row, "the scenario must open a case"
    return row


@pytest.fixture
def uids(ctx, config, case):
    row = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, case["case_uid"]),
    )
    assert row and row["event_uids"]
    return list(row["event_uids"])[:3]


def crew(
    uids: list[str], verdict: str, reads: str = "", shown: str = "supported"
) -> ScriptedClient:
    return ScriptedClient(
        replies={
            # First: the independent reads run under the Investigator's prompt.
            "Read this case on your own": json.dumps(
                {"reasoning": "The nightly backup job.", "verdict": reads or verdict}
            ),
            "You check claims": json.dumps({"checks": [{"claim": 0, "support": shown}]}),
            "You are Investigator": json.dumps(
                {
                    "verdict": verdict,
                    "confidence": 0.8,
                    "reasoning": "The key is the nightly backup job, which moved hosts last week.",
                    "claims": [{"says": "The backup job used the key.", "citations": uids}],
                    "severity": "low",
                    "severity_reason": "A known job, on a new host.",
                    "citations": uids,
                    "scope": ["user:ci-runner"],
                    "ready_to_close": True,
                }
            ),
            "You are Challenger": json.dumps(
                {
                    "arguing": "attack",
                    "explanations": ["The backup job moved hosts"],
                    "strongest": "The backup job moved hosts",
                    "grounded_in": "baseline",
                    "concede": True,
                }
            ),
            "You are IR Commander": json.dumps({"proposals": [], "page_human": False}),
        }
    )


# -- the taxonomy -----------------------------------------------------------
def test_the_four_dispositions_and_the_escalation_that_is_not_one():
    assert engine.DISPOSITIONS == ("malicious", "suspicious", "benign_expected", "false_positive")
    assert "needs_human" in engine.VERDICTS and "needs_human" not in engine.DISPOSITIONS


def test_the_pre_split_verdict_still_reads():
    """Old rows, old clients and old evals said `benign`; it means the safer half."""
    assert engine.normalise_verdict("benign") == "benign_expected"
    assert engine.normalise_verdict("malicious") == "malicious"


def test_a_rule_cannot_be_declared_wrong_without_evidence(ctx, config, case):
    """`false_positive` is a claim about the detection, and claims need citations."""
    row = engine.set_verdict(
        ctx.db, config.tenant_id, case["case_uid"], "false_positive", 0.9, "the rule is junk", []
    )
    assert row["verdict"] == "needs_human" and row["confidence"] == 0.0


# -- where each one goes ----------------------------------------------------
def test_expected_activity_suppresses_narrowly_and_with_an_expiry(ctx, store, config, case, uids):
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=crew(uids, "benign_expected"),
        config=config,
    )
    assert report.verdict == "benign_expected"

    live = routing.active_suppressions(ctx.db, config.tenant_id)
    assert live, "expected activity must quieten the thing that fired"
    fired = {
        (r["rule_id"], r["entity_key"])
        for r in fetch_all(
            ctx.db,
            "SELECT rule_id, entity_key FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
            (config.tenant_id, case["case_uid"]),
        )
    }
    for row in live:
        assert row["expires_at"] > datetime.now(UTC), "nothing is suppressed forever"
        assert row["expires_at"] < datetime.now(UTC) + timedelta(days=8), "a week at most (D77)"
        assert (row["rule_id"], row["entity"]) in fired, "a suppression is the exact (rule, entity)"
        assert row["case_uid"] == case["case_uid"], "a suppression names what justified it"

    assert not fetch_all(
        ctx.db,
        "SELECT 1 FROM shoc.detection_backlog WHERE tenant_id = %s AND kind = 'defect'",
        (config.tenant_id,),
    ), "expected activity is not a detection defect"


def test_expected_activity_is_written_down_so_the_next_case_knows(ctx, store, config, case, uids):
    run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=crew(uids, "benign_expected"),
        config=config,
    )
    facts = fetch_all(
        ctx.db,
        "SELECT body, expires_at FROM shoc.memory WHERE tenant_id = %s AND source = 'crew'",
        (config.tenant_id,),
    )
    assert facts and any("backup job" in f["body"] for f in facts)
    assert all(f["expires_at"] is not None for f in facts), "a learnt fact expires"


def test_a_false_positive_becomes_a_detection_defect_not_a_suppression(
    ctx, store, config, case, uids
):
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=crew(uids, "false_positive"),
        config=config,
    )
    assert report.verdict == "false_positive"

    items = fetch_all(
        ctx.db,
        "SELECT * FROM shoc.detection_backlog WHERE tenant_id = %s ORDER BY item_uid",
        (config.tenant_id,),
    )
    assert items, "a wrong rule owes the Detection Engineer a defect"
    assert {i["kind"] for i in items} == {"defect"}
    assert {i["intake"] for i in items} == {"case"}
    assert all(i["case_uid"] == case["case_uid"] for i in items)
    assert not routing.active_suppressions(ctx.db, config.tenant_id), (
        "a broken rule is fixed, never quietly muted"
    )


def test_a_bad_disposition_goes_to_the_commander(ctx, store, config, case, uids):
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=crew(uids, "malicious"),
        config=config,
    )
    assert {e["routed_to"] for e in report.routed} == {"IR Commander"}


def test_no_model_still_routes_the_case_to_a_person(ctx, store, config, case):
    report = run_case(
        ctx.db, store, config.tenant_id, case["case_uid"], client=NoLLM(), config=config
    )
    assert report.verdict == "needs_human"
    assert [e["routed_to"] for e in report.routed] == ["human"]


def test_every_closure_leaves_a_record_of_where_it_went(ctx, store, config, case, uids):
    run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=crew(uids, "benign_expected"),
        config=config,
    )
    rows = fetch_all(
        ctx.db,
        "SELECT disposition FROM shoc.case_routing WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, case["case_uid"]),
    )
    assert rows, "a disposition that routes nowhere is noise triaged forever"
    assert {r["disposition"] for r in rows} == {"benign_expected"}


def test_a_suppression_that_has_run_out_stops_filtering(ctx, config, case):
    routing.route(
        ctx.db, config.tenant_id, case, "benign_expected", summary="the backup job", closer="human"
    )
    ctx.db.execute(
        "UPDATE shoc.suppressions SET expires_at = now() - interval '1 day' WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert routing.expire_suppressions(ctx.db, config.tenant_id) >= 1
    assert routing.active_suppressions(ctx.db, config.tenant_id) == []


# -- a benign close stands on the measured number (D77, RFC 0020) ----------
def test_a_benign_verdict_the_checks_do_not_back_goes_to_a_person(ctx, store, config, case, uids):
    """Both reads land on the attack side and no claim is shown: nothing closes or goes quiet."""
    tenant = config.tenant_id
    report = run_case(
        ctx.db,
        store,
        tenant,
        case["case_uid"],
        client=crew(uids, "benign_expected", reads="malicious", shown="unsupported"),
        config=config,
    )
    assert report.verdict == "needs_human"
    assert [e["routed_to"] for e in report.routed] == ["human"]
    row = engine.require(ctx.db, tenant, case["case_uid"])
    assert row["state"] != "closed" and row["verdict"] == "needs_human"
    assert not fetch_all(ctx.db, "SELECT 1 FROM shoc.suppressions WHERE tenant_id = %s", (tenant,))
    assert not fetch_all(
        ctx.db, "SELECT 1 FROM shoc.memory WHERE tenant_id = %s AND source = 'crew'", (tenant,)
    ), "nothing is learnt from a close that did not happen"


def test_a_crew_close_below_the_floor_quiets_nothing_and_a_persons_does(ctx, config, case):
    low = {**case, "confidence": 0.2}
    routing.route(ctx.db, config.tenant_id, low, "benign_expected", summary="the backup job")
    assert routing.active_suppressions(ctx.db, config.tenant_id) == []
    routing.route(
        ctx.db, config.tenant_id, low, "benign_expected", summary="the backup job", closer="human"
    )
    assert routing.active_suppressions(ctx.db, config.tenant_id), "a person's close is theirs"


def test_a_closure_taken_back_takes_its_note_in_memory_with_it(ctx, store, config, case, uids):
    """And the weekly recheck of a closure is not shown that closure's own note (D77)."""
    from shoc.agents.dossier import build_dossier

    tenant, case_uid = config.tenant_id, case["case_uid"]
    run_case(ctx.db, store, tenant, case_uid, client=crew(uids, "benign_expected"), config=config)
    row = engine.require(ctx.db, tenant, case_uid)
    assert row["state"] == "closed"
    mark = routing.closure_mark(case_uid)
    assert mark in build_dossier(ctx.db, store, tenant, row).text
    assert mark not in build_dossier(ctx.db, store, tenant, row, exclude_case=case_uid).text
    routing.undo_closure(ctx.db, tenant, case_uid, "reopened: a test")
    assert mark not in build_dossier(ctx.db, store, tenant, row).text, "it expired with the close"


def test_the_weekly_recheck_reads_the_least_certain_closure_first(
    ctx, store, config, clean, monkeypatch
):
    from shoc.agents import recheck

    tenant = config.tenant_id
    for uid, confidence in (("CASE-sure", 0.9), ("CASE-unsure", 0.5)):
        ctx.db.execute(
            """INSERT INTO shoc.cases
                   (case_uid, tenant_id, title, state, verdict, confidence, closed_at, closed_by)
               VALUES (%s, %s, 'k', 'closed', 'benign_expected', %s, now(), 'crew')""",
            (uid, tenant, confidence),
        )
    monkeypatch.setattr(recheck, "SAMPLE", 1)
    client = ScriptedClient(
        replies={
            "Read this case on your own": json.dumps(
                {"reasoning": "The backup job.", "verdict": "benign_expected"}
            )
        }
    )
    assert "read 1" in recheck.run(ctx.db, store, tenant, config, client=client)
    assert recheck.agreed(ctx.db, tenant, "CASE-unsure")
    assert not recheck.agreed(ctx.db, tenant, "CASE-sure")
