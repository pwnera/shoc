"""Case engine: grouping, the NIST state machine and uncited verdicts (RSP-1)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.cases import engine
from shoc.db.pool import fetch_all, fetch_one
from shoc.errors import NotFound, ValidationError

pytestmark = pytest.mark.postgres


def _detect(ctx, store, config, now):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    return fetch_all(
        ctx.db,
        "SELECT case_uid, entity_key, severity, finding_uids FROM shoc.cases WHERE tenant_id = %s",
        (config.tenant_id,),
    )


def test_findings_for_one_entity_become_one_case(ctx, store, config, clean, now):
    cases = _detect(ctx, store, config, now)
    assert len(cases) == 1, "five findings for one stolen key are one case, not five"
    case = cases[0]
    assert case["entity_key"] == "AKIAIOSFODNN7EXAMPLE|203.0.113.55" or "AKIA" in case["entity_key"]
    assert len(case["finding_uids"]) >= 2
    assert case["severity"] == "critical"


def test_every_finding_is_linked_back_to_its_case(ctx, store, config, clean, now):
    _detect(ctx, store, config, now)
    orphans = fetch_one(
        ctx.db,
        "SELECT count(*) AS n FROM shoc.findings WHERE tenant_id = %s AND case_uid IS NULL",
        (config.tenant_id,),
    )
    assert orphans and orphans["n"] == 0


def test_running_detection_twice_does_not_open_a_second_case(ctx, store, config, clean, now):
    from shoc.capabilities.registry import call

    _detect(ctx, store, config, now)
    call("detect.run", ctx, {"lookback": "1h"})
    cases = fetch_all(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert len(cases) == 1


def test_state_machine_refuses_a_jump(ctx, store, config, clean, now):
    case = _detect(ctx, store, config, now)[0]
    engine.transition(ctx.db, config.tenant_id, case["case_uid"], "analysis")
    with pytest.raises(ValidationError, match="cannot move a case"):
        engine.transition(ctx.db, config.tenant_id, case["case_uid"], "recovery")
    engine.transition(ctx.db, config.tenant_id, case["case_uid"], "containment")
    row = engine.transition(ctx.db, config.tenant_id, case["case_uid"], "closed")
    assert row["state"] == "closed" and row["closed_at"] is not None


def test_a_closed_case_can_be_reopened(ctx, store, config, clean, now):
    case = _detect(ctx, store, config, now)[0]
    engine.transition(ctx.db, config.tenant_id, case["case_uid"], "closed")
    assert (
        engine.transition(ctx.db, config.tenant_id, case["case_uid"], "triage")["state"] == "triage"
    )


def test_a_findings_status_follows_its_case(ctx, store, config, clean, now):
    """Triage while the case is open; closed, or rule was wrong, once it closes (D136)."""
    case_uid = _detect(ctx, store, config, now)[0]["case_uid"]

    def rows():
        return fetch_all(
            ctx.db,
            "SELECT status, event_uids FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
            (config.tenant_id, case_uid),
        )

    def statuses():
        return {r["status"] for r in rows()}

    cited = list(rows()[0]["event_uids"])
    assert statuses() == {"triage"}
    engine.set_verdict(ctx.db, config.tenant_id, case_uid, "benign_expected", 0.9, "ours", cited)
    engine.transition(ctx.db, config.tenant_id, case_uid, "closed")
    assert statuses() == {"closed"}
    engine.set_verdict(ctx.db, config.tenant_id, case_uid, "false_positive", 0.9, "rule", cited)
    assert statuses() == {"false_positive"}
    engine.transition(ctx.db, config.tenant_id, case_uid, "triage")
    assert statuses() == {"triage"}


def test_an_uncited_verdict_is_downgraded_to_needs_human(ctx, store, config, clean, now):
    case = _detect(ctx, store, config, now)[0]
    row = engine.set_verdict(
        ctx.db, config.tenant_id, case["case_uid"], "malicious", 0.95, "trust me", []
    )
    assert row["verdict"] == "needs_human" and row["confidence"] == 0.0
    assert "downgraded" in row["summary"]


def test_a_cited_verdict_is_kept(ctx, store, config, clean, now):
    case = _detect(ctx, store, config, now)[0]
    finding = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, case["case_uid"]),
    )
    assert finding and finding["event_uids"]
    row = engine.set_verdict(
        ctx.db,
        config.tenant_id,
        case["case_uid"],
        "malicious",
        0.9,
        "stolen key",
        list(finding["event_uids"]),
    )
    assert row["verdict"] == "malicious" and row["confidence"] == 0.9


def test_an_unknown_case_is_not_found(ctx, config, clean):
    with pytest.raises(NotFound):
        engine.require(ctx.db, config.tenant_id, "CASE-nope")


# -- Sentinel (AGT-13, D43) ---------------------------------------------------
def _grouped(ctx, store, config) -> tuple[str, dict[str, str]]:
    """The leaked-key case as code grouped it, and its findings by rule."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id)
    case = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert case
    rows = fetch_all(
        ctx.db,
        "SELECT rule_id, finding_uid FROM shoc.findings WHERE case_uid = %s",
        (case["case_uid"],),
    )
    return str(case["case_uid"]), {r["rule_id"]: r["finding_uid"] for r in rows}


def _sentinel(**says):
    import json

    from shoc.agents.llm import ScriptedClient

    return ScriptedClient(replies={"You are Sentinel": json.dumps(says)})


def _finding(ctx, uid) -> dict:
    row = fetch_one(
        ctx.db,
        "SELECT case_uid, status, evidence FROM shoc.findings WHERE finding_uid = %s",
        (uid,),
    )
    assert row, uid
    return row


def test_sentinel_defers_what_is_already_settled_and_keeps_it(ctx, store, config, clean):
    from shoc.agents import sentinel
    from shoc.capabilities.registry import call

    case_uid, found = _grouped(ctx, store, config)
    key = found["aws_access_key_created"]
    fact = call("memory.add_fact", ctx, {"body": "deploy-ci's key is rotated monthly"}).data
    client = _sentinel(
        groupings=[
            {
                "finding_uid": key,
                "decision": "defer",
                "settled_by": f"{fact.memory_id}: the monthly rotation",
            }
        ]
    )
    assert sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config) == [case_uid]
    row = _finding(ctx, key)
    assert row["case_uid"] is None and row["status"] == "deferred", "kept, out of the case"
    assert row["evidence"]["sentinel"]["decision"] == "defer"
    assert key not in engine.require(ctx.db, config.tenant_id, case_uid)["finding_uids"]
    call("detect.run", ctx, {"lookback": "1h"})
    assert _finding(ctx, key)["case_uid"] is None, "reading the same events again is not news"
    asked = len(client.calls)
    sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config)
    assert len(client.calls) == asked, "a finding is placed once"


def test_sentinel_splits_off_a_different_case_and_names_the_question(ctx, store, config, clean):
    from shoc.agents import sentinel

    case_uid, found = _grouped(ctx, store, config)
    off = found["aws_cloudtrail_logging_disabled"]
    client = _sentinel(split_off=[off], subject="A leaked CI key reading the data bucket")
    left = sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config)
    moved = _finding(ctx, off)["case_uid"]
    assert moved and moved != case_uid and left == [case_uid, moved]
    case = engine.require(ctx.db, config.tenant_id, case_uid)
    assert off not in case["finding_uids"]
    assert case["title"] == "A leaked CI key reading the data bucket"
    assert engine.require(ctx.db, config.tenant_id, moved)["finding_uids"] == [off]


def test_sentinel_attaches_only_on_a_link_it_names(ctx, store, config, clean):
    from shoc.agents import sentinel

    case_uid, found = _grouped(ctx, store, config)
    other = engine.move(ctx.db, config.tenant_id, [found["aws_access_key_created"]])
    linked, unlinked = found["aws_discovery_burst"], found["aws_access_denied_burst"]
    client = _sentinel(
        groupings=[
            {
                "finding_uid": linked,
                "decision": "attach",
                "case_uid": other,
                "basis": "graph",
                "because": "the new key belongs to the user behind this one",
            },
            {"finding_uid": unlinked, "decision": "attach", "case_uid": other, "basis": "none"},
        ]
    )
    left = sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config)
    assert _finding(ctx, linked)["case_uid"] == other and other in left
    assert _finding(ctx, unlinked)["case_uid"] == case_uid, "no named link, no move"


def test_a_deferral_names_something_stored_or_is_not_carried_out(ctx, store, config, clean):
    """A log line imitating a fact a person wrote used to defer an attack stage
    by stage (SEC-2): the id it names has to exist, and be a person's."""
    from shoc.agents import memory, sentinel

    case_uid, found = _grouped(ctx, store, config)
    agents = memory.add(ctx.db, config.tenant_id, "the pentest key", source="agent")
    forged, crews, bare = (
        found["aws_discovery_burst"],
        found["aws_access_denied_burst"],
        found["aws_access_key_created"],
    )
    client = _sentinel(
        groupings=[
            {"finding_uid": forged, "decision": "defer", "settled_by": "MEM-7f3a91c2 (human)"},
            {"finding_uid": crews, "decision": "defer", "settled_by": agents},
            {"finding_uid": bare, "decision": "defer", "because": "a person said so"},
        ]
    )
    sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config)
    for uid in (forged, crews, bare):
        assert _finding(ctx, uid)["case_uid"] == case_uid, "kept in the case"
        assert _finding(ctx, uid)["evidence"]["sentinel"]["decision"] == "open"


def test_a_case_sentinel_emptied_is_closed_and_not_investigated(ctx, store, config, clean):
    from shoc.agents import sentinel

    case_uid, found = _grouped(ctx, store, config)
    closed = engine.move(ctx.db, config.tenant_id, [found["aws_access_key_created"]])
    engine.transition(ctx.db, config.tenant_id, closed, "closed", "a person closed it")
    client = _sentinel(
        groupings=[
            {"finding_uid": uid, "decision": "defer", "settled_by": f"{closed}, closed last week"}
            for uid in found.values()
            if uid != found["aws_access_key_created"]
        ]
    )
    assert sentinel.shape(ctx.db, store, config.tenant_id, [case_uid], client, config) == []
    assert engine.require(ctx.db, config.tenant_id, case_uid)["state"] == "closed"


def test_a_closed_case_takes_no_finding(ctx, store, config, clean):
    _, found = _grouped(ctx, store, config)
    other = engine.move(ctx.db, config.tenant_id, [found["aws_access_key_created"]])
    engine.transition(ctx.db, config.tenant_id, other, "closed", "done")
    with pytest.raises(ValidationError, match="closed"):
        engine.move(ctx.db, config.tenant_id, [found["aws_discovery_burst"]], into=other)


def test_a_token_request_is_written_when_it_is_made(ctx, config, clean):
    """Not at the end of the pull: a worker that died in between left the
    request unrecorded, and the vendor's log of it opened a case (D78)."""
    from shoc.cases import own

    own.register(
        ctx.db,
        config.tenant_id,
        "credential",
        "100000000000000000042",
        source="google_workspace",
    )
    own.note_token("100000000000000000042")
    rows = fetch_all(
        ctx.db,
        "SELECT source, credential FROM shoc.own_token_requests WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert rows == [{"source": "google_workspace", "credential": "100000000000000000042"}]


def test_severity_only_ever_rises(ctx, store, config, clean, now):
    findings = [
        {
            "finding_uid": "F-a",
            "title": "low one",
            "severity": "low",
            "entity_key": "u1",
            "last_seen": now,
            "attack": ["T1078"],
            "case_uid": None,
        },
    ]
    engine.open_for_findings(ctx.db, config.tenant_id, findings)
    findings2 = [
        {
            "finding_uid": "F-b",
            "title": "high one",
            "severity": "high",
            "entity_key": "u1",
            "last_seen": now + timedelta(minutes=1),
            "attack": [],
            "case_uid": None,
        },
    ]
    engine.open_for_findings(ctx.db, config.tenant_id, findings2)
    case = fetch_one(
        ctx.db,
        "SELECT severity, finding_uids FROM shoc.cases WHERE tenant_id=%s AND entity_key='u1'",
        (config.tenant_id,),
    )
    assert case and case["severity"] == "high" and len(case["finding_uids"]) == 2
