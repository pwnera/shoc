"""The openspace: typed messages, real citations, budgets (AGT-1, RFC 0003, RFC 0010)."""

from __future__ import annotations

import pytest

from shoc.agents.openspace import (
    Budget,
    Message,
    Spend,
    post,
    transcript,
    validate_citations,
)
from shoc.capabilities.registry import call
from shoc.cases import engine
from shoc.db.pool import execute, fetch_one
from shoc.errors import NotFound, ValidationError

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row
    return row["case_uid"]


@pytest.fixture
def real_uids(ctx, config, case):
    row = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, case),
    )
    assert row and row["event_uids"]
    return list(row["event_uids"])[:3]


def test_a_message_is_stored_with_its_verified_citations(ctx, store, config, case, real_uids):
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="Sentinel",
            kind="observation",
            body="A key was used from a new address",
            citations=real_uids,
        ),
    )
    messages = transcript(ctx.db, config.tenant_id, case)
    assert len(messages) == 1
    assert messages[0]["cited_event_uids"] == real_uids


def test_invented_event_ids_are_dropped(ctx, store, config, case, real_uids):
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="Investigator",
            kind="hypothesis",
            body="Stolen key",
            citations=[*real_uids, "ct-this-event-never-existed"],
        ),
    )
    stored = transcript(ctx.db, config.tenant_id, case)[0]["cited_event_uids"]
    assert "ct-this-event-never-existed" not in stored
    assert stored == real_uids


def test_a_claim_with_no_surviving_citation_is_refused(ctx, store, config, case):
    with pytest.raises(ValidationError, match="must cite at least one event"):
        post(
            ctx.db,
            store,
            config.tenant_id,
            case,
            Message(
                agent="Investigator",
                kind="hypothesis",
                body="Definitely malicious",
                citations=["ct-invented"],
            ),
        )


def test_a_challenge_needs_no_citation(ctx, store, config, case):
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="Challenger",
            kind="challenge",
            body="Could the CI runner have moved?",
        ),
    )
    assert transcript(ctx.db, config.tenant_id, case)[0]["kind"] == "challenge"


def test_an_unknown_kind_is_refused(ctx, store, config, case):
    with pytest.raises(ValidationError, match="unknown openspace message kind"):
        post(ctx.db, store, config.tenant_id, case, Message(agent="X", kind="gossip", body="psst"))


def test_an_empty_body_is_refused(ctx, store, config, case):
    with pytest.raises(ValidationError, match="needs a body"):
        post(
            ctx.db, store, config.tenant_id, case, Message(agent="X", kind="observation", body="  ")
        )


def test_posting_into_a_missing_case_is_not_found(ctx, store, config, clean):
    with pytest.raises(NotFound):
        post(
            ctx.db,
            store,
            config.tenant_id,
            "CASE-nope",
            Message(agent="X", kind="observation", body="hello"),
        )


def test_a_human_inject_is_recorded_as_such(ctx, store, config, case):
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="human:sam",
            principal="human",
            kind="inject",
            body="No CI migration is planned this quarter",
            round=2,
        ),
    )
    message = transcript(ctx.db, config.tenant_id, case)[0]
    assert message["principal"] == "human" and message["round"] == 2


def test_tokens_and_rounds_are_charged_to_the_case(ctx, store, config, case, real_uids):
    for round_no in (1, 2):
        post(
            ctx.db,
            store,
            config.tenant_id,
            case,
            Message(
                agent="Investigator",
                kind="evidence",
                body=f"round {round_no}",
                citations=real_uids,
                tokens=1_000,
                round=round_no,
            ),
        )
    row = engine.require(ctx.db, config.tenant_id, case)
    assert row["rounds"] == 2 and row["tokens_used"] == 2_000


def test_a_request_must_name_the_agent_it_is_for(ctx, store, config, case):
    with pytest.raises(ValidationError, match="must name the agent it is for"):
        post(
            ctx.db,
            store,
            config.tenant_id,
            case,
            Message(
                agent="Investigator",
                kind="request",
                body="Is 203.0.113.55 ours?",
            ),
        )


def test_an_interruption_is_for_the_openspace_and_needs_no_citation(ctx, store, config, case):
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="CTI",
            kind="interject",
            body="That address is on a feed as of yesterday",
        ),
    )
    message = transcript(ctx.db, config.tenant_id, case)[0]
    assert message["kind"] == "interject" and message["to_agent"] == ""


def test_validate_citations_keeps_only_events_that_exist(ctx, store, config, real_uids):
    assert validate_citations(store, config.tenant_id, [*real_uids, "nope"]) == real_uids
    assert validate_citations(store, config.tenant_id, []) == []


def test_budgets_scale_with_severity():
    assert Budget.for_severity("low").max_rounds < Budget.for_severity("critical").max_rounds
    assert Budget.for_severity("critical").max_tokens > Budget.for_severity("medium").max_tokens


def test_a_spend_reports_which_budget_it_broke():
    budget = Budget(max_rounds=2, max_tokens=1000, max_seconds=60)
    assert Spend(rounds=2).exceeds(budget).startswith("round budget")
    assert Spend(rounds=1, tokens=1000).exceeds(budget).startswith("token budget")
    assert Spend(rounds=1, tokens=10, seconds=61).exceeds(budget).startswith("time budget")
    assert Spend(rounds=1, tokens=10, seconds=1).exceeds(budget) == ""


def test_an_identical_repost_is_counted_not_appended(ctx, store, config, case):
    """A crew that cannot reach its model says the same thing every retry.

    Before this, a case a flaky gateway touched for a day held dozens of
    byte-identical messages, and the transcript grew for as long as the outage
    lasted without saying anything new.
    """
    message = Message(
        agent="IR Commander",
        kind="observation",
        body="The crew stopped without a verdict: the gateway returned no completion.",
        round=1,
    )
    first = post(ctx.db, store, config.tenant_id, case, message)
    for _ in range(4):
        post(ctx.db, store, config.tenant_id, case, message)
    rows = transcript(ctx.db, config.tenant_id, case)
    same = [r for r in rows if r["msg_id"] == first["msg_id"]]
    assert len(same) == 1, "the repeats must collapse onto the first message"
    assert same[0]["repeats"] == 4
    assert same[0]["last_repeat_at"] is not None


def test_a_different_message_still_appends(ctx, store, config, case):
    body = "Sentinel saw five detections."
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(agent="Sentinel", kind="observation", body=body),
    )
    before = len(transcript(ctx.db, config.tenant_id, case))
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(agent="Sentinel", kind="observation", body=body + " And one more."),
    )
    assert len(transcript(ctx.db, config.tenant_id, case)) == before + 1


def test_a_message_that_cost_tokens_is_never_collapsed(ctx, store, config, case):
    """Spend has to stay countable even when a model repeats itself."""
    message = Message(
        agent="Investigator", kind="observation", body="The same conclusion.", tokens=120
    )
    post(ctx.db, store, config.tenant_id, case, message)
    before = len(transcript(ctx.db, config.tenant_id, case))
    post(ctx.db, store, config.tenant_id, case, message)
    assert len(transcript(ctx.db, config.tenant_id, case)) == before + 1


def test_a_long_case_shows_its_latest_messages_and_says_how_many(
    ctx, store, config, case, real_uids
):
    """case.get returned the first 200 messages, so on a case past 200 the
    Discussion and Timeline lost the end, the decision included (AGT-1, API-1).
    """
    execute(
        ctx.db,
        """INSERT INTO shoc.openspace_messages (tenant_id, case_uid, agent, kind, body)
           SELECT %s, %s, 'Sentinel', 'observation', 'note ' || n
           FROM generate_series(1, 250) n""",
        (config.tenant_id, case),
    )
    post(
        ctx.db,
        store,
        config.tenant_id,
        case,
        Message(
            agent="IR Commander",
            kind="decision",
            body="Revoke the key.",
            citations=real_uids,
        ),
    )
    detail = call("case.get", ctx, {"case_uid": case}).data
    assert detail.openspace_total == 251
    assert len(detail.openspace) == 200
    assert detail.openspace[-1]["body"] == "Revoke the key."
    ids = [m["msg_id"] for m in detail.openspace]
    assert ids == sorted(ids), "the newest 200, still oldest first"
