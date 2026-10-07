"""What happens when nobody is watching (RSP-2, RSP-3, AGT-1, OPS-1).

shoc runs for a company whose only technical person does not open it most days,
so every one of these tests is a version of the same question: does this still
finish if no human ever arrives?

The bug they were written for is worth stating plainly. The IR Commander
proposed `okta.revoke_sessions` at L1 on a real case, and the proposal was
written into the openspace as a line of JSON. No action row was ever created, so
nothing could run it, and the case sat waiting for an approval nobody was coming
to give. Three separate faults: the crew's proposals were not put to the policy,
approved actions had nothing that executed them, and the policy judged the
autonomy of every proposal against a confidence the case did not carry yet.
"""

from __future__ import annotations

import json

import pytest

from shoc.agents.llm import ScriptedClient
from shoc.agents.loop import run_case
from shoc.agents.openspace import Budget, transcript
from shoc.cases import actions as action_store
from shoc.cases import engine, unattended
from shoc.db.pool import execute, fetch_all, fetch_one
from tests.support import audit_seq, audit_trail

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db,
        "SELECT case_uid, severity FROM shoc.cases WHERE tenant_id = %s LIMIT 1",
        (config.tenant_id,),
    )
    assert row, "the scenario must open a case"
    return row


@pytest.fixture
def with_a_crew(config):
    """`config` is session-scoped, so a provider set here must be put back.

    The sweep stands down when no model is configured, so a test of the sweep has
    to say there is one — and leaving that set leaks a real API call into
    whatever file runs next.
    """
    was = config.llm_provider
    config.llm_provider = "openai"
    yield config
    config.llm_provider = was


@pytest.fixture
def uids(ctx, config, case):
    row = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, case["case_uid"]),
    )
    assert row and row["event_uids"]
    return list(row["event_uids"])[:3]


def commander(uids: list[str], action: str, target: str) -> ScriptedClient:
    """A crew that reaches a confident verdict and proposes one named action."""
    return ScriptedClient(
        replies={
            # The independent reads and the claim check behind the measured
            # confidence (RFC 0020); first, because the reads use the
            # Investigator's prompt and the first matching needle answers.
            "Read this case on your own": json.dumps({"verdict": "malicious"}),
            "You check claims": json.dumps({"checks": [{"claim": 0, "support": "supported"}]}),
            "You are Investigator": json.dumps(
                {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reasoning": "The key enumerated the account from a new address and read 64 objects.",
                    "claims": [
                        {"says": "The key read 64 objects from a new address.", "citations": uids}
                    ],
                    "severity": "high",
                    "severity_reason": "A live key is reading data.",
                    "citations": uids,
                    "still_active": True,
                }
            ),
            "You are Challenger": json.dumps(
                {
                    "arguing": "benign",
                    "explanations": [],
                    "strongest": "",
                    "grounded_in": "nothing",
                    "concede": True,
                }
            ),
            "You are IR Commander": json.dumps(
                {
                    "proposals": [
                        {
                            "action": action,
                            "target": target,
                            "autonomy": "L1",
                            "reversible": True,
                            "stage": "short_term",
                            "rationale": "Stops it now and can be undone",
                            "blast_radius": {
                                "principals": 1,
                                "company_loses": "nothing",
                                "citations": uids[:1],
                            },
                        }
                    ],
                    "page_human": False,
                    "containment_note": "Disable it, then rotate.",
                    "verify": ["the key is disabled"],
                    "ready_to_close": False,
                }
            ),
        }
    )


def test_an_l1_proposal_becomes_an_action_and_is_queued_to_run(ctx, store, config, case, uids):
    """The whole bug in one test: a proposal the policy allows must leave the chat table."""
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE"),
        config=config,
    )
    assert report.actions, "the Commander's proposals must reach the policy"
    taken = report.actions[0]
    assert taken["error"] == ""
    assert taken["autonomy"] == "L1", "a confident critical case clears the policy's floor"
    assert taken["state"] == "approved" and taken["queued"] is True
    row = fetch_one(
        ctx.db,
        "SELECT state, autonomy, decide_by FROM shoc.actions WHERE tenant_id=%s AND action_uid=%s",
        (config.tenant_id, taken["action_uid"]),
    )
    assert row and row["state"] == "approved"
    assert row["decide_by"] is None, "nothing that runs by itself waits for a deadline"
    queued = fetch_all(
        ctx.db,
        "SELECT payload FROM shoc.jobs WHERE tenant_id=%s AND kind='action.run'",
        (config.tenant_id,),
    )
    assert [q["payload"]["action_uid"] for q in queued] == [taken["action_uid"]]


def test_an_invented_action_is_recorded_as_one_nothing_could_run(ctx, store, config, case, uids):
    """The Commander once wrote `okta.revoke_sessions` for an action then called
    `idp.revoke_sessions`; now that name is the one nothing defines (RFC 0031)."""
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=commander(uids, "idp.revoke_sessions", "bob@example.com"),
        config=config,
    )
    assert report.actions and "unknown action" in report.actions[0]["error"]
    assert report.actions[0]["action_uid"] == ""
    said = [
        json.loads(m["body"])
        for m in transcript(ctx.db, config.tenant_id, case["case_uid"])
        if m["kind"] == "proposal"
    ]
    assert said and "unknown action" in said[0]["state"], "the case has to say it went nowhere"


def test_an_l2_proposal_gets_a_deadline_rather_than_waiting_for_ever(
    ctx, store, config, case, uids
):
    report = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=commander(uids, "aws.revoke_role_sessions", "deploy"),
        config=config,
    )
    taken = report.actions[0]
    assert taken["autonomy"] == "L2" and taken["queued"] is False
    row = fetch_one(
        ctx.db,
        "SELECT state, decide_by FROM shoc.actions WHERE tenant_id=%s AND action_uid=%s",
        (config.tenant_id, taken["action_uid"]),
    )
    assert row and row["state"] == "proposed" and row["decide_by"] is not None


def test_the_worker_queues_an_action_a_human_approved(ctx, conn, config, case, clean):
    """A human approving in Slack used to leave the action `approved` for ever too."""
    from shoc import worker

    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "tester",
        principal_kind="human",
        config=config,
    )
    execute(conn, "DELETE FROM shoc.jobs")
    action_store.approve(conn, config.tenant_id, row["action_uid"], "rettila", "human")
    assert worker.run_approved_actions(conn) >= 1
    queued = fetch_all(
        conn,
        "SELECT payload FROM shoc.jobs WHERE tenant_id=%s AND kind='action.run'",
        (config.tenant_id,),
    )
    assert row["action_uid"] in [q["payload"]["action_uid"] for q in queued]


def test_the_action_run_job_actually_executes_it(ctx, conn, config, case, clean):
    """Queueing is half of it. The job has to run, through the worker, with RLS on."""
    from shoc import worker

    before = audit_seq(conn, config.tenant_id)
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="notify.page",
            params={"summary": "the key is still in use"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    assert row["state"] == "approved", "notify.page is L1 on a critical case"
    summary = worker.handle(
        {
            "tenant_id": config.tenant_id,
            "kind": "action.run",
            "payload": {"action_uid": row["action_uid"]},
        },
        config,
    )
    assert row["action_uid"] in summary
    after = fetch_one(
        conn, "SELECT state, dry_run FROM shoc.actions WHERE action_uid = %s", (row["action_uid"],)
    )
    assert after and after["state"] == "done"
    assert after["dry_run"] is True, "a new install plans and changes nothing"
    # The worker runs it through `action.run` as a service principal (API-1, D8),
    # so the call is on record next to both changes of state.
    assert audit_trail(conn, config.tenant_id, before) == [
        ("action.proposed", "agent:IR Commander"),
        ("action.executed", "service:worker"),
        ("action.run", "service:worker"),
    ]


def test_an_undecided_action_on_a_quiet_case_is_abandoned_with_a_reason(
    ctx, conn, config, case, clean
):
    """Waiting is not an outcome. A medium case is not worth waking anybody for."""
    engine.set_severity(conn, config.tenant_id, case["case_uid"], "medium", "for this test")
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = %s",
        (row["action_uid"],),
    )
    before = audit_seq(conn, config.tenant_id)
    chased = unattended.run(conn, config.tenant_id, config)
    assert audit_trail(conn, config.tenant_id, before) == [
        ("action.rejected", "service:unattended")
    ]
    assert chased.abandoned == [row["action_uid"]] and chased.paged == []
    after = fetch_one(
        conn, "SELECT state, error FROM shoc.actions WHERE action_uid=%s", (row["action_uid"],)
    )
    assert after and after["state"] == "rejected" and "nobody decided" in after["error"]
    bodies = [m["body"] for m in transcript(conn, config.tenant_id, case["case_uid"])]
    assert any("Nothing was done about it" in b for b in bodies)


def test_an_undecided_action_on_a_severe_case_pages_instead(ctx, conn, config, case, clean):
    engine.set_severity(conn, config.tenant_id, case["case_uid"], "critical", "for this test")
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = %s",
        (row["action_uid"],),
    )
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.paged == [row["action_uid"]] and chased.abandoned == []
    paged = fetch_all(
        conn,
        "SELECT type, state FROM shoc.actions WHERE tenant_id=%s AND type='notify.page'",
        (config.tenant_id,),
    )
    assert paged, "somebody has to be woken for a critical case nobody decided"


def test_a_page_is_never_chased_and_goes_out_once(ctx, conn, config, case, clean):
    """The page loop: the case had used its three automatic actions, so the page
    itself needed approval, and four hours later the sweep paged about the page,
    quoting it, every cycle after that."""
    engine.set_severity(conn, config.tenant_id, case["case_uid"], "critical", "for this test")
    for n in range(3):
        execute(
            conn,
            """INSERT INTO shoc.actions (action_uid, tenant_id, case_uid, type, target, params,
                   autonomy, state, reversible, dry_run, rationale, requested_by, idempotency_key)
               VALUES (%s,%s,%s,'cloudflare.block_ip',%s,'{}','L1','done',true,true,'','test',%s)""",
            (f"ACT-used-{n}", config.tenant_id, case["case_uid"], f"192.0.2.{n}", f"used-{n}"),
        )
    stalled = []
    for role in ("deploy", "billing"):
        row = action_store.propose(
            conn,
            config.tenant_id,
            action_store.Proposal(
                action_type="aws.revoke_role_sessions",
                params={"role_name": role},
                case_uid=case["case_uid"],
            ),
            "IR Commander",
            principal_kind="agent",
            config=config,
        )
        stalled.append(row["action_uid"])
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = ANY(%s)",
        (stalled,),
    )
    for _ in range(3):
        unattended.run(conn, config.tenant_id, config)
        execute(
            conn,
            """UPDATE shoc.actions SET decide_by = now() - interval '1 hour'
               WHERE tenant_id = %s AND state = 'proposed'""",
            (config.tenant_id,),
        )
    pages = fetch_all(
        conn,
        "SELECT state FROM shoc.actions WHERE tenant_id=%s AND type='notify.page'",
        (config.tenant_id,),
    )
    assert len(pages) == 1, "one page per case per day, never a page about a page"
    assert pages[0]["state"] in ("approved", "done"), "a page does not wait for approval"


def test_a_case_stuck_on_needs_human_is_told_nobody_is_coming(ctx, conn, config, case, clean):
    """`needs_human` was a destination. It has to be a state with an exit."""
    engine.set_verdict(conn, config.tenant_id, case["case_uid"], "needs_human", 0.2, "not sure", [])
    execute(
        conn,
        """UPDATE shoc.cases SET severity = 'medium', worked_at = now() - interval '9 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case["case_uid"]),
    )
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.nudged == [case["case_uid"]]
    injected = [
        m for m in transcript(conn, config.tenant_id, case["case_uid"]) if m["kind"] == "inject"
    ]
    assert injected and "nobody is coming" in injected[-1]["body"]


def test_an_unanswered_nudge_is_not_repeated(ctx, conn, config, case, clean):
    """The nudge was sent every half hour whether or not the crew had read the last one."""
    engine.set_verdict(conn, config.tenant_id, case["case_uid"], "needs_human", 0.2, "not sure", [])
    execute(
        conn,
        """UPDATE shoc.cases SET severity = 'medium', worked_at = now() - interval '9 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case["case_uid"]),
    )
    assert unattended.run(conn, config.tenant_id, config).nudged == [case["case_uid"]]
    assert unattended.run(conn, config.tenant_id, config).nudged == []
    injected = [
        m for m in transcript(conn, config.tenant_id, case["case_uid"]) if m["kind"] == "inject"
    ]
    assert len(injected) == 1 and not injected[0].get("repeats")


def test_a_paged_action_still_undecided_is_abandoned(ctx, conn, config, case, clean):
    """The page went out, nobody answered, and the action sat `proposed` for ever."""
    engine.set_severity(conn, config.tenant_id, case["case_uid"], "critical", "for this test")
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = %s",
        (row["action_uid"],),
    )
    assert unattended.run(conn, config.tenant_id, config).paged == [row["action_uid"]]
    execute(
        conn,
        "UPDATE shoc.actions SET chased_at = now() - %s * interval '1 hour' WHERE action_uid = %s",
        (unattended.DECIDE_WITHIN_HOURS + 1, row["action_uid"]),
    )
    assert unattended.run(conn, config.tenant_id, config).abandoned == [row["action_uid"]]
    after = fetch_one(
        conn, "SELECT state, error FROM shoc.actions WHERE action_uid=%s", (row["action_uid"],)
    )
    assert after and after["state"] == "rejected" and "paged" in after["error"]


def test_a_quiet_case_past_its_deadline_is_woken_then_paged(ctx, conn, config, case, clean):
    """A case in containment with nothing new sat there for ever (D51)."""
    execute(
        conn,
        """UPDATE shoc.cases SET severity = 'high', state = 'containment', verdict = 'malicious',
                  worked_at = now() - interval '5 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case["case_uid"]),
    )
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.nudged == [case["case_uid"]] and chased.paged == []
    injected = [
        m for m in transcript(conn, config.tenant_id, case["case_uid"]) if m["kind"] == "inject"
    ]
    assert injected and "deadline" in injected[-1]["body"]
    # Before the second expiry nothing more happens.
    assert unattended.run(conn, config.tenant_id, config).paged == []
    execute(
        conn,
        """UPDATE shoc.openspace_messages SET created_at = now() - interval '4 hours 30 minutes'
           WHERE tenant_id = %s AND case_uid = %s AND kind = 'inject'""",
        (config.tenant_id, case["case_uid"]),
    )
    assert unattended.run(conn, config.tenant_id, config).paged == [case["case_uid"]]


def test_a_medium_case_expiring_twice_is_closed(ctx, conn, config, case, clean):
    """D51 as amended: a second expiry is an outcome. Below `high` it is a close."""
    execute(
        conn,
        """UPDATE shoc.cases SET severity = 'medium', state = 'analysis',
                  worked_at = now() - interval '30 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case["case_uid"]),
    )
    assert unattended.run(conn, config.tenant_id, config).nudged == [case["case_uid"]]
    execute(
        conn,
        """UPDATE shoc.openspace_messages SET created_at = now() - interval '25 hours'
           WHERE tenant_id = %s AND case_uid = %s AND kind = 'inject'""",
        (config.tenant_id, case["case_uid"]),
    )
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.paged == [] and chased.nudged == [] and chased.closed == [case["case_uid"]]
    row = engine.require(conn, config.tenant_id, case["case_uid"])
    assert row["state"] == "closed"
    bodies = [m["body"] for m in transcript(conn, config.tenant_id, case["case_uid"])]
    assert any("deadline twice" in b for b in bodies), "the reason is in the case"
    assert unattended.run(conn, config.tenant_id, config).closed == []


def test_the_sweep_goes_back_to_a_case_that_has_something_new(
    ctx, conn, config, case, clean, with_a_crew
):
    """`tokens_used = 0` was true exactly once, so a case was worked once and forgotten."""
    from shoc import worker

    # The crew worked this case after the detections that opened it, which is the
    # ordinary order of events.
    execute(
        conn,
        "UPDATE shoc.findings SET created_at = now() - interval '2 hours' WHERE case_uid = %s",
        (case["case_uid"],),
    )
    execute(
        conn,
        "UPDATE shoc.cases SET worked_at = now() - interval '1 hour' WHERE case_uid = %s",
        (case["case_uid"],),
    )
    execute(conn, "DELETE FROM shoc.jobs")
    assert "queued 0" in worker._sweep_cases(ctx), "a worked case with nothing new stays closed"

    execute(
        conn,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key, case_uid,
                window_start, window_end, first_seen, last_seen, event_count, event_uids)
           VALUES ('F-new',%s,'r2','something else fired','high','e',%s,
                   now(), now(), now(), now(), 1, ARRAY['e1'])""",
        (config.tenant_id, case["case_uid"]),
    )
    assert "queued 1" in worker._sweep_cases(ctx)


def test_a_second_run_continues_the_discussion_instead_of_restarting_it(
    ctx, store, config, case, uids
):
    first = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE"),
        config=config,
    )
    execute(
        ctx.db,
        "UPDATE shoc.cases SET worked_at = now() - interval '1 hour' WHERE case_uid = %s",
        (case["case_uid"],),
    )
    second = run_case(
        ctx.db,
        store,
        config.tenant_id,
        case["case_uid"],
        client=commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE"),
        config=config,
    )
    assert second.rounds > first.rounds, "the rounds carry on, they do not start again"
    openings = [
        m["body"]
        for m in transcript(ctx.db, config.tenant_id, case["case_uid"])
        if m["agent"] == "shoc" and not str(m["body"]).startswith("Confidence ")
    ]
    assert len(openings) == 2
    assert "detection(s) fired" in openings[0]
    assert "since the crew last looked" in openings[1], "say what changed, not what fired"


def test_the_investigator_can_reach_cti_on_a_case_nobody_scheduled(ctx, store, config, case, uids):
    """CTI used to be reachable only by keyword, and lost the one slot a round
    allowed. It is a tool now, so what matters is that the Investigator is offered
    it and the exchange is recorded rather than that a word caught it."""
    from shoc.agents.llm import ToolCall

    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    client.wants = [
        ToolCall(id="c1", name="ask_cti", arguments={"question": "Anything on 203.0.113.55?"})
    ]
    client.replies["You are CTI"] = json.dumps(
        {
            "known": [
                {
                    "says": "On the abuse.ch blocklist since June.",
                    "provenance": "store",
                    "source_uid": "",
                }
            ],
            "confidence": 0.6,
            "citations": uids,
        }
    )
    run_case(ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config)
    messages = transcript(ctx.db, config.tenant_id, case["case_uid"])
    asked = [m for m in messages if m["kind"] == "request" and m["to_agent"] == "CTI"]
    said = [m for m in messages if m["agent"] == "CTI"]
    assert asked, "the Investigator must be able to reach CTI without a scheduler"
    assert said and "abuse.ch" in said[0]["body"]
    assert "[store]" in said[0]["body"], "a claim says where it came from"
    assert len(asked) == 1, "the loop does not ask CTI again once the Investigator did"


def test_the_evidence_calls_cti_when_the_investigator_does_not(ctx, store, config, case, uids):
    """AGT-11: an external address in the events is enough to bring CTI in."""
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    client.replies["You are CTI"] = json.dumps(
        {
            "known": [
                {"says": "Nothing has been published on 203.0.113.55.", "provenance": "lookup"}
            ],
            "confidence": 0.5,
        }
    )
    run_case(ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config)
    messages = transcript(ctx.db, config.tenant_id, case["case_uid"])
    asked = [m for m in messages if m["kind"] == "request"]
    assert [m["to_agent"] for m in asked] == ["CTI"]
    assert [m["agent"] for m in messages if m["kind"] == "answer"] == ["CTI"]
    assert any("Nothing has been published on 203.0.113.55" in c for c in client.calls), (
        "what CTI said is in front of the turns after it"
    )


def test_the_investigator_can_correct_the_severity_a_rule_guessed_at(
    ctx, store, config, case, uids
):
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    client.replies["You are Investigator"] = json.dumps(
        {
            "verdict": "suspicious",
            "confidence": 0.7,
            "reasoning": "One login from a new country, nothing else moved.",
            "severity": "low",
            "severity_reason": "no privileged action followed the login",
            "citations": uids,
        }
    )
    report = run_case(
        ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config
    )
    assert report.severity == "low"
    row = fetch_one(
        ctx.db, "SELECT severity FROM shoc.cases WHERE case_uid = %s", (case["case_uid"],)
    )
    assert row and row["severity"] == "low"
    bodies = [m["body"] for m in transcript(ctx.db, config.tenant_id, case["case_uid"])]
    assert any("Severity moved from" in b for b in bodies), "a severity change is never quiet"


def test_a_severity_change_with_no_reason_is_refused(ctx, store, config, case, uids):
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    client.replies["You are Investigator"] = json.dumps(
        {
            "verdict": "malicious",
            "confidence": 0.9,
            "reasoning": "It is bad.",
            "severity": "informational",
            "severity_reason": "",
            "citations": uids,
        }
    )
    report = run_case(
        ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config
    )
    assert any("no reason" in e for e in report.errors)
    row = fetch_one(
        ctx.db, "SELECT severity FROM shoc.cases WHERE case_uid = %s", (case["case_uid"],)
    )
    assert row and row["severity"] != "informational"


def test_a_medium_case_now_hears_a_benign_explanation(ctx, store, config, case, uids):
    """The debate used to be gated on severity as well as on the budget."""
    execute(
        ctx.db,
        "UPDATE shoc.cases SET severity = 'medium' WHERE case_uid = %s",
        (case["case_uid"],),
    )
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    client.replies["You are Challenger"] = json.dumps(
        {
            "arguing": "benign",
            "explanations": ["The CI runner moved"],
            "strongest": "The CI runner moved",
            "grounded_in": "checklist",
            "would_rule_out": ["A change record"],
            "concede": False,
        }
    )
    run_case(ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config)
    agents = {m["agent"] for m in transcript(ctx.db, config.tenant_id, case["case_uid"])}
    assert "Challenger" in agents


def test_the_budget_follows_what_the_case_contains():
    plain = Budget.for_case("medium")
    researchable = Budget.for_case("medium", observables=5)
    published = Budget.for_case("medium", observables=5, reports=1)
    assert plain.max_rounds == 2
    assert researchable.max_tokens > plain.max_tokens
    assert published.max_rounds > plain.max_rounds


# -- D45: the Commander's blast radius, fallback and window reach the policy ----
def test_an_unanswered_blast_radius_stops_the_crew(ctx, store, config, case, uids):
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    said = json.loads(client.replies["You are IR Commander"])
    del said["proposals"][0]["blast_radius"]
    client.replies["You are IR Commander"] = json.dumps(said)
    report = run_case(
        ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config
    )
    taken = report.actions[0]
    assert taken["autonomy"] == "L2" and taken["state"] == "proposed"
    row = action_store.require(ctx.db, config.tenant_id, taken["action_uid"])
    assert "blast radius" in row["rationale"]


def test_an_expired_l2_falls_back_to_the_commanders_narrower_action(ctx, conn, config, clean):
    from tests.support import malicious_case

    okta = malicious_case(conn, config.tenant_id, "okta_mfa_fatigue")
    engine.set_severity(conn, config.tenant_id, okta, "critical", "for this test")
    cited = fetch_one(conn, "SELECT event_uids FROM shoc.findings WHERE case_uid = %s", (okta,))
    assert cited
    blast = {"principals": 1, "citations": list(cited["event_uids"])[:1]}
    (taken,) = action_store.from_crew(
        conn,
        config.tenant_id,
        okta,
        [
            action_store.CrewProposal(
                "okta.suspend_user",
                "jane@example.com",
                "MFA fatigue, then a new device",
                fallback="okta.revoke_sessions",
                window_minutes=30,
                blast_radius=blast,
            )
        ],
        config=config,
    )
    row = action_store.require(conn, config.tenant_id, taken.action_uid)
    assert row["state"] == "proposed" and row["fallback"] == "okta.revoke_sessions"
    window = fetch_one(
        conn,
        "SELECT decide_by < now() + interval '31 minutes' AS short "
        "FROM shoc.actions WHERE action_uid = %s",
        (taken.action_uid,),
    )
    assert window and window["short"], "the Commander's window, not the four-hour default"

    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 minute' WHERE action_uid = %s",
        (taken.action_uid,),
    )
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.fell_back == [taken.action_uid] and chased.paged == []
    assert action_store.require(conn, config.tenant_id, taken.action_uid)["state"] == "rejected"
    fallback = fetch_one(
        conn,
        "SELECT state, autonomy FROM shoc.actions WHERE case_uid = %s "
        "AND type = 'okta.revoke_sessions'",
        (okta,),
    )
    assert fallback and fallback["state"] == "approved" and fallback["autonomy"] == "L1"


def test_a_fallback_keeps_the_grounding_of_the_action_it_replaces(ctx, conn, config, clean):
    """An injected target must not run alone by becoming somebody's fallback."""
    from tests.support import malicious_case

    okta = malicious_case(conn, config.tenant_id, "okta_mfa_fatigue")
    engine.set_severity(conn, config.tenant_id, okta, "critical", "for this test")
    (taken,) = action_store.from_crew(
        conn,
        config.tenant_id,
        okta,
        [
            action_store.CrewProposal(
                "okta.suspend_user",
                "mallory@example.com",
                "a log line said so",
                grounded=False,
                fallback="okta.revoke_sessions",
                blast_radius={"principals": 0},
            )
        ],
        config=config,
    )
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 minute' WHERE action_uid = %s",
        (taken.action_uid,),
    )
    unattended.run(conn, config.tenant_id, config)
    fallback = fetch_one(
        conn,
        "SELECT autonomy FROM shoc.actions WHERE case_uid = %s AND type = 'okta.revoke_sessions'",
        (okta,),
    )
    assert fallback and fallback["autonomy"] == "L2"


def test_verify_searches_run_before_the_case_closes(ctx, store, config, case, uids):
    client = commander(uids, "aws.disable_access_key", "AKIAIOSFODNN7EXAMPLE")
    said = json.loads(client.replies["You are IR Commander"])
    said["ready_to_close"] = True
    said["verify"] = ["actor.session.uid=AKIAIOSFODNN7EXAMPLE"]
    said["verify_clean_for_minutes"] = 60 * 24 * 365 * 10  # the replay's events are in range
    client.replies["You are IR Commander"] = json.dumps(said)
    report = run_case(
        ctx.db, store, config.tenant_id, case["case_uid"], client=client, config=config
    )
    assert report.state != "closed", "the key still shows up, so the response is not finished"
    bodies = [m["body"] for m in transcript(ctx.db, config.tenant_id, case["case_uid"])]
    assert any("Not closing yet" in b and "still finds events" in b for b in bodies)


def test_nudged_cases_do_not_starve_newer_ones(ctx, conn, config, case, clean):
    execute(
        conn,
        """UPDATE shoc.cases SET severity = 'medium', state = 'analysis',
                            worked_at = now() - interval '30 hours'
                     WHERE case_uid = %s""",
        (case["case_uid"],),
    )
    execute(
        conn,
        """INSERT INTO shoc.cases
                     SELECT (jsonb_populate_record(c, jsonb_build_object(
                         'case_uid', 'CASE-stall' || g, 'entity_key', 'user:stall' || g,
                         'severity', 'high', 'worked_at', now() - interval '5 hours'))).*
                     FROM shoc.cases c, generate_series(1, 25) g WHERE c.case_uid = %s""",
        (case["case_uid"],),
    )
    first = unattended.run(conn, config.tenant_id, config)
    assert len(first.nudged) == 25 and case["case_uid"] not in first.nudged
    assert unattended.run(conn, config.tenant_id, config).nudged == [case["case_uid"]]
