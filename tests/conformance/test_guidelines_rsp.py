"""The response, autonomy and paging guidelines that need a database (RSP-G5, RSP-G7, RSP-G10).

A rule the code breaks today is listed in a test's KNOWN with why it is allowed
for now; the test fails on a break that is not listed and on a listed one that
no longer breaks, so each list only shrinks.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest

from shoc.agents import manager
from shoc.agents.openspace import transcript
from shoc.capabilities.registry import call
from shoc.cases import actions as action_store
from shoc.cases import engine, playbooks, unattended
from shoc.db.pool import execute, fetch_one
from shoc.detect import rules as ruleset
from shoc.detect.engine import run_rule
from shoc.errors import ValidationError
from shoc.ingest import batch
from tests.support import fixture_rows, fixture_source, load_fixture, malicious_case

pytestmark = pytest.mark.postgres

KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key
RULES = {r.id: r for r in ruleset.load()}
BOOKS = playbooks.load()


@pytest.fixture
def case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key", store)


@pytest.fixture
def unruled_case(ctx, store, config, clean):
    """The leaked-key case with no verdict yet, so the crew's proposals wait for a person."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row, "the scenario must open a case"
    return str(row["case_uid"])


# -- RSP-G5 a step acts on what a rule named ------------------------------------
def _rule_reads() -> list[tuple[str, str]]:
    """Every (rule, kind) a shipped step that acts reads as `{{ rule.<id>.<kind> }}`."""
    pairs: set[tuple[str, str]] = set()
    for book in BOOKS:
        for step in book.steps:
            if not step.action or step.action.startswith("notify."):
                continue
            for path in playbooks.PLACEHOLDER.findall(json.dumps(step.params)):
                scope, _, rest = path.partition(".")
                rule_id, _, kind = rest.partition(".")
                if scope == "rule" and rule_id in RULES and kind:
                    pairs.add((rule_id, kind))
    return sorted(pairs)


READS = _rule_reads()
# Steps that read a kind their rule's positive fixture does not make it carry,
# each with why. The fix is the fixture's: real events carry the field.
KIND_KNOWN = {
    "aws_access_key_created.resource": "its CreateAccessKey records have no responseElements",
    "edr_high_severity_detection.file_hash": "its detections name no file hash",
}


@pytest.mark.parametrize(("rule_id", "kind"), READS, ids=[f"{r}.{k}" for r, k in READS])
def test_a_step_reads_a_kind_its_rule_emits(rule_id, kind, store, config, clean, now):
    """RSP-G5: a step's `rule.<id>.<kind>` is a kind that rule's finding carries,
    so the step renders a target instead of an empty value it skips."""
    rule = RULES[rule_id]
    rows = fixture_rows(
        load_fixture(rule.id, "positive"), fixture_source(rule), config.tenant_id, now
    )
    batch.load(store, rows)
    findings = run_rule(
        store, config.tenant_id, rule, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert findings, f"{rule_id} did not fire on its positive fixture"
    emitted = sorted({e.partition(":")[0] for f in findings for e in f.entities})
    key = f"{rule_id}.{kind}"
    if key in KIND_KNOWN:
        assert kind not in emitted, f"{key} is emitted now: take it out of KIND_KNOWN"
    else:
        assert kind in emitted, f"a step reads rule.{key}; {rule_id}'s findings carry {emitted}"


def _acts_on_entity() -> dict[str, Any]:
    """A person's playbook whose only acting step reads the case's first user."""
    return {
        "id": "suspend_on_entity",
        "title": "Suspend the first user on the case",
        "rules": ["okta_mfa_push_fatigue"],
        "questions": [
            {"id": "approved", "ask": "Was a push approved after the denials, and from where?"},
            {"id": "after", "ask": "What did the session do after sign-in?"},
        ],
        "benign_when": ["The user denied a push by mistake and approved the next one."],
        "trigger": {"verdict": ["malicious"], "severity_at_least": "medium"},
        "steps": [
            {
                "name": "suspend the account",
                "action": "okta.suspend_user",
                "params": {"user": "{{ entity.user }}"},
            }
        ],
    }


GATE_KNOWN = {"shoc/cases/playbooks.py:merge": "RSP-G5 gap: the lint has no entity.* check"}


def test_a_merged_playbook_may_not_act_on_entity(ctx, clean):
    """RSP-G5: the playbook.merge gate refuses a step that acts on `entity.*`,
    as the shipped playbooks are held to it."""
    try:
        call("playbook.merge", ctx, {"playbook": _acts_on_entity(), "dry_run": True})
        said = ""
    except ValidationError as exc:
        said = " ".join([str(exc), *map(str, getattr(exc, "reasons", None) or [])])
    if "shoc/cases/playbooks.py:merge" in GATE_KNOWN:
        assert "entity." not in said, "the gate refuses it now: take it out of GATE_KNOWN"
        assert not said, f"the gate refused the playbook for another reason: {said}"
    else:
        assert "entity." in said, f"the gate took a step that acts on entity.user: {said!r}"


# -- RSP-G7 every close goes through one function -------------------------------
def _approved(ctx, case_uid: str, action: str, **params: str) -> str:
    record = call(
        "action.propose",
        ctx,
        {"action": action, "params": params, "case_uid": case_uid, "rationale": "test"},
    ).data
    if record.state == "proposed":
        call("action.approve", ctx, {"action_uid": record.action_uid})
    return record.action_uid


def _wait_then_page(monkeypatch) -> str:
    book = playbooks.Playbook.from_dict(
        {
            "id": "wait_then_page",
            "title": "Wait, then page",
            "rules": ["x"],
            "steps": [
                {"name": "give the key a quarter hour", "wait_minutes": 15},
                {"name": "page", "action": "notify.page", "params": {"summary": "still here"}},
            ],
        }
    )
    monkeypatch.setattr(playbooks, "get", lambda playbook_id, *rest: book)
    return book.id


def _close(path: str, verdict: str, ctx, conn, config, case_uid: str) -> None:
    """Close the case, or rule on it, the way `path` does."""
    tenant = config.tenant_id
    if path == "case.close":
        call("case.close", ctx, {"case_uid": case_uid, "disposition": verdict, "reason": "test"})
        return
    finding = fetch_one(
        conn, "SELECT event_uids FROM shoc.findings WHERE case_uid = %s LIMIT 1", (case_uid,)
    )
    cited = list(finding["event_uids"]) if finding else []
    engine.set_verdict(conn, tenant, case_uid, verdict, 0.9, "test", cited)
    if path == "case.set_state":
        call("case.set_state", ctx, {"case_uid": case_uid, "state": "closed", "note": "test"})
    elif path == "crew":
        # What loop.run_case does when the crew closes a case.
        engine.transition(conn, tenant, case_uid, "closed", "crew decision", by="crew")
    elif path == "unattended":
        unattended._close(conn, tenant, case_uid, "low", unattended.DEADLINE_HOURS["low"])


# A person's close, or a benign verdict, stops what waits on the case; a crew or
# deadline close of an attack leaves its containment approvable and runnable, which
# amends D176's refusal of any action on a closed case.
PATHS = ("case.close", "case.set_state", "crew", "unattended", "set_verdict")
PERSON = {"case.close", "case.set_state"}
NO_RUN_CANCELLED = "a benign verdict rejects what waits, but only a person's close cancels runs"
CLOSE_KNOWN = {
    "crew/malicious": "D176: _case_says_no refuses an action on any closed case",
    "crew/false_positive": NO_RUN_CANCELLED,
    "unattended/malicious": "_close rejects what waits on an attack, and _case_says_no refuses",
    "unattended/false_positive": NO_RUN_CANCELLED,
    "set_verdict/false_positive": NO_RUN_CANCELLED,
}


@pytest.mark.parametrize("verdict", ["malicious", "false_positive"])
@pytest.mark.parametrize("path", PATHS)
def test_every_close_path_has_the_same_effect(path, verdict, ctx, conn, config, case, monkeypatch):
    """RSP-G7: every way a case closes, or is ruled benign, decides its actions and
    runs by who closed it and with what verdict, and by nothing else.

    An approved L1 still disabled a key seconds after a false-positive verdict (ir-15).
    """
    tenant = config.tenant_id
    waiting = call(
        "action.propose",
        ctx,
        {
            "action": "aws.revoke_role_sessions",
            "params": {"role_name": "deploy"},
            "case_uid": case,
            "rationale": "test",
        },
    ).data
    assert waiting.state == "proposed", "a person's revoke waits for an approval"
    approved = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    assert action_store.require(conn, tenant, approved)["state"] == "approved"
    run = playbooks.start(conn, tenant, _wait_then_page(monkeypatch), case, config)
    assert playbooks.advance(conn, tenant, run["run_uid"], "", config).state == "waiting_timer"

    _close(path, verdict, ctx, conn, config, case)

    after = action_store.require(conn, tenant, approved)
    says_no = action_store._case_says_no(conn, tenant, after)
    ran = fetch_one(
        conn, "SELECT state FROM shoc.playbook_runs WHERE run_uid = %s", (run["run_uid"],)
    )
    seen = {
        "waiting": action_store.require(conn, tenant, waiting.action_uid)["state"],
        "approved": after["state"],
        "runnable": after["state"] == "approved" and not says_no,
        "run_cancelled": bool(ran and ran["state"] == "cancelled"),
    }
    stop = path in PERSON or verdict == "false_positive"
    want = {
        "waiting": "rejected" if stop else "proposed",
        "approved": "rejected" if stop else "approved",
        "runnable": not stop,
        "run_cancelled": stop,
    }
    key = f"{path}/{verdict}"
    if key in CLOSE_KNOWN:
        assert seen != want, f"{key} has the same effect now: take it out of CLOSE_KNOWN"
    else:
        assert seen == want, f"{key} left {seen}, where it should leave {want}"


# -- RSP-G10 the chase waits for the page to settle -------------------------------
def test_an_l2_is_not_abandoned_while_its_page_retries(
    ctx, conn, config, unruled_case, clean, pager
):
    """RSP-G10: an L2 nobody decided keeps its chase while the page about it is
    retried, gets its second window once the page goes out, and only then is abandoned.

    One PagerDuty 503 abandoned the L2 at once, and the retried page asked about
    an action that was already rejected (po-3).
    """
    tenant = config.tenant_id
    engine.set_severity(conn, tenant, unruled_case, "high", "for this test")
    row = action_store.propose(
        conn,
        tenant,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=unruled_case,
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    uid = row["action_uid"]
    assert row["state"] == "proposed", "the crew's revoke on an unruled case waits for a person"
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = %s",
        (uid,),
    )

    pager.status = 503
    chased = unattended.run(conn, tenant, config)
    assert uid not in chased.abandoned and uid not in chased.paged
    action = fetch_one(
        conn, "SELECT state, chased_at FROM shoc.actions WHERE action_uid = %s", (uid,)
    )
    assert action and action["state"] == "proposed" and action["chased_at"] is not None
    page = """SELECT outcome, delivered_at, retry_at FROM shoc.notices
              WHERE tenant_id = %s AND source = 'unattended' AND condition = 'deadline_expired'"""
    notice = fetch_one(conn, page, (tenant,))
    assert notice and notice["retry_at"] is not None, "the page is being tried again"
    assert notice["outcome"] is None and notice["delivered_at"] is None

    pager.status = 202
    execute(
        conn,
        """UPDATE shoc.notices SET retry_at = now() - interval '1 second'
           WHERE tenant_id = %s AND source = 'unattended'""",
        (tenant,),
    )
    manager.deliver(conn, tenant, config)
    notice = fetch_one(conn, page, (tenant,))
    assert notice and notice["outcome"] == "paged"
    assert uid not in unattended.run(conn, tenant, config).abandoned, "its second window runs"

    execute(
        conn,
        "UPDATE shoc.actions SET chased_at = now() - %s * interval '1 hour' WHERE action_uid = %s",
        (unattended.DECIDE_WITHIN_HOURS + 1, uid),
    )
    assert unattended.run(conn, tenant, config).abandoned == [uid]
    after = fetch_one(conn, "SELECT state, error FROM shoc.actions WHERE action_uid = %s", (uid,))
    assert after and after["state"] == "rejected" and "paged" in after["error"]
    bodies = [m["body"] for m in transcript(conn, tenant, unruled_case)]
    assert any("Nothing was done about it" in b for b in bodies)
