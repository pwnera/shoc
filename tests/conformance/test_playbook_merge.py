"""People merge playbooks at runtime, made of the actions shoc has (RSP-2, RFC 0033)."""

from __future__ import annotations

import json

import pytest

from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import engine, playbooks
from shoc.db.pool import execute, fetch_one
from shoc.errors import Denied, GateRefused, NotFound, ValidationError

pytestmark = pytest.mark.postgres

OURS = "suspend_on_push_fatigue"


def _ours(**over):
    """Suspend at once on push fatigue, where the shipped playbook only revokes sessions."""
    return {
        "id": OURS,
        "title": "Suspend the account on push fatigue",
        "rules": ["okta_mfa_push_fatigue"],
        "questions": [
            {"id": "approved", "ask": "Was a push approved after the denials, and from where?"},
            {"id": "after", "ask": "What did the session do after sign-in?"},
        ],
        "benign_when": ["The user denied a push by mistake and approved the next one."],
        "trigger": {"verdict": ["malicious"], "severity_at_least": "medium"},
        "steps": [
            {
                "name": "revoke the user's sessions",
                "action": "okta.revoke_sessions",
                "params": {"user": "{{ entity.user }}"},
            },
            {
                "name": "suspend the account",
                "action": "okta.suspend_user",
                "params": {"user": "{{ entity.user }}"},
            },
        ],
        **over,
    }


def _books(ctx, case_uid=""):
    listed = call("playbook.list", ctx, {"case_uid": case_uid}).data.playbooks
    return {b["id"]: b for b in listed}


@pytest.fixture
def okta_case(ctx, config, clean):
    """The case that holds the push-fatigue finding, ruled malicious."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "okta_mfa_fatigue", tenant_id=config.tenant_id, store=ctx.store)
    row = fetch_one(
        ctx.db,
        """SELECT case_uid, event_uids FROM shoc.findings
           WHERE tenant_id = %s AND rule_id = 'okta_mfa_push_fatigue' AND case_uid <> ''
           LIMIT 1""",
        (config.tenant_id,),
    )
    assert row, "the scenario raises push fatigue on a case"
    engine.set_verdict(
        ctx.db,
        config.tenant_id,
        row["case_uid"],
        "malicious",
        0.95,
        "push fatigue",
        list(row["event_uids"]),
    )
    return str(row["case_uid"])


def test_a_merged_playbook_takes_its_rule_and_runs_on_its_cases(ctx, okta_case):
    out = call("playbook.merge", ctx, {"playbook": _ours(), "reason": "suspend at once"})
    assert out.data.took_from == {"okta_mfa_push_fatigue": "contain_account_takeover"}

    books = _books(ctx)
    assert books[OURS]["rules"] == ["okta_mfa_push_fatigue"]
    assert books[OURS]["merged_by"] == "human:test"
    assert "okta_mfa_push_fatigue" not in books["contain_account_takeover"]["rules"]
    assert OURS in _books(ctx, okta_case)

    run = call("playbook.run", ctx, {"playbook_id": OURS, "case_uid": okta_case})
    assert run.data.state == "waiting_approval", "suspending a person waits for a human"


def test_a_dry_run_checks_a_playbook_and_merges_nothing(ctx, clean):
    out = call("playbook.merge", ctx, {"playbook": _ours(), "dry_run": True})
    assert out.data.dry_run
    assert out.data.took_from == {"okta_mfa_push_fatigue": "contain_account_takeover"}
    assert OURS not in _books(ctx)
    with pytest.raises(ValidationError, match="two questions"):
        call("playbook.merge", ctx, {"playbook": _ours(questions=[]), "dry_run": True})


def test_what_playbook_list_returns_can_be_merged_again(ctx, clean):
    shipped = _books(ctx)["contain_account_takeover"]
    copy = {**shipped, "id": "takeover_here", "rules": ["okta_push_approved_after_denial"]}
    out = call("playbook.merge", ctx, {"playbook": copy})
    assert out.data.rules == ["okta_push_approved_after_denial"]
    assert _books(ctx)["takeover_here"]["steps"] == shipped["steps"]


def test_revert_gives_the_rule_back_and_cancels_the_open_run(ctx, okta_case):
    call("playbook.merge", ctx, {"playbook": _ours()})
    run = call("playbook.run", ctx, {"playbook_id": OURS, "case_uid": okta_case}).data

    out = call("playbook.revert", ctx, {"playbook_id": OURS, "reason": "too blunt"})
    assert out.data.answered_by == {"okta_mfa_push_fatigue": "contain_account_takeover"}
    assert out.data.cancelled_runs == 1
    assert OURS not in _books(ctx)
    assert "okta_mfa_push_fatigue" in _books(ctx)["contain_account_takeover"]["rules"]
    # A run of a playbook that is gone still answers, and stays cancelled.
    resumed = call("playbook.resume", ctx, {"run_uid": run.run_uid})
    assert resumed.data.state == "cancelled"


def test_merging_again_replaces_it_and_cancels_the_old_version_s_runs(ctx, okta_case):
    call("playbook.merge", ctx, {"playbook": _ours()})
    call("playbook.run", ctx, {"playbook_id": OURS, "case_uid": okta_case})
    again = _ours(title="Suspend on push fatigue, then page")
    again["steps"] = [
        *again["steps"],
        {"name": "page", "action": "notify.page", "params": {"summary": "{{ case.title }}"}},
    ]
    dry = call("playbook.merge", ctx, {"playbook": again, "dry_run": True})
    assert dry.data.cancelled_runs == 1 and "would cancel 1 open run" in dry.summary
    out = call("playbook.merge", ctx, {"playbook": again})
    assert out.data.cancelled_runs == 1
    assert len(_books(ctx)[OURS]["steps"]) == 3


def test_the_gate_names_every_reason(ctx, clean):
    bad = _ours(
        id="contain_account_takeover",
        rules=["okta_mfa_push_fatigue", "no_such_rule", "aws_access_key_created"],
        questions=[{"id": "q", "ask": "What happened?"}],
        trigger={"verdict": ["benign_expected"], "severity_at_least": "urgent"},
        steps=[{"name": "suspend", "action": "okta.suspend_user", "params": {}}],
    )
    with pytest.raises(GateRefused) as refused:
        call("playbook.merge", ctx, {"playbook": bad})
    reasons = refused.value.reasons
    for words in (
        "ships in content/",
        "trigger.verdict",
        "trigger.severity_at_least",
        "two questions",
        "no rule or hunt pack 'no_such_rule'",
        "gives okta.suspend_user no user",
        "can never run on a case from aws_access_key_created",
    ):
        assert sum(words in r for r in reasons) == 1, words


def test_a_rule_stays_with_the_playbook_that_can_act_on_it(ctx, clean):
    page_only = _ours(
        steps=[{"name": "page", "action": "notify.page", "params": {"summary": "{{ case.title }}"}}]
    )
    with pytest.raises(ValidationError, match="contain_account_takeover, which answers it now"):
        call("playbook.merge", ctx, {"playbook": page_only})


def test_a_rule_has_one_merged_playbook(ctx, clean):
    call("playbook.merge", ctx, {"playbook": _ours()})
    with pytest.raises(ValidationError, match=f"answered by {OURS}, merged here"):
        call("playbook.merge", ctx, {"playbook": _ours(id="another_one")})


def _merged_rule(conn, tenant_id, playbook_id):
    """A new rule the Detection Engineer merged, answered by `playbook_id`."""
    rule = {
        "id": "okta_rule_merged_here",
        "title": "A rule merged here",
        "logsource": {"product": "okta"},
        "detection": {"selection": {"api.operation": "user.session.start"}},
    }
    execute(
        conn,
        """INSERT INTO shoc.merged_rules (tenant_id, rule_id, body, playbook_id, merged_by)
           VALUES (%s, %s, %s, %s, 'agent:test')""",
        (tenant_id, rule["id"], json.dumps(rule), playbook_id),
    )


def test_a_playbook_a_merged_rule_answers_to_is_not_reverted(ctx, conn, config, clean):
    call("playbook.merge", ctx, {"playbook": _ours()})
    _merged_rule(conn, config.tenant_id, OURS)
    assert "okta_rule_merged_here" in _books(ctx)[OURS]["rules"]
    with pytest.raises(ValidationError, match="okta_rule_merged_here would be answered by no"):
        call("playbook.revert", ctx, {"playbook_id": OURS, "reason": "gone"})


def test_a_narrowed_rule_keeps_its_shipped_playbook(conn, config, clean):
    narrowing = {
        "narrows": "okta_mfa_push_fatigue",
        "exclude": [{"src_endpoint.ip": "203.0.113.7", "actor.user.uid": "00u1example"}],
    }
    execute(
        conn,
        """INSERT INTO shoc.merged_rules (tenant_id, rule_id, body, playbook_id, merged_by)
           VALUES (%s, 'okta_mfa_push_fatigue', %s, '', 'agent:test')""",
        (config.tenant_id, json.dumps(narrowing)),
    )
    books = {b.id: b for b in playbooks.load(config, conn, config.tenant_id)}
    assert "okta_mfa_push_fatigue" in books["contain_account_takeover"].rules


def test_a_shipped_playbook_is_out_of_reach(ctx, clean):
    with pytest.raises(NotFound, match="not a playbook merged here"):
        call("playbook.revert", ctx, {"playbook_id": "contain_account_takeover", "reason": "x"})


def test_only_a_person_merges_a_playbook(config, conn, store):
    crew = Context(
        tenant_id=config.tenant_id,
        caller=Caller(kind="agent", id="crew", scopes=("*",)),
        config=config,
    )
    crew._db, crew._store = conn, store
    with pytest.raises(Denied, match="may not call this capability"):
        call("playbook.merge", crew, {"playbook": _ours()})
