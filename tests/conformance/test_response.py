"""Actions, approvals and playbook runs end to end (RSP-2, RSP-3, RSP-4)."""

from __future__ import annotations

import pytest

from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import engine, playbooks
from shoc.db.pool import execute, fetch_one
from shoc.errors import Denied, ValidationError
from tests.support import a_step_that_waits, audit_seq, audit_trail, malicious_case

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    """A malicious, confident, critical case for a leaked key — the v0.3 scenario."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row
    finding = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, row["case_uid"]),
    )
    assert finding
    engine.set_verdict(
        ctx.db,
        config.tenant_id,
        row["case_uid"],
        "malicious",
        0.93,
        "A stolen key enumerated the account and read a bucket.",
        list(finding["event_uids"]),
    )
    return row["case_uid"]


@pytest.fixture
def okta_case(ctx, store, config, clean):
    """An account takeover. Suspending an Okta user is no answer to a leaked AWS key."""
    return malicious_case(ctx.db, config.tenant_id, "okta_mfa_fatigue", ctx.store)


@pytest.fixture
def role_case(ctx, store, config, clean):
    """Instance role credentials used from outside, with an IAM user on the case too."""
    return malicious_case(ctx.db, config.tenant_id, "aws_session_key_two_users", ctx.store)


@pytest.fixture
def agent_ctx(config, conn, store):
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config)
    c._db, c._store = conn, store
    return c


def test_a_confident_reversible_proposal_is_born_approved(agent_ctx, case):
    result = call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
            "case_uid": case,
            "rationale": "stolen key",
        },
    )
    assert result.data.state == "approved" and result.data.autonomy == "L1"
    assert result.data.dry_run, "a new install plans, it does not act"


def test_a_risky_proposal_waits_for_a_human(agent_ctx, case):
    result = call(
        "action.propose",
        agent_ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    assert result.data.state == "proposed" and result.data.autonomy == "L2"


def test_an_agent_cannot_approve_its_own_proposal(agent_ctx, case):
    proposed = call(
        "action.propose",
        agent_ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    with pytest.raises(Denied, match="may not call this capability"):
        call("action.approve", agent_ctx, {"action_uid": proposed.data.action_uid})
    from shoc.cases.actions import approve

    # And the store refuses too, so no surface can route around the check.
    with pytest.raises(Denied, match="only a human principal"):
        approve(agent_ctx.db, agent_ctx.tenant_id, proposed.data.action_uid, "crew", "agent")


def test_a_human_approves_and_the_action_runs_as_a_dry_run(ctx, agent_ctx, case):
    proposed = call(
        "action.propose",
        agent_ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    approved = call("action.approve", ctx, {"action_uid": proposed.data.action_uid})
    assert approved.data.state == "approved"
    outcome = call("action.run", ctx, {"action_uid": proposed.data.action_uid, "dry_run": True})
    assert outcome.data.ok and outcome.data.dry_run
    assert "[dry run]" in outcome.data.detail and "deploy" in outcome.data.detail


def test_running_the_same_action_twice_does_not_act_twice(ctx, agent_ctx, case):
    proposed = call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIA1", "user_name": "deploy-ci"},
            "case_uid": case,
        },
    )
    first = call("action.run", ctx, {"action_uid": proposed.data.action_uid, "dry_run": True})
    second = call("action.run", ctx, {"action_uid": proposed.data.action_uid, "dry_run": True})
    assert first.data.ok and second.data.detail == "already done"


def test_a_rejected_action_cannot_run(ctx, agent_ctx, case):
    proposed = call(
        "action.propose",
        agent_ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    call("action.reject", ctx, {"action_uid": proposed.data.action_uid, "note": "on holiday"})
    with pytest.raises(ValidationError, match="rejected, not approved"):
        call("action.run", ctx, {"action_uid": proposed.data.action_uid, "dry_run": True})


def test_an_action_on_an_uncited_case_is_blocked(ctx, config, conn, store, clean, agent_ctx):
    uid = engine.open_for_findings(
        conn,
        config.tenant_id,
        [
            {
                "finding_uid": "F-x",
                "title": "no evidence",
                "severity": "critical",
                "entity_key": "u1",
                "entities": ["user:u1"],
                "last_seen": __import__("datetime").datetime.now(__import__("datetime").UTC),
                "attack": [],
                "case_uid": None,
            }
        ],
    )[0]
    engine.set_verdict(conn, config.tenant_id, uid, "needs_human", 0.0, "", [])
    result = call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIA1", "user_name": "deploy-ci"},
            "case_uid": uid,
        },
    )
    assert result.data.state == "blocked"


def test_the_leaked_key_playbook_matches_and_contains_without_waiting(ctx, case, config):
    """The v0.3 exit criterion: a leaked key is contained without waking anyone."""
    matching = call("playbook.list", ctx, {"case_uid": case})
    assert "contain_leaked_cloud_key" in [p["id"] for p in matching.data.playbooks]

    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": True},
    )
    assert run.data.state == "done", "containment does not wait for a human"
    detail = " ".join(run.data.detail).lower()
    assert "disable" in detail and "[dry run]" in detail
    assert "page" in detail, "a human is still told what happened"


def test_an_optional_l2_step_waits_for_a_human_but_the_rest_does_not(ctx, config, role_case):
    """RSP-6: the page goes out at once, the role's sessions wait for a human.

    Revoking a role's sessions can break production, so it needs approval, but
    it must not hold the rest of the response up either.
    """
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_workload_credentials", "case_uid": role_case, "dry_run": True},
    )
    assert run.data.state == "done"
    assert run.data.pending_approval, "the revocation must be left for a human to approve"
    assert "left for a human to approve" in " ".join(run.data.detail).lower()

    proposed = call("action.list", ctx, {"case_uid": role_case, "state": "proposed"})
    waiting = [r for r in proposed.data.rows if r["action_uid"] in run.data.pending_approval]
    assert waiting and waiting[0]["type"] == "aws.revoke_role_sessions"
    assert waiting[0]["autonomy"] == "L2"

    # And it is still there to approve once a human has looked at it.
    view = call("playbook.get", ctx, {"run_uid": run.data.run_uid})
    assert run.data.pending_approval[0] in view.data.pending_approval


def test_a_playbook_with_an_l2_step_stops_and_waits(ctx, okta_case, monkeypatch):
    book = a_step_that_waits(monkeypatch)
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": book, "case_uid": okta_case, "dry_run": True},
    )
    assert run.data.state == "waiting_approval", "suspending a person needs a human"
    assert run.data.waiting_on
    assert run.data.steps_done >= 2, "the reversible steps ran first"


def test_a_run_resumes_once_a_human_approves(ctx, okta_case, monkeypatch):
    book = a_step_that_waits(monkeypatch)
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": book, "case_uid": okta_case, "dry_run": True},
    )
    waiting = run.data.waiting_on
    assert waiting
    call("action.approve", ctx, {"action_uid": waiting})
    resumed = call("playbook.resume", ctx, {"run_uid": run.data.run_uid})
    assert resumed.data.state == "done"
    assert resumed.data.steps_done > run.data.steps_done


def cited(ctx, case_uid):
    row = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (ctx.tenant_id, case_uid),
    )
    assert row
    return list(row["event_uids"])


def test_a_case_ruled_benign_stops_its_waiting_run(ctx, config, okta_case, monkeypatch):
    book = a_step_that_waits(monkeypatch)
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": book, "case_uid": okta_case, "dry_run": True},
    )
    assert run.data.state == "waiting_approval"
    engine.set_verdict(
        ctx.db,
        config.tenant_id,
        okta_case,
        "benign_expected",
        0.9,
        "A help-desk reset.",
        cited(ctx, okta_case),
    )
    waiting = fetch_one(
        ctx.db, "SELECT state FROM shoc.actions WHERE action_uid = %s", (run.data.waiting_on,)
    )
    assert waiting and waiting["state"] == "rejected", "nobody approves a response to nothing"
    resumed = call("playbook.resume", ctx, {"run_uid": run.data.run_uid})
    assert resumed.data.state == "cancelled"


def test_a_run_queued_before_a_benign_verdict_does_nothing(ctx, config, case):
    engine.set_verdict(
        ctx.db, config.tenant_id, case, "false_positive", 0.9, "A test key.", cited(ctx, case)
    )
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": True},
    )
    assert run.data.state == "cancelled"
    assert run.data.steps_done == 0
    assert not call("action.list", ctx, {"case_uid": case}).data.rows


def test_a_run_is_started_only_once(ctx, case):
    first = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": True},
    )
    second = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": True},
    )
    assert first.data.run_uid == second.data.run_uid


def test_an_optional_step_with_no_target_is_skipped(ctx, case, config):
    # The leaked key belongs to an IAM user: the case names no role to revoke.
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_workload_credentials", "case_uid": case, "dry_run": True},
    )
    steps = playbooks.steps_of(ctx.db, run.data.run_uid)
    optional = [s for s in steps if s["name"] == "revoke the role's older sessions"]
    assert optional and optional[0]["state"] == "skipped"
    assert run.data.state == "done"


def test_the_policy_is_visible_to_anyone_who_can_read(ctx):
    view = call("policy.show", ctx, {})
    assert view.data.defaults["autonomy"] == "L2"
    assert "aws.disable_access_key" in view.data.available_actions
    assert "needs a human" in view.summary


def test_credentials_are_stored_encrypted_and_only_a_human_can_set_them(ctx, agent_ctx, config):
    with pytest.raises(Denied):
        call(
            "credential.configure", agent_ctx, {"provider": "aws", "secret": {"access_key_id": "x"}}
        )
    call(
        "credential.configure",
        ctx,
        {
            "provider": "aws",
            "settings": {"region": "eu-west-1"},
            "secret": {"access_key_id": "AKIAADMIN", "secret_access_key": "topsecret"},
            "verify": False,
        },
    )
    row = fetch_one(
        ctx.db,
        "SELECT secret FROM shoc.action_credentials WHERE tenant_id=%s AND provider=%s",
        (config.tenant_id, "aws"),
    )
    assert row and b"topsecret" not in bytes(row["secret"])


def test_actions_are_listed_with_what_they_wait_for(ctx, agent_ctx, case):
    call(
        "action.propose",
        agent_ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    listing = call("action.list", ctx, {"case_uid": case})
    assert listing.data.count >= 1 and listing.data.waiting_for_approval >= 1
    assert "waiting for a human" in listing.summary


def test_every_action_is_audited(ctx, agent_ctx, case):
    """The call and the change of state it caused, each under its principal (SEC-1)."""
    from shoc.db.audit import verify

    before = audit_seq(ctx.db, ctx.tenant_id)
    proposed = call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIA1", "user_name": "deploy-ci"},
            "case_uid": case,
        },
    )
    call("action.run", ctx, {"action_uid": proposed.data.action_uid, "dry_run": True})
    call("action.undo", ctx, {"action_uid": proposed.data.action_uid})
    ok, _count, detail = verify(ctx.db, ctx.tenant_id)
    assert ok, detail
    assert audit_trail(ctx.db, ctx.tenant_id, before) == [
        ("action.proposed", "agent:crew"),
        ("action.propose", "agent:crew"),
        ("action.started", "human:test"),
        ("action.executed", "human:test"),
        ("action.run", "human:test"),
        ("action.rolled_back", "human:test"),
        ("action.undo", "human:test"),
    ]


def test_a_worker_that_dies_mid_action_leaves_it_on_record(ctx, agent_ctx, case, monkeypatch):
    """The start is chained before the side effect, and a stuck run is raised (SEC-1, RSP-3)."""
    from shoc.agents import ops
    from shoc.cases import actions as action_store

    proposed = call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIA2", "user_name": "deploy-ci"},
            "case_uid": case,
        },
    )
    uid = proposed.data.action_uid

    def killed(*_args: object) -> None:
        raise SystemExit("worker killed")

    monkeypatch.setattr(action_store, "dry_run_result", killed)
    before = audit_seq(ctx.db, ctx.tenant_id)
    with pytest.raises(SystemExit):
        action_store.execute(ctx.db, ctx.tenant_id, uid, "", by="agent:worker")
    assert audit_trail(ctx.db, ctx.tenant_id, before) == [("action.started", "agent:worker")]
    assert not [a for a in ops.alerts(ctx.db, ctx.tenant_id) if a.kind == "action.stuck"]
    execute(
        ctx.db,
        "UPDATE shoc.actions SET updated_at = now() - interval '2 hours' WHERE action_uid = %s",
        (uid,),
    )
    assert [a.subject for a in ops.alerts(ctx.db, ctx.tenant_id) if a.kind == "action.stuck"] == [
        uid
    ]


def test_a_run_can_be_read_back_with_its_steps(ctx, okta_case, monkeypatch):
    """Reading a run must not require resuming it."""
    book = a_step_that_waits(monkeypatch)
    started = call(
        "playbook.run",
        ctx,
        {"playbook_id": book, "case_uid": okta_case, "dry_run": True},
    )
    read = call("playbook.get", ctx, {"run_uid": started.data.run_uid})
    assert read.data.run_uid == started.data.run_uid
    assert read.data.playbook_id == book
    assert read.data.state == "waiting_approval"
    assert read.data.waiting_on, "it says which action is blocking it"
    assert len(read.data.steps) == started.data.steps_total
    assert read.data.steps[0]["name"]


def test_reading_a_run_that_does_not_exist_is_not_found(ctx, config, clean):
    from shoc.errors import NotFound

    with pytest.raises(NotFound):
        call("playbook.get", ctx, {"run_uid": "RUN-nope"})
