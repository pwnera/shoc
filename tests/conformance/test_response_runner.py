"""The playbook runner and the action store when something goes wrong (RSP-2, RSP-4, RSP-5,
RSP-6, RSP-7).

Every test here is a run that used to raise, wait for ever or act on the wrong
thing: a step whose action failed, a worker that died mid-call, an approval that
never came, a job that was parked as failed.
"""

from __future__ import annotations

import pytest

from shoc.actions.base import ActionResult
from shoc.capabilities.registry import call
from shoc.cases import actions as action_store
from shoc.cases import engine, playbooks, unattended
from shoc.db.pool import execute, fetch_all, fetch_one
from tests.support import audit_seq, audit_trail, malicious_case

pytestmark = pytest.mark.postgres

KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key, used by deploy-ci


@pytest.fixture
def case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key")


@pytest.fixture
def okta_case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "okta_mfa_fatigue")


def _run(ctx, case_uid, playbook="contain_leaked_cloud_key"):
    return call(
        "playbook.run", ctx, {"playbook_id": playbook, "case_uid": case_uid, "dry_run": True}
    )


def _failing(monkeypatch, times: int):
    """The first `times` executions fail the way a vendor outage does."""
    real = action_store.dry_run_result
    left = [times]

    def flaky(action, params):
        if left[0] > 0:
            left[0] -= 1
            return ActionResult(ok=False, detail="IAM answered 503")
        return real(action, params)

    monkeypatch.setattr(action_store, "dry_run_result", flaky)


def _resume_jobs(conn, run_uid):
    return fetch_all(
        conn,
        """SELECT run_at > now() AS later FROM shoc.jobs
           WHERE kind = 'playbook.resume' AND payload->>'run_uid' = %s""",
        (run_uid,),
    )


# -- RSP-2: retries, timers, and what a resume finds ---------------------------
def test_a_failed_step_is_tried_again_later_and_then_succeeds(ctx, conn, case, monkeypatch):
    _failing(monkeypatch, 1)
    first = _run(ctx, case)
    assert first.data.state == "waiting_timer", "a vendor error is not the end of the run"
    assert [j["later"] for j in _resume_jobs(conn, first.data.run_uid)] == [True]
    before = audit_seq(conn, ctx.tenant_id)
    again = call("playbook.resume", ctx, {"run_uid": first.data.run_uid})
    assert again.data.state == "done"
    assert ("action.retried", "service:playbook-runner") in audit_trail(conn, ctx.tenant_id, before)


def test_a_step_out_of_retries_fails_the_run_instead_of_raising(ctx, conn, case, monkeypatch):
    _failing(monkeypatch, 10)
    run = _run(ctx, case)
    for _ in range(playbooks.RETRIES):
        assert run.data.state == "waiting_timer"
        run = call("playbook.resume", ctx, {"run_uid": run.data.run_uid})
    assert run.data.state == "failed"
    # And resuming a failed run is a no-op, not an exception.
    assert call("playbook.resume", ctx, {"run_uid": run.data.run_uid}).data.state == "failed"


def test_a_timer_step_parks_the_run_until_its_time(ctx, conn, config, case, monkeypatch):
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
    run = playbooks.start(conn, config.tenant_id, "wait_then_page", case, config, dry_run=True)
    report = playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config)
    assert report.state == "waiting_timer" and report.steps_done == 0
    assert [j["later"] for j in _resume_jobs(conn, run["run_uid"])] == [True]
    assert playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config).state == (
        "waiting_timer"
    ), "a resume before the time keeps waiting"
    execute(
        conn,
        "UPDATE shoc.playbook_steps SET started_at = now() - interval '16 minutes' "
        "WHERE run_uid = %s AND step_index = 0",
        (run["run_uid"],),
    )
    assert playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config).state == "done"


def test_a_step_a_dead_worker_left_running_is_tried_again(ctx, conn, case, monkeypatch):
    def killed(*_args: object) -> None:
        raise SystemExit("worker killed")

    with monkeypatch.context() as patch:
        patch.setattr(action_store, "dry_run_result", killed)
        with pytest.raises(SystemExit):
            _run(ctx, case)
    run = fetch_one(conn, "SELECT run_uid FROM shoc.playbook_runs WHERE case_uid = %s", (case,))
    assert run
    # Still inside its call as far as anybody knows: a resume leaves it alone.
    assert call("playbook.resume", ctx, {"run_uid": run["run_uid"]}).data.state == "running"
    execute(
        conn,
        "UPDATE shoc.actions SET updated_at = now() - interval '1 hour' "
        "WHERE case_uid = %s AND state = 'running'",
        (case,),
    )
    assert call("playbook.resume", ctx, {"run_uid": run["run_uid"]}).data.state == "done"


def test_a_step_somebody_undid_cancels_the_run_rather_than_raising(ctx, conn, case):
    proposed = call(
        "action.propose",
        ctx,
        {
            "action": "aws.disable_access_key",
            "case_uid": case,
            "params": {"access_key_id": KEY, "user_name": "deploy-ci"},
        },
    )
    uid = proposed.data.action_uid
    call("action.approve", ctx, {"action_uid": uid})
    call("action.run", ctx, {"action_uid": uid})
    call("action.undo", ctx, {"action_uid": uid})
    run = _run(ctx, case)
    assert run.data.state == "cancelled" and "undone" in " ".join(run.data.detail)


def test_a_run_whose_job_was_lost_is_picked_up_and_then_given_up(ctx, conn, config, case):
    from shoc import worker

    run = _run(ctx, case)
    execute(
        conn,
        "UPDATE shoc.playbook_runs SET state = 'running', updated_at = now() - "
        "interval '1 hour' WHERE run_uid = %s",
        (run.data.run_uid,),
    )
    execute(conn, "DELETE FROM shoc.jobs")
    worker.resume_waiting_runs(conn)
    assert len(_resume_jobs(conn, run.data.run_uid)) == 1
    execute(
        conn,
        "UPDATE shoc.jobs SET state = 'failed', last_error = 'boom' WHERE kind = 'playbook.resume'",
    )
    worker.resume_waiting_runs(conn)
    execute(conn, "UPDATE shoc.jobs SET state = 'failed' WHERE kind = 'playbook.resume'")
    worker.resume_waiting_runs(conn)
    row = fetch_one(
        conn, "SELECT state, error FROM shoc.playbook_runs WHERE run_uid = %s", (run.data.run_uid,)
    )
    assert row and row["state"] == "failed" and "failed 2 times" in row["error"]


# -- RSP-4: a failed crew action is not the playbook's -------------------------
def test_the_playbook_does_not_reuse_a_failed_crew_action(ctx, conn, config, case, monkeypatch):
    taken = action_store.from_crew(
        conn,
        config.tenant_id,
        case,
        [action_store.CrewProposal("aws.disable_access_key", KEY, "leaked")],
        config=config,
    )[0]
    assert taken.state == "approved", taken.error
    row = action_store.require(conn, config.tenant_id, taken.action_uid)
    assert row["params"]["user_name"] == "deploy-ci", "the key's user comes from the evidence"
    _failing(monkeypatch, 1)
    action_store.execute(conn, config.tenant_id, taken.action_uid, "", by="agent:worker")
    assert action_store.require(conn, config.tenant_id, taken.action_uid)["state"] == "failed"
    run = _run(ctx, case)
    assert run.data.state == "done", "the step proposes it again instead of raising"


def test_a_key_whose_user_cannot_be_found_is_refused(ctx, conn, config, case):
    taken = action_store.from_crew(
        conn,
        config.tenant_id,
        case,
        [action_store.CrewProposal("aws.disable_access_key", "AKIANOBODYKNOWS0000", "leaked")],
        config=config,
    )[0]
    assert not taken.action_uid and "user_name" in taken.error


# -- RSP-7: approvals that never come, and approvals that do ---------------------
def test_an_expired_l2_step_skips_instead_of_cancelling_the_run(
    ctx, conn, config, okta_case, monkeypatch
):
    book = playbooks.Playbook.from_dict(
        {
            "id": "suspend_then_page",
            "title": "Suspend, then page",
            "rules": ["x"],
            "steps": [
                {
                    "name": "suspend the account",
                    "action": "okta.suspend_user",
                    "params": {"user": "{{ entity.user }}"},
                },
                {"name": "page", "action": "notify.page", "params": {"summary": "still here"}},
            ],
        }
    )
    monkeypatch.setattr(playbooks, "get", lambda playbook_id, *rest: book)
    engine.set_severity(conn, config.tenant_id, okta_case, "medium", "for this test")
    run = _run(ctx, okta_case, "suspend_then_page")
    assert run.data.state == "waiting_approval"
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 minute' WHERE action_uid = %s",
        (run.data.waiting_on,),
    )
    assert unattended.run(conn, config.tenant_id, config).abandoned == [run.data.waiting_on]
    resumed = call("playbook.resume", ctx, {"run_uid": run.data.run_uid})
    assert resumed.data.state != "cancelled"
    assert "nobody approved it in time" in " ".join(resumed.data.detail)


def test_an_approved_optional_step_is_run_by_the_worker(ctx, conn, config, clean):
    from shoc import worker

    # The role behind a session key, which only a human may revoke.
    case = malicious_case(ctx.db, config.tenant_id, "aws_session_key_two_users")
    run = _run(ctx, case, "contain_workload_credentials")
    (left,) = run.data.pending_approval
    call("action.approve", ctx, {"action_uid": left})
    execute(conn, "DELETE FROM shoc.jobs")
    assert worker.run_approved_actions(conn) == 1
    jobs = fetch_all(conn, "SELECT payload FROM shoc.jobs WHERE kind = 'action.run'")
    assert [j["payload"]["action_uid"] for j in jobs] == [left]


def test_asking_again_keeps_the_window_and_the_approval(ctx, conn, config, case):
    def propose():
        return action_store.propose(
            conn,
            config.tenant_id,
            action_store.Proposal(
                "aws.revoke_role_sessions", {"role_name": "deploy"}, case_uid=case
            ),
            "IR Commander",
            principal_kind="agent",
            config=config,
        )

    first = propose()
    assert first["state"] == "proposed"
    assert propose()["decide_by"] == first["decide_by"], "asking again restarts nothing"
    action_store.approve(conn, config.tenant_id, first["action_uid"], "rettila", "human")
    assert propose()["state"] == "approved", "asking again never undoes an approval"


def test_an_action_whose_job_failed_can_be_queued_again(ctx, conn, config, case):
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal("notify.page", {"summary": "x"}, case_uid=case),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    execute(conn, "DELETE FROM shoc.jobs")
    uid = row["action_uid"]
    assert action_store.queue_run(conn, config.tenant_id, uid)
    assert not action_store.queue_run(conn, config.tenant_id, uid), "never queued twice at once"
    for _ in range(action_store.RUN_JOBS):
        execute(
            conn,
            "UPDATE shoc.jobs SET state = 'failed' WHERE kind = 'action.run' AND state = 'pending'",
        )
        action_store.queue_run(conn, config.tenant_id, uid)
    parked = fetch_all(conn, "SELECT state FROM shoc.jobs WHERE kind = 'action.run'")
    assert [p["state"] for p in parked] == ["failed"] * action_store.RUN_JOBS, (
        "after RUN_JOBS parked jobs the worker stops trying"
    )


# -- RSP-4: a block with a lifetime is lifted ------------------------------------
def test_a_block_is_undone_when_its_ttl_runs_out(ctx, conn, config, monkeypatch):
    from shoc import worker
    from shoc.detect import osint

    monkeypatch.setattr(osint, "research_target", lambda *a, **k: None)
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal("cloudflare.block_ip", {"ip": "203.0.113.9"}),
        "human:rettila",
        principal_kind="human",
        config=config,
    )
    assert row["params"]["ttl_minutes"] == 120, "the policy's ttl travels with the action"
    action_store.approve(conn, config.tenant_id, row["action_uid"], "rettila", "human")
    action_store.execute(conn, config.tenant_id, row["action_uid"], "", by="human:rettila")
    job = fetch_one(
        conn,
        """SELECT run_at > now() + interval '119 minutes' AS later
                             FROM shoc.jobs WHERE kind = 'action.expire'""",
    )
    assert job and job["later"]
    summary = worker.handle(
        {
            "tenant_id": config.tenant_id,
            "kind": "action.expire",
            "payload": {"action_uid": row["action_uid"]},
        },
        config,
    )
    assert "expired" in summary
    assert action_store.require(conn, config.tenant_id, row["action_uid"])["state"] == (
        "rolled_back"
    )


# -- RSP-5, RSP-6: decide() through research and review ---------------------------
def test_decide_researches_a_hash_and_reviews_the_block(ctx, conn, config, case, monkeypatch):
    from shoc.cases import review as peer_review
    from shoc.cases.policy import Review
    from shoc.detect import osint

    asked: list[tuple[str, str]] = []

    def research(conn, store, tenant_id, kind, target, **kw):
        asked.append((kind, target))
        return osint.Research(value=target, type="sha256", verdict="malicious")

    monkeypatch.setattr(osint, "research_target", research)
    monkeypatch.setattr(
        peer_review,
        "review_action",
        lambda *a, **k: Review(
            done=True, approved=False, reason="IR Commander: it is the company's backup agent"
        ),
    )
    digest = "b" * 64
    decision, _ = action_store.decide(
        conn,
        config.tenant_id,
        action_store.Proposal("crowdstrike.block_hash", {"hash": digest}),
        "human",
        config,
    )
    assert asked == [("hash", digest)], "a hash is researched like an address"
    assert decision.needs_approval and "backup agent" in decision.reason, (
        "an objection reaches the human deciding an L2"
    )
    assert "review" in decision.escalated_by


def test_our_own_recorded_address_counts_as_known_egress(ctx, conn, config, monkeypatch):
    from shoc.cases import own
    from shoc.detect import osint

    monkeypatch.setattr(
        osint,
        "research_target",
        lambda *a, **k: osint.Research(value="198.51.100.20", type="ip", verdict="malicious"),
    )
    own.register(conn, config.tenant_id, "address", "198.51.100.20", source="test")
    decision, _ = action_store.decide(
        conn,
        config.tenant_id,
        action_store.Proposal("cloudflare.block_ip", {"ip": "198.51.100.20"}),
        "human",
        config,
    )
    assert "our own known egress" in decision.reason
