"""The worker: schedules, job handling, retries and the cron leader."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from shoc import worker
from shoc.db import jobs
from shoc.db.pool import execute, fetch_all, fetch_one

pytestmark = pytest.mark.postgres


@pytest.fixture(autouse=True)
def queue(conn, config, clean):
    """The queue is shared across tenants, so these tests own the whole of it.

    The session's config is shared too: a test that gives the crew a provider
    hands the next one the provider it found.
    """
    provider = config.llm_provider
    execute(conn, "DELETE FROM shoc.jobs")
    execute(conn, "DELETE FROM shoc.schedules")
    yield
    config.llm_provider = provider
    execute(conn, "DELETE FROM shoc.jobs")
    execute(conn, "DELETE FROM shoc.schedules")


def test_default_schedules_cover_the_whole_cycle(conn, config):
    worker.ensure_default_schedules(conn, config)
    kinds = {
        r["kind"]: r["interval_seconds"]
        for r in fetch_all(
            conn,
            "SELECT kind, interval_seconds FROM shoc.schedules WHERE tenant_id = %s",
            (config.tenant_id,),
        )
    }
    assert kinds["detect.run"] == 300
    assert kinds["retention"] == 86400
    assert kinds["intel.refresh"] == 21600
    assert "ops.check" in kinds and "graph.refresh" in kinds
    assert "report.shift" not in kinds, "the shift report is gone (D52, RFC 0015)"
    assert kinds["case.sweep"] == 900, "an unworked case must be picked up again"
    assert kinds["case.recheck"] == 604800, "what the crew closed as nothing is read again"
    assert kinds["report.exec"] == 2592000, "the executive report goes out every 30 days (AGT-14)"


def test_the_sweep_sends_the_crew_back_at_a_case_nobody_worked(conn, ctx, store, config, clean):
    """A failed investigation used to be final: the job key never changed again."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        conn, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row
    case_uid = row["case_uid"]
    execute(
        conn,
        "UPDATE shoc.cases SET tokens_used = 0, worked_at = NULL WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, case_uid),
    )
    execute(conn, "DELETE FROM shoc.jobs")

    config.llm_provider = "openai"  # a crew to send; the sweep is a no-op without one
    assert "queued 1" in worker._sweep_cases(ctx)
    queued = fetch_all(
        conn,
        "SELECT payload FROM shoc.jobs WHERE tenant_id = %s AND kind = 'case.investigate'",
        (config.tenant_id,),
    )
    assert [q["payload"]["case_uid"] for q in queued] == [case_uid]


def test_the_sweep_is_not_silenced_by_the_jobs_it_queued_before(conn, ctx, store, config, clean):
    """Attempt numbers reset every hour, so keying jobs on them reused a key the
    case had already spent, and the insert did nothing without saying so."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        conn, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row
    execute(conn, "DELETE FROM shoc.jobs")
    config.llm_provider = "openai"
    for _ in range(2):
        execute(
            conn,
            """UPDATE shoc.cases SET worked_at = NULL, crew_attempts = 0,
                      crew_attempted_at = now() - interval '2 hours'
               WHERE tenant_id = %s AND case_uid = %s""",
            (config.tenant_id, row["case_uid"]),
        )
        assert "queued 1" in worker._sweep_cases(ctx)
    queued = fetch_all(
        conn,
        "SELECT 1 FROM shoc.jobs WHERE tenant_id = %s AND kind = 'case.investigate'",
        (config.tenant_id,),
    )
    assert len(queued) == 2, "the second sweep queued nothing"


def _failed_tries(conn, config, store, tries: int, ago: str) -> str:
    """One case from the replay, whose last `tries` crew runs never came back."""
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        conn, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row
    execute(
        conn,
        f"""UPDATE shoc.cases
            SET tokens_used = 0, worked_at = NULL, crew_attempts = %s,
                crew_attempted_at = now() - interval '{ago}'
            WHERE tenant_id = %s AND case_uid = %s""",
        (tries, config.tenant_id, row["case_uid"]),
    )
    execute(conn, "DELETE FROM shoc.jobs")
    config.llm_provider = "openai"
    return str(row["case_uid"])


def test_the_sweep_waits_after_a_failed_try(conn, ctx, store, config, clean):
    # Attempts are counted on the case, not by counting messages: the tries are
    # remembered without writing anything into the record they describe.
    _failed_tries(conn, config, store, 1, "1 minute")
    assert "queued 0" in worker._sweep_cases(ctx)


def test_the_sweep_tries_again_once_the_wait_has_passed(conn, ctx, store, config, clean):
    """Tries spent on an outage slow the crew down; they never retire the case."""
    case_uid = _failed_tries(conn, config, store, 20, "4 days")
    assert "queued 1" in worker._sweep_cases(ctx)
    after = fetch_one(
        conn,
        "SELECT crew_attempts FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, case_uid),
    )
    assert after and after["crew_attempts"] == 21


def test_a_run_the_crew_finished_restarts_the_count(conn, ctx, store, config, clean):
    case_uid = _failed_tries(conn, config, store, 20, "1 minute")
    # The crew spoke after the last try, and a finding arrived after that.
    execute(
        conn,
        """UPDATE shoc.cases SET worked_at = now() - interval '30 seconds'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case_uid),
    )
    execute(
        conn,
        "UPDATE shoc.findings SET created_at = now() WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, case_uid),
    )
    assert "queued 1" in worker._sweep_cases(ctx)


def test_a_message_posted_while_the_crew_talked_brings_it_back(conn, ctx, store, config, clean):
    """The crew reads the transcript once, when the run starts. Stamping
    `worked_at` at the end of the run marked a message it never read as seen."""
    from shoc.agents import loop
    from shoc.agents.openspace import Message, post

    case_uid = _failed_tries(conn, config, store, 0, "10 minutes")
    started = datetime.now(UTC)
    post(
        conn,
        store,
        config.tenant_id,
        case_uid,
        Message(
            agent="human:ana",
            kind="inject",
            body="this is legit, it's me",
            principal="human",
        ),
    )
    loop._worked(conn, config.tenant_id, case_uid, started)
    assert "queued 1" in worker._sweep_cases(ctx)


def _worked_case(conn, config, store) -> str:
    """A case the crew worked a minute ago and that nothing has touched since."""
    case_uid = _failed_tries(conn, config, store, 0, "10 minutes")
    execute(
        conn,
        """UPDATE shoc.cases SET worked_at = now() - interval '1 minute'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case_uid),
    )
    execute(
        conn,
        """UPDATE shoc.findings SET created_at = now() - interval '1 hour'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case_uid),
    )
    return case_uid


def test_a_worked_case_with_nothing_new_is_left_alone(conn, ctx, store, config, clean):
    _worked_case(conn, config, store)
    assert "queued 0" in worker._sweep_cases(ctx)


def test_an_injected_fact_brings_a_worked_case_back(conn, ctx, store, config, clean):
    """An external agent's inject, not only a person's message (AGT-12)."""
    from shoc.agents.openspace import Message, post

    case_uid = _worked_case(conn, config, store)
    post(
        conn,
        store,
        config.tenant_id,
        case_uid,
        Message(
            agent="external_agent:edr",
            kind="inject",
            body="The host was reimaged at 09:12.",
            principal="external_agent",
        ),
    )
    assert "queued 1" in worker._sweep_cases(ctx)


@pytest.mark.parametrize(
    "kind, state, by, back",
    [
        ("aws.disable_access_key", "done", None, 1),
        ("aws.disable_access_key", "failed", None, 1),
        ("aws.disable_access_key", "approved", None, 0),
        ("aws.disable_access_key", "rejected", "human:alice", 1),
        ("aws.disable_access_key", "rejected", "unattended", 0),
        ("notify.slack", "done", None, 0),
    ],
)
def test_a_finished_action_brings_a_worked_case_back(
    conn, ctx, store, config, clean, kind, state, by, back
):
    """A containment that ended or a person turned down is news to the crew; a page it
    sent is not, and neither is a timeout it was already told about (AGT-12)."""
    case_uid = _worked_case(conn, config, store)
    execute(
        conn,
        """INSERT INTO shoc.actions
             (action_uid, tenant_id, case_uid, type, target, state, approved_by)
           VALUES (%s, %s, %s, %s, 'AKIAIOSFODNN7EXAMPLE', %s, %s)""",
        (f"ACT-{kind}-{state}-{by}", config.tenant_id, case_uid, kind, state, by),
    )
    assert f"queued {back}" in worker._sweep_cases(ctx)


def test_the_sweep_does_nothing_without_a_model(conn, ctx, store, config, clean):
    config.llm_provider = "none"
    assert "nobody to send" in worker._sweep_cases(ctx)


def test_the_sweep_stands_down_while_the_provider_is_failing(conn, ctx, store, config, clean):
    """Every try during an outage fails the same way, so none is made."""
    from shoc.agents import ops

    config.llm_provider = "openai"
    ops.record_failure(conn, config.tenant_id, "gemini-3-pro", "returned no completion: code 500")
    summary = worker._sweep_cases(ctx)
    assert "provider is failing" in summary and "code 500" in summary


def test_a_due_schedule_becomes_exactly_one_job(conn, config):
    jobs.upsert_schedule(conn, f"{config.tenant_id}:t", config.tenant_id, "detect.run", 300, {})
    assert jobs.tick(conn) >= 1

    # Ticking again before it is due must not queue a second copy.
    def queued() -> int:
        row = fetch_one(
            conn, "SELECT count(*) AS n FROM shoc.jobs WHERE tenant_id = %s", (config.tenant_id,)
        )
        assert row
        return int(row["n"])

    before = queued()
    jobs.tick(conn)
    assert queued() == before


def test_an_idempotency_key_collapses_duplicates(conn, config, clean):
    first = jobs.enqueue(conn, config.tenant_id, "detect.run", {}, idempotency_key="same")
    second = jobs.enqueue(conn, config.tenant_id, "detect.run", {}, idempotency_key="same")
    assert first and second is None


def test_claiming_marks_the_job_running_and_records_the_worker(conn, config, clean):
    jobs.enqueue(conn, config.tenant_id, "detect.run", {})
    claimed = jobs.claim(conn, 5)
    assert len(claimed) == 1
    row = fetch_one(
        conn, "SELECT state, locked_by FROM shoc.jobs WHERE job_id = %s", (claimed[0]["job_id"],)
    )
    assert row and row["state"] == "running"
    assert row["locked_by"] == jobs.WORKER_ID


def test_a_failure_is_retried_with_backoff_then_parked(conn, config, clean):
    job_id = jobs.enqueue(conn, config.tenant_id, "detect.run", {})
    assert job_id

    def state() -> dict:
        row = fetch_one(
            conn, "SELECT state, attempts, run_at FROM shoc.jobs WHERE job_id=%s", (job_id,)
        )
        assert row
        return row

    for attempt in range(1, 4):
        jobs.claim(conn, 1)
        jobs.fail(conn, job_id, "boom", max_attempts=3)
        row = state()
        if attempt < 3:
            assert row["state"] == "pending", "retried"
            assert row["run_at"] > datetime.now(UTC), "with backoff"
            execute(conn, "UPDATE shoc.jobs SET run_at = now() WHERE job_id = %s", (job_id,))
    assert state()["state"] == "failed", "and parked after the last attempt"


def test_a_stale_running_job_is_requeued(conn, config, clean):
    job_id = jobs.enqueue(conn, config.tenant_id, "detect.run", {})
    jobs.claim(conn, 1)
    execute(
        conn,
        "UPDATE shoc.jobs SET locked_at = now() - interval '1 hour' WHERE job_id = %s",
        (job_id,),
    )
    assert jobs.requeue_stale(conn, timedelta(minutes=15)) == 1
    row = fetch_one(conn, "SELECT state FROM shoc.jobs WHERE job_id=%s", (job_id,))
    assert row and row["state"] == "pending"


def test_only_one_worker_becomes_the_cron_leader(conn, config):
    import psycopg
    from psycopg.rows import DictRow, dict_row

    assert jobs.become_cron_leader(conn) in (True, False)
    other: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        config.dsn, row_factory=dict_row, autocommit=True
    )
    try:
        first = jobs.become_cron_leader(conn)
        second = jobs.become_cron_leader(other)
        assert not (first and second), "the advisory lock must be exclusive"
    finally:
        other.close()


def test_a_follower_takes_over_when_the_cron_leader_goes_away(conn, config, monkeypatch):
    """A worker that started behind a live leader used to stay a follower for life.

    After a rolling update or a killed leader pod, no schedule fired again.
    """
    import threading

    import psycopg
    from psycopg.rows import DictRow, dict_row

    from shoc.db import pool

    monkeypatch.setattr(worker, "handle", lambda job, cfg: "skipped")
    # Earlier tests may hold the lock on the fixture's or this thread's session.
    execute(conn, "SELECT pg_advisory_unlock_all()")
    pool.close()
    old_leader: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        config.dsn, row_factory=dict_row, autocommit=True
    )
    assert jobs.become_cron_leader(old_leader)
    schedule_id = f"{config.tenant_id}:failover"
    jobs.upsert_schedule(conn, schedule_id, config.tenant_id, "detect.run", 300, {})

    def ticked() -> bool:
        row = fetch_one(
            conn,
            "SELECT next_run_at > now() AS ticked FROM shoc.schedules WHERE schedule_id = %s",
            (schedule_id,),
        )
        return bool(row and row["ticked"])

    def follower() -> None:
        try:
            worker.run(config, poll_seconds=0.1, stop=stop)
        finally:
            pool.close()  # release the lock with the thread's session

    stop = threading.Event()
    thread = threading.Thread(target=follower)
    thread.start()
    try:
        time.sleep(1.5)
        assert not ticked(), "only the leader ticks"
        old_leader.close()
        deadline = time.time() + 20
        while time.time() < deadline and not ticked():
            time.sleep(0.2)
        assert ticked(), "the follower took over once the leader's session ended"
    finally:
        stop.set()
        thread.join(timeout=10)
        old_leader.close()
    assert not thread.is_alive()


def test_the_server_gives_up_on_a_lost_cron_leader_within_minutes(conn, config):
    """Nothing closes the session of a node that is lost or cut off.

    With Linux defaults the server kept its backend, and the cron lock, for
    about two hours of TCP keepalive.
    """
    import psycopg
    from psycopg.rows import DictRow, dict_row

    execute(conn, "SELECT pg_advisory_unlock_all()")
    leader: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        config.dsn, row_factory=dict_row, autocommit=True
    )
    try:
        socket = fetch_one(leader, "SELECT inet_client_addr() IS NULL AS local")
        if socket and socket["local"]:
            pytest.skip("keepalive applies to TCP sessions only")
        assert jobs.become_cron_leader(leader)
        settings = {
            r["name"]: r["setting"]
            for r in fetch_all(
                leader,
                """SELECT name, setting FROM pg_settings WHERE name IN
                   ('tcp_keepalives_idle', 'tcp_keepalives_interval',
                    'tcp_keepalives_count', 'tcp_user_timeout')""",
            )
        }
        assert settings == {
            "tcp_keepalives_idle": "60",
            "tcp_keepalives_interval": "10",
            "tcp_keepalives_count": "3",
            "tcp_user_timeout": "90000",
        }
    finally:
        leader.close()


def test_a_hung_worker_exits_so_its_cron_lock_frees(conn, config, monkeypatch):
    """A leader stuck in one job held the lock for good, and no schedule fired again."""
    import os
    import threading

    from shoc.db import pool

    exited = threading.Event()
    release = threading.Event()
    stop = threading.Event()

    def stuck(job: dict, cfg: object) -> str:
        release.wait(30)
        return "stuck"

    def fake_exit(code: int) -> None:
        assert code
        exited.set()
        stop.set()
        release.set()

    monkeypatch.setattr(worker, "handle", stuck)
    monkeypatch.setattr(worker, "ensure_default_schedules", lambda *_: None)
    monkeypatch.setattr(worker, "HUNG_AFTER_SECONDS", 1.0)
    monkeypatch.setattr(os, "_exit", fake_exit)
    jobs.enqueue(conn, config.tenant_id, "detect.run", {})

    def run() -> None:
        try:
            worker.run(config, poll_seconds=0.1, stop=stop)
        finally:
            pool.close()  # release the lock with the thread's session

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert exited.wait(15), "a worker whose loop stopped coming round must exit"
    finally:
        stop.set()
        release.set()
        thread.join(timeout=10)
    assert not thread.is_alive()


def test_the_worker_runs_a_detection_job_end_to_end(conn, store, config, clean, ctx):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    # Forget both the findings and the rule watermarks, so the worker's cycle
    # really re-detects rather than looking at an already-consumed window.
    execute(conn, "DELETE FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,))
    execute(conn, "DELETE FROM shoc.rule_state WHERE tenant_id = %s", (config.tenant_id,))
    jobs.enqueue(conn, config.tenant_id, "detect.run", {"lookback": "1h"})
    processed = worker.run(config, once=True)
    assert processed >= 1
    found = fetch_one(
        conn, "SELECT count(*) AS n FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert found and found["n"] >= 5


def test_a_queued_job_wakes_an_idle_worker(conn, config, clean, monkeypatch):
    """`enqueue` sends a NOTIFY; the worker used to sleep through it and poll (AGT-1)."""
    import threading

    from shoc.db import pool

    done = threading.Event()

    def handled(job, cfg):
        if job["kind"] == "detect.run":
            done.set()
        return "ok"

    monkeypatch.setattr(worker, "handle", handled)
    monkeypatch.setattr(worker, "ensure_default_schedules", lambda conn, cfg: None)
    stop = threading.Event()

    def idle() -> None:
        try:
            worker.run(config, poll_seconds=120, stop=stop)
        finally:
            pool.close()

    thread = threading.Thread(target=idle)
    thread.start()
    try:
        time.sleep(1.5)  # past its first, empty pass: it is waiting now
        jobs.enqueue(conn, config.tenant_id, "detect.run", {})
        assert done.wait(10), "a NOTIFY must wake the worker long before its 120 s poll"
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive(), "a stop is honoured within the wait, not after it"


def test_an_unknown_job_kind_fails_loudly(config, conn, clean):
    with pytest.raises(ValueError, match="unknown job kind"):
        worker.handle(
            {"tenant_id": config.tenant_id, "kind": "mow.the.lawn", "payload": {}}, config
        )


def test_a_broken_job_does_not_stop_the_worker(conn, store, config, clean, monkeypatch):
    # This worker may be the cron leader; keep the default schedules out of the count.
    monkeypatch.setattr(worker, "ensure_default_schedules", lambda *_: None)
    jobs.enqueue(conn, config.tenant_id, "mow.the.lawn", {})
    jobs.enqueue(conn, config.tenant_id, "detect.run", {"lookback": "1h"})
    assert worker.run(config, once=True) == 2
    states = {
        r["kind"]: r["state"]
        for r in fetch_all(
            conn, "SELECT kind, state FROM shoc.jobs WHERE tenant_id = %s", (config.tenant_id,)
        )
    }
    assert states["mow.the.lawn"] == "pending", "retried, not fatal"
    assert states["detect.run"] == "done"


def test_a_failed_job_hands_the_queue_back_to_every_tenant(conn, store, config, clean, monkeypatch):
    """A job pins the worker's connection to its tenant (SEC-1); failing must unpin it."""
    from shoc.db.pool import ALL_TENANTS, connect, current_tenant

    # This worker becomes the cron leader; keep the default schedules out of the count.
    monkeypatch.setattr(worker, "ensure_default_schedules", lambda *_: None)
    jobs.enqueue(conn, config.tenant_id, "action.run", {"action_uid": "A-nope"})
    assert worker.run(config, once=True) == 1
    assert current_tenant(connect(config)) == ALL_TENANTS


def test_investigations_are_not_queued_without_an_llm(conn, store, config, clean, ctx):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    jobs.enqueue(conn, config.tenant_id, "detect.run", {"lookback": "1h"})
    worker.run(config, once=True)
    queued = fetch_all(
        conn,
        "SELECT kind FROM shoc.jobs WHERE tenant_id = %s AND kind = 'case.investigate'",
        (config.tenant_id,),
    )
    assert queued == [], "with SHOC_LLM_PROVIDER=none the crew is never queued"


def test_a_waiting_run_is_nudged_once_its_action_is_approved(
    conn, store, config, clean, ctx, monkeypatch
):
    from shoc.capabilities.registry import call
    from tests.support import a_step_that_waits, malicious_case

    case = malicious_case(conn, config.tenant_id, "okta_mfa_fatigue", store)
    book = a_step_that_waits(monkeypatch)
    run = call(
        "playbook.run",
        ctx,
        {"playbook_id": book, "case_uid": case, "dry_run": True},
    )
    assert run.data.state == "waiting_approval"
    assert worker.resume_waiting_runs(conn) == 0, "nothing approved yet"
    call("action.approve", ctx, {"action_uid": run.data.waiting_on})
    assert worker.resume_waiting_runs(conn) == 1
    kinds = [
        json.loads(json.dumps(r["payload"]))
        for r in fetch_all(
            conn,
            "SELECT payload FROM shoc.jobs WHERE tenant_id=%s AND kind='playbook.resume'",
            (config.tenant_id,),
        )
    ]
    assert kinds and kinds[0]["run_uid"] == run.data.run_uid


def test_the_worker_may_call_every_capability_it_schedules():
    """The bug this catches: a scheduled job the worker's own scopes forbid."""
    from shoc.capabilities.registry import get
    from shoc.worker import JOB_CAPABILITIES, SYSTEM_CALLER, SYSTEM_JOBS, WORKER_CALLER

    for kind, capability in JOB_CAPABILITIES.items():
        if not capability:
            continue
        cap = get(capability)
        caller = SYSTEM_CALLER if kind in SYSTEM_JOBS else WORKER_CALLER
        assert caller.kind in cap.principals, f"{kind}: worker is not an allowed principal"
        assert caller.allows(cap.scope), f"{kind}: worker lacks scope '{cap.scope}'"


def test_the_jobs_that_act_unattended_run_a_capability():
    """API-1: these five ran in-process, so nothing checked or audited them."""
    from shoc.worker import JOB_CAPABILITIES, SYSTEM_JOBS

    for kind in ("action.run", "stream.deliver", "manager.deliver", "unattended", "retention"):
        assert JOB_CAPABILITIES[kind] and kind in SYSTEM_JOBS, kind


def test_the_worker_cannot_approve_its_own_actions():
    from shoc.capabilities.registry import get
    from shoc.worker import SYSTEM_CALLER, WORKER_CALLER

    approve = get("action.approve")
    for caller in (WORKER_CALLER, SYSTEM_CALLER):
        assert caller.kind not in approve.principals
        assert not caller.allows(approve.scope)


def test_the_workers_own_jobs_are_audited_calls(conn, store, config, clean):
    from tests.support import audit_seq

    before = audit_seq(conn, config.tenant_id)
    for kind in (
        "stream.deliver",
        "manager.deliver",
        "unattended",
        "retention",
        "report.weekly",
        "report.exec",
    ):
        worker.handle({"tenant_id": config.tenant_id, "kind": kind, "payload": {}}, config)
    rows = fetch_all(
        conn,
        """SELECT capability, principal_kind || ':' || principal_id AS who FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s ORDER BY seq""",
        (config.tenant_id, before),
    )
    assert [(r["capability"], r["who"]) for r in rows] == [
        ("stream.deliver", "service:worker"),
        ("manager.deliver", "service:worker"),
        ("case.chase", "service:worker"),
        ("events.retain", "service:worker"),
        ("report.send", "service:worker"),
        ("report.send", "service:worker"),
    ]
    sent = fetch_all(
        conn,
        "SELECT payload->>'kind' AS kind FROM shoc.stream_events WHERE tenant_id = %s "
        "AND type = 'report.ready' ORDER BY seq",
        (config.tenant_id,),
    )
    assert [r["kind"] for r in sent] == ["weekly", "exec"]


def test_every_tenant_is_scheduled_even_one_migrated_while_the_worker_runs(
    conn, config, monkeypatch
):
    """API-1: only SHOC_TENANT had schedules, so another tenant's events sat undetected."""
    import threading

    from shoc.db import pool

    other, later = f"{config.tenant_id}b", f"{config.tenant_id}c"

    def register(tenant: str) -> None:
        execute(
            conn,
            """INSERT INTO shoc.tenants (tenant_id, name, schema_name) VALUES (%s, %s, %s)
               ON CONFLICT DO NOTHING""",
            (tenant, tenant, config.tenant_schema(tenant)),
        )

    def scheduled(tenant: str) -> set[str]:
        return {
            r["kind"]
            for r in fetch_all(
                conn, "SELECT kind FROM shoc.schedules WHERE tenant_id = %s", (tenant,)
            )
        }

    def wait_for(tenant: str) -> bool:
        deadline = time.time() + 20
        while time.time() < deadline and not scheduled(tenant):
            time.sleep(0.2)
        return bool(scheduled(tenant))

    monkeypatch.setattr(worker, "handle", lambda job, cfg: "skipped")
    execute(conn, "SELECT pg_advisory_unlock_all()")  # an earlier test's lock
    pool.close()
    register(other)
    stop = threading.Event()

    def run() -> None:
        try:
            worker.run(config, poll_seconds=0.1, stop=stop)
        finally:
            pool.close()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert wait_for(other), "a registered tenant is scheduled at startup"
        register(later)
        assert wait_for(later), "a tenant migrated later is scheduled on the next pass"
    finally:
        stop.set()
        thread.join(timeout=10)
        execute(conn, "DELETE FROM shoc.tenants WHERE tenant_id = ANY(%s)", ([other, later],))
    assert scheduled(later) >= {
        "detect.run",
        "retention",
        "stream.deliver",
        "intel.refresh",
        "hunt.daily",
        "ops.check",
        "unattended",
        "report.weekly",
        "report.exec",
    }


def test_every_job_kind_the_worker_handles_is_listed(config):
    """`handle` and JOB_CAPABILITIES must not drift apart."""
    import inspect

    from shoc.worker import JOB_CAPABILITIES, _handle

    source = inspect.getsource(_handle)
    for kind in JOB_CAPABILITIES:
        assert f'"{kind}"' in source, f"{kind} is listed but not handled"
    for line in source.splitlines():
        if line.strip().startswith('if kind == "'):
            kind = line.split('"')[1]
            assert kind in JOB_CAPABILITIES, f"{kind} is handled but not listed"


def test_the_worker_waits_for_the_schema_instead_of_crashing(conn, config, store):
    from shoc.worker import wait_for_schema

    assert wait_for_schema(conn, attempts=1, delay=0, config=config)


def test_a_worker_on_a_warehouse_needs_no_event_table_in_postgres(conn, config, monkeypatch):
    """`shoc migrate` makes the event table in the warehouse, so that is where to look."""
    from dataclasses import replace

    from shoc import store as stores
    from shoc.store.base import StoreHealth
    from shoc.worker import wait_for_schema

    class Warehouse:
        ok = True

        def health(self):
            return StoreHealth(dialect="warehouse", ok=self.ok)

        def close(self):
            pass

    warehouse = Warehouse()
    monkeypatch.setitem(stores.ADAPTERS, "warehouse", lambda cfg, tid, ro: warehouse)
    elsewhere = replace(config, backend="warehouse", tenant_id=f"{config.tenant_id}wh")
    assert wait_for_schema(conn, attempts=1, delay=0, config=elsewhere)
    warehouse.ok = False
    assert not wait_for_schema(conn, attempts=1, delay=0, config=elsewhere)


def test_two_workers_never_claim_the_same_job(conn, config):
    """SKIP LOCKED is the whole scaling story, so prove it rather than trust it."""
    import psycopg
    from psycopg.rows import DictRow, dict_row

    for i in range(20):
        jobs.enqueue(conn, config.tenant_id, "detect.run", {"n": i})
    second: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        config.dsn, row_factory=dict_row, autocommit=True
    )
    try:
        from shoc.db.pool import ALL_TENANTS, set_tenant

        set_tenant(second, ALL_TENANTS)
        a = jobs.claim(conn, 10)
        b = jobs.claim(second, 10)
        ids_a = {j["job_id"] for j in a}
        ids_b = {j["job_id"] for j in b}
        assert len(a) == 10 and len(b) == 10
        assert not (ids_a & ids_b), "two workers took the same job"
        assert jobs.claim(conn, 10) == [], "and there is nothing left over"
    finally:
        second.close()


def test_a_job_claimed_by_a_dead_worker_comes_back(conn, config):
    job_id = jobs.enqueue(conn, config.tenant_id, "detect.run", {})
    jobs.claim(conn, 1)
    execute(
        conn,
        "UPDATE shoc.jobs SET locked_at = now() - interval '2 hours' WHERE job_id = %s",
        (job_id,),
    )
    jobs.requeue_stale(conn, timedelta(minutes=15))
    assert [j["job_id"] for j in jobs.claim(conn, 1)] == [job_id]


def test_the_worker_reconnects_when_the_database_goes_away(config, conn, store, clean, monkeypatch):
    """A restarted database is an ordinary event for a process that runs for months."""
    import threading

    import psycopg

    from shoc.db import pool

    calls = {"claims": 0}
    real_claim = jobs.claim

    def flaky_claim(connection, limit=1):
        calls["claims"] += 1
        if calls["claims"] == 1:
            raise psycopg.OperationalError("terminating connection due to administrator command")
        return real_claim(connection, limit)

    monkeypatch.setattr(jobs, "claim", flaky_claim)
    stop = threading.Event()
    thread = threading.Thread(
        target=worker.run, args=(config,), kwargs={"poll_seconds": 0.1, "stop": stop}
    )
    thread.start()
    try:
        deadline = time.time() + 20
        while time.time() < deadline and calls["claims"] < 3:
            time.sleep(0.2)
        assert calls["claims"] >= 3, "the worker kept going after the connection died"
    finally:
        stop.set()
        thread.join(timeout=10)
        pool.close()
    assert not thread.is_alive()


def test_reconnect_returns_a_working_connection(config, conn):
    from shoc.db import pool
    from shoc.db.pool import fetch_one

    fresh = worker.reconnect(config, attempts=2, delay=0.1)
    try:
        row = fetch_one(fresh, "SELECT 1 AS ok")
        assert row and row["ok"] == 1
    finally:
        pool.close()


def test_a_single_pass_still_surfaces_a_dead_database(config, conn, clean, monkeypatch):
    """`--once` is for scripts and tests: it should fail loudly, not loop."""
    import psycopg

    def dead_claim(connection, limit=1):
        raise psycopg.OperationalError("server closed the connection unexpectedly")

    monkeypatch.setattr(jobs, "claim", dead_claim)
    with pytest.raises(psycopg.OperationalError):
        worker.run(config, once=True)


def test_a_refusing_source_does_not_park_a_job_every_cycle(conn, ctx, store, config, clean):
    """`source.sync` raises so a shell exits non-zero; the worker does not re-raise.

    The failure is already on `connector_state`, which is what health reads.
    Failing the job as well parked one row per polling cycle for as long as a
    credential stayed wrong, and told the operator the same thing twice.
    """
    from unittest import mock

    from shoc.ingest.connectors.base import RunStats

    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'okta', true, '{"org_url": "https://acme.okta.test"}'::jsonb, NULL)""",
        (config.tenant_id,),
    )
    refused = RunStats(
        source="okta", error="okta rejected the credential (401); it needs okta.logs.read."
    )
    job = {"kind": "source.sync", "tenant_id": config.tenant_id, "payload": {"source": "okta"}}
    with mock.patch("shoc.ingest.connectors.base.run", return_value=refused):
        summary = worker.handle(job, config)
    assert "401" in summary, "the worker still says what happened"
    assert "rule(s)" in summary, "and carries on with the detection cycle"


def test_a_refusing_source_still_fails_the_call_itself(ctx, store, config, clean):
    """The capability raises, which is what makes a shell exit non-zero."""
    from unittest import mock

    from shoc.capabilities.registry import call
    from shoc.db.pool import execute as run_sql
    from shoc.errors import UpstreamError
    from shoc.ingest.connectors.base import RunStats

    run_sql(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'okta', true, '{"org_url": "https://acme.okta.test"}'::jsonb, NULL)""",
        (config.tenant_id,),
    )
    with (
        mock.patch(
            "shoc.ingest.connectors.base.run", return_value=RunStats(source="okta", error="401")
        ),
        pytest.raises(UpstreamError),
    ):
        call("source.sync", ctx, {"source": "okta"})


def test_a_failed_job_hands_the_connection_back_to_every_tenant(config, clean):
    """The loop claims jobs on the connection a job pins to its own tenant.

    Left pinned after a failure, the next claim would only see that tenant.
    """
    from shoc.db.pool import ALL_TENANTS, connect, current_tenant
    from shoc.errors import NotFound

    job = {
        "kind": "action.run",
        "tenant_id": config.tenant_id,
        "payload": {"action_uid": "A-missing"},
    }
    with pytest.raises(NotFound):
        worker.handle(job, config)
    assert current_tenant(connect(config)) == ALL_TENANTS


def test_a_scheduled_sync_loads_through_the_writer_role(conn, store, config, clean):
    """The worker is an agent principal, and agents read through SHOC_READONLY_DSN
    (D22). That role cannot create a partition or insert, so a scheduled pull that
    loaded through it fetched every event and stored none."""
    from unittest import mock

    from shoc.ingest.connectors.base import FetchResult
    from tests.support import FIXTURES, expand

    if not config.readonly_dsn:
        pytest.skip("no read-only role configured")
    assert worker.WORKER_CALLER.kind == "agent"
    records = expand(json.loads((FIXTURES / "mappings" / "okta.json").read_text())[:1], "okta")
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'okta', true, '{"org_url": "https://acme.okta.test"}'::jsonb, NULL)""",
        (config.tenant_id,),
    )
    okta = mock.Mock()
    okta.fetch.return_value = FetchResult(records=records)
    job = {"kind": "source.sync", "tenant_id": config.tenant_id, "payload": {"source": "okta"}}
    with mock.patch("shoc.ingest.connectors.get", return_value=okta):
        summary = worker.handle(job, config)
    assert "fetched 1, loaded 1" in summary


def test_the_hourly_check_tells_the_stream_an_ongoing_alert_once(conn, config):
    """A provider failing all day was republished to every subscriber each hour (OPS-1)."""
    from shoc.agents import ops

    job = {"kind": "ops.check", "tenant_id": config.tenant_id, "payload": {}}
    ops.record_failure(conn, config.tenant_id, "gemini-3-pro", "code 500 after 12s")
    worker.handle(job, config)
    ops.record_failure(conn, config.tenant_id, "gemini-3-pro", "code 500 after 31s")
    worker.handle(job, config)
    sent = fetch_all(
        conn,
        "SELECT subject FROM shoc.stream_events WHERE tenant_id = %s AND type = 'health.llm.failing'",
        (config.tenant_id,),
    )
    assert [r["subject"] for r in sent] == ["gemini-3-pro"]
