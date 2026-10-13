"""What tells the absent operator shoc itself is in trouble (OPS-1, AGT-1, DET-4, RSP-3).

A model out of credit, a feed that parses to nothing, a page that reached
nobody, a check that raised before it decided its pages: each used to leave
every job reading as a success. These tests ask whether the one person who can
fix it is told, once, and whether nothing is closed in the meantime.
"""

from __future__ import annotations

import httpx
import pytest

from shoc import worker
from shoc.agents import manager, ops, reporter
from shoc.capabilities.registry import call
from shoc.cases import actions as action_store
from shoc.cases import engine, unattended
from shoc.db.pool import execute, fetch_all, fetch_one

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


def _findings_at(conn, config, case_uid: str, severity: str) -> None:
    execute(
        conn,
        "UPDATE shoc.findings SET severity = %s WHERE tenant_id = %s AND case_uid = %s",
        (severity, config.tenant_id, case_uid),
    )


def _past_deadline(conn, config, case_uid: str, hours: float, **columns: object) -> None:
    sets = "".join(f", {name} = %({name})s" for name in columns)
    execute(
        conn,
        f"""UPDATE shoc.cases SET state = 'analysis',
                   worked_at = now() - %(hours)s * interval '1 hour'{sets}
            WHERE tenant_id = %(t)s AND case_uid = %(c)s""",
        {"hours": hours, "t": config.tenant_id, "c": case_uid, **columns},
    )


def _second_expiry(conn, config, case_uid: str, hours: float) -> None:
    """Age the deadline nudge the first pass wrote, so the next pass is the second expiry."""
    execute(
        conn,
        """UPDATE shoc.openspace_messages SET created_at = now() - %s * interval '1 hour'
           WHERE tenant_id = %s AND case_uid = %s AND kind = 'inject'""",
        (hours, config.tenant_id, case_uid),
    )


# -- the model stopped answering (ai-4) ----------------------------------------
def _answered(conn, config, ago: str) -> None:
    ops.record_spend(conn, config.tenant_id, "main-model", 1_000, 100)
    execute(
        conn,
        "UPDATE shoc.llm_spend SET last_ok_at = now() - %s::interval WHERE tenant_id = %s",
        (ago, config.tenant_id),
    )


def _model_pages(conn, config) -> list[dict]:
    return fetch_all(
        conn,
        """SELECT body FROM shoc.notices
           WHERE tenant_id = %s AND kind = 'page' AND group_key = 'llm'""",
        (config.tenant_id,),
    )


def test_spent_model_credit_pages_once_naming_the_cause(ctx, config, clean):
    _answered(ctx.db, config, "20 minutes")
    ops.record_failure(
        ctx.db,
        config.tenant_id,
        "main-model",
        "Investigator: HTTPStatusError: Client error '402 Payment Required'",
    )
    down = ops.model_down(ctx.db, config.tenant_id)
    assert down and down["status"] == "402", "no retry fixes a 402, so it is down at once"
    manager.coverage(ctx.db, config.tenant_id, config)
    manager.coverage(ctx.db, config.tenant_id, config)
    pages = _model_pages(ctx.db, config)
    assert len(pages) == 1, "an hourly check tells it once a day"
    assert "credit is spent" in pages[0]["body"] and "llm.configure" in pages[0]["body"]

    items = reporter.exceptions(ctx.db, config.tenant_id, config)
    model = [i for i in items if i["reference"].startswith("llm:")]
    assert len(model) == 1 and "HTTP 402" in model[0]["what"]


def test_a_model_silent_for_hours_pages_and_a_brief_failure_does_not(ctx, config, clean):
    _answered(ctx.db, config, "1 hour")
    ops.record_failure(ctx.db, config.tenant_id, "main-model", "code 500 after 31s")
    assert ops.model_down(ctx.db, config.tenant_id) is None, "an hour of 500s is a busy provider"
    manager.coverage(ctx.db, config.tenant_id, config)
    assert not _model_pages(ctx.db, config)

    _answered(ctx.db, config, f"{ops.MODEL_DARK_HOURS + 1} hours")
    ops.record_failure(ctx.db, config.tenant_id, "main-model", "code 500 after 31s")
    down = ops.model_down(ctx.db, config.tenant_id)
    assert down and down["status"] == ""
    manager.coverage(ctx.db, config.tenant_id, config)
    [page] = _model_pages(ctx.db, config)
    assert "failed every call" in page["body"]


def test_a_case_nobody_read_is_held_while_the_model_is_down(ctx, conn, config, case, clean):
    """A spent credit used to close every medium case unread within half a day."""
    uid = case["case_uid"]
    engine.set_severity(conn, config.tenant_id, uid, "medium", "for this test")
    _findings_at(conn, config, uid, "medium")
    _past_deadline(conn, config, uid, 30, verdict="needs_human")
    assert unattended.run(conn, config.tenant_id, config).nudged == [uid]
    _second_expiry(conn, config, uid, 25)
    ops.record_failure(conn, config.tenant_id, "main-model", "UpstreamError: code 402")
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.held == [uid] and chased.closed == [] and chased.paged == []
    assert engine.require(conn, config.tenant_id, uid)["state"] != "closed"


def test_an_upgrade_does_not_page_at_the_first_failure(ctx, config, clean):
    """Rows from before migration 060 hold calls and no last_ok_at. Read as a model
    that never answered, the first 500 after the upgrade paged the outage (ai-4)."""
    ops.record_spend(ctx.db, config.tenant_id, "main-model", 1_000, 100)
    execute(
        ctx.db,
        "UPDATE shoc.llm_spend SET last_ok_at = NULL WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    ops.record_failure(ctx.db, config.tenant_id, "main-model", "code 500 after 31s")
    assert ops.model_down(ctx.db, config.tenant_id) is None
    manager.coverage(ctx.db, config.tenant_id, config)
    assert not _model_pages(ctx.db, config)


def test_a_first_call_that_fails_is_not_yet_an_outage(ctx, config, clean):
    """A new install whose first call meets a 500 has not been dark for hours."""
    ops.record_failure(ctx.db, config.tenant_id, "main-model", "code 500 after 31s")
    assert ops.model_down(ctx.db, config.tenant_id) is None


@pytest.mark.parametrize(
    "cut",
    [TimeoutError("the model call ran out of the time it was given"), httpx.ReadTimeout("slow")],
)
def test_a_page_worded_past_its_time_is_not_a_provider_failure(
    conn, config, case, monkeypatch, cut
):
    """WORDING_SECONDS is shoc's own cut-off: counted as the provider failing, every
    page from a slow model stood the case sweep down for 15 minutes (ai-4)."""
    from shoc.agents.llm import ScriptedClient

    class Slow(ScriptedClient):
        def complete(self, *args, **kwargs):
            raise cut

    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: Slow())
    rows = [
        {
            "case_uid": case["case_uid"],
            "citations": [],
            "source": "IR Commander",
            "condition": "critical_severity",
            "severity": "critical",
            "body": "A leaked key is in use.",
        }
    ]
    assert manager.word(conn, config.tenant_id, rows, config) == manager.template(rows)
    assert ops.provider_failing(conn, config.tenant_id) == ""
    assert not fetch_all(
        conn,
        "SELECT 1 FROM shoc.llm_spend WHERE tenant_id = %s AND failures > 0",
        (config.tenant_id,),
    )


def test_a_high_case_is_paged_until_the_outage_is(ctx, conn, config, case, clean, pager):
    """Minutes of 500s are not yet the one outage page (MODEL_DARK_HOURS), so a high
    case past its deadlines is still paged on its own rather than held unseen."""
    uid = case["case_uid"]
    _findings_at(conn, config, uid, "high")
    engine.set_severity(conn, config.tenant_id, uid, "high", "for this test")
    _past_deadline(conn, config, uid, 5, verdict="malicious")
    assert unattended.run(conn, config.tenant_id, config).nudged == [uid]
    _second_expiry(conn, config, uid, 4.5)
    _answered(conn, config, "5 minutes")
    ops.record_failure(conn, config.tenant_id, "main-model", "code 500 after 31s")
    assert ops.provider_failing(conn, config.tenant_id)
    assert ops.model_down(conn, config.tenant_id) is None
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.paged == [uid] and chased.held == []


def test_a_case_the_crew_tried_and_never_read_is_held_not_closed(ctx, conn, config, case, clean):
    uid = case["case_uid"]
    engine.set_severity(conn, config.tenant_id, uid, "low", "for this test")
    _findings_at(conn, config, uid, "low")
    _past_deadline(conn, config, uid, 80, crew_attempts=2, tokens_used=0)
    assert unattended.run(conn, config.tenant_id, config).nudged == [uid]
    _second_expiry(conn, config, uid, 73)
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.held == [uid] and chased.closed == []

    # One the crew did read closes below high, as D51 says.
    execute(
        conn,
        "UPDATE shoc.cases SET tokens_used = 900 WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, uid),
    )
    assert unattended.run(conn, config.tenant_id, config).closed == [uid]


# -- paging reads the worst finding (ai-3) --------------------------------------
def test_a_critical_case_lowered_to_low_keeps_its_one_hour_deadline_and_pages(
    ctx, conn, config, case, clean, pager
):
    uid = case["case_uid"]
    _findings_at(conn, config, uid, "critical")
    engine.set_severity(conn, config.tenant_id, uid, "low", "the log said it was a test")
    assert engine.require(conn, config.tenant_id, uid)["severity"] == "low"
    _past_deadline(conn, config, uid, 2, verdict="malicious")
    assert unattended.run(conn, config.tenant_id, config).nudged == [uid], "1h, not low's 72h"
    _second_expiry(conn, config, uid, 1.5)
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.paged == [uid] and chased.closed == []


def test_a_model_lowering_a_case_does_not_settle_its_critical_page(
    ctx, conn, config, case, clean, pager
):
    uid = case["case_uid"]
    _findings_at(conn, config, uid, "critical")
    engine.set_severity(conn, config.tenant_id, uid, "low", "the log said it was a test")
    manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        "A leaked key is in use.",
        case_uid=uid,
        condition="critical_severity",
        deliver=False,
    )
    out = manager.deliver(conn, config.tenant_id, config)
    assert out.paged and not out.digest

    execute(
        conn,
        "UPDATE shoc.cases SET verdict = 'malicious' WHERE tenant_id = %s AND case_uid = %s",
        (config.tenant_id, uid),
    )
    assert manager.uncontained(conn, config.tenant_id, uid), "high or critical by its findings"


# -- an approval whose page is being retried (H1) --------------------------------
def test_an_approval_stays_open_while_its_page_is_retried(ctx, conn, config, case, clean, pager):
    uid = case["case_uid"]
    engine.set_severity(conn, config.tenant_id, uid, "critical", "for this test")
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions", params={"role_name": "deploy"}, case_uid=uid
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    action = row["action_uid"]
    execute(
        conn,
        "UPDATE shoc.actions SET decide_by = now() - interval '1 hour' WHERE action_uid = %s",
        (action,),
    )
    pager.status = 503
    chased = unattended.run(conn, config.tenant_id, config)
    assert chased.paged == [] and chased.abandoned == []
    after = fetch_one(
        conn, "SELECT state, chased_at FROM shoc.actions WHERE action_uid = %s", (action,)
    )
    assert after and after["state"] == "proposed" and after["chased_at"] is not None

    # The retries ran out, and a pass after the window decides.
    execute(
        conn,
        """UPDATE shoc.notices SET delivered_at = now(), outcome = 'failed', retry_at = NULL
           WHERE tenant_id = %s AND source = 'unattended'""",
        (config.tenant_id,),
    )
    execute(
        conn,
        "UPDATE shoc.actions SET chased_at = now() - %s * interval '1 hour' WHERE action_uid = %s",
        (unattended.DECIDE_WITHIN_HOURS + 1, action),
    )
    assert unattended.run(conn, config.tenant_id, config).abandoned == [action]
    done = fetch_one(conn, "SELECT state, error FROM shoc.actions WHERE action_uid = %s", (action,))
    assert done and done["state"] == "rejected" and "no page could go out" in done["error"]


# -- a page that reached nobody (H2) -------------------------------------------
def test_a_page_that_reached_nobody_is_an_exception_item(ctx, config, clean):
    for body, settle in (
        ("Okta has been dark.", "delivered_at = now(), outcome = 'failed'"),
        ("GitHub has been dark.", "retry_at = now() + interval '5 minutes'"),
    ):
        uid = manager.tell(
            ctx.db, config.tenant_id, "Ops", "page", body, condition="coverage_dark", deliver=False
        )
        execute(
            ctx.db,
            f"""UPDATE shoc.notices SET {settle}, last_error = 'PagerDuty answered 503'
                WHERE tenant_id = %s AND notice_uid = %s""",
            (config.tenant_id, uid),
        )
    [item] = [
        i
        for i in reporter.exceptions(ctx.db, config.tenant_id, config)
        if i["reference"].startswith("page:failed:")
    ]
    assert item["what"].startswith("Make pages reach you: 1 page(s)"), "one still retrying"
    assert "503" in item["why_only_a_human"]


# -- the weekly reads the stored spend cap (H7) ----------------------------------
def test_the_weekly_shows_spend_over_the_cap_llm_configure_stored(ctx, store, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, settings)
           VALUES (%s, 'llm', '{"spend_usd_per_day": "0.01"}'::jsonb)""",
        (config.tenant_id,),
    )
    ops.record_spend(ctx.db, config.tenant_id, "claude-sonnet-5", 1_000_000, 100_000)
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "weekly", config=config)
    assert any(a["kind"] == "cost.over_budget" for a in report.body["alerts"])


# -- intel feeds and local lists (cti-7, H9) ------------------------------------
def test_a_feed_that_failed_went_stale_or_keeps_nothing_is_an_alert(ctx, config, clean, pager):
    rows = [
        # feed, parser, enabled, ran, ok hours ago, error
        ("misp", "misp_events", True, True, 1, "HTTPStatusError: 401 Unauthorized"),
        ("abuse_ch_urlhaus", "", True, True, 1, None),  # parses to nothing
        ("abuse_ch_feodo", "", True, True, 1, None),  # keeps an indicator
        ("otx", "otx_pulses", True, True, 1, None),  # a quiet week is honest
        ("vendor_blog", "rss", True, True, 30, None),  # stale
        ("new_feed", "rss", True, False, None, None),  # never ran: not judged
        ("old_feed", "rss", False, True, 30, "gone"),  # disabled
    ]
    for feed, parser, enabled, ran, ok, error in rows:
        execute(
            ctx.db,
            """INSERT INTO shoc.intel_feeds
                   (tenant_id, feed, parser, enabled, last_run_at, last_ok_at, last_error)
               VALUES (%s, %s, %s, %s, CASE WHEN %s THEN now() END,
                       now() - %s::float8 * interval '1 hour', %s)""",
            (config.tenant_id, feed, parser, enabled, ran, ok, error),
        )
    execute(
        ctx.db,
        """INSERT INTO shoc.iocs (tenant_id, type, value, source, expires_at)
           VALUES (%s, 'ip', '198.51.100.7', 'abuse.ch/feodo', now() + interval '1 day')""",
        (config.tenant_id,),
    )
    failing = {f["feed"]: f["why"] for f in ops.failing_feeds(ctx.db, config.tenant_id)}
    assert set(failing) == {"misp", "abuse_ch_urlhaus", "vendor_blog"}
    assert "401" in failing["misp"] and "keep no indicator" in failing["abuse_ch_urlhaus"]
    raised = {
        a.subject for a in ops.alerts(ctx.db, config.tenant_id) if a.kind == "intel.feed_failing"
    }
    assert raised == set(failing)
    status = call("health.status", ctx, {})
    assert not status.data.ok and "failing intel feed(s)" in status.summary


def test_a_local_list_that_failed_to_load_is_an_alert(ctx, config, clean, monkeypatch):
    from datetime import UTC, datetime

    from shoc.detect import osint

    monkeypatch.setattr(osint, "LIST_WARNINGS", {"tranco": "download refused: 403"})
    monkeypatch.setattr(osint, "_FAILED", {"cloud:aws": datetime.now(UTC)})
    lists = {
        a.subject: a.detail
        for a in ops.alerts(ctx.db, config.tenant_id)
        if a.kind == "intel.list_failing"
    }
    assert lists == {
        "tranco": "download refused: 403",
        "cloud:aws": "not loaded; tried again every 15 minutes",
    }


# -- a source that read some streams (H8) ---------------------------------------
@pytest.mark.parametrize(
    ("ok", "kind", "severity"),
    [
        ("now()", "source.partial", "medium"),
        ("now() - interval '2 hours'", "source.failing", "high"),
    ],
)
def test_a_refused_stream_is_partial_and_a_refused_pull_is_failing(
    ctx, config, clean, ok, kind, severity
):
    execute(
        ctx.db,
        f"""INSERT INTO shoc.connector_state
                (tenant_id, source, cursor, last_run_at, last_ok_at, last_error)
            VALUES (%s, 'entra', '{{}}'::jsonb, now(), {ok},
                    'signIns: Entra refused it (403). To stop reading it, set streams to a '
                    || 'list without signIns.')""",
        (config.tenant_id,),
    )
    raised = [a for a in ops.alerts(ctx.db, config.tenant_id) if a.subject == "entra"]
    assert [(a.kind, a.severity) for a in raised] == [(kind, severity)]


def test_a_push_after_a_failed_pull_is_still_failing(ctx, config, clean):
    """A webhook landing after a whole poll failed read as some streams failing (H8)."""
    from shoc.ingest.connectors import base

    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state
                (tenant_id, source, cursor, last_run_at, last_ok_at, last_error)
            VALUES (%s, 'github', '{}'::jsonb, now() - interval '1 minute',
                    now() - interval '2 hours', 'GitHub rejected the credential (401)')""",
        (config.tenant_id,),
    )
    base.mark_push(ctx.db, config.tenant_id, "github", 3)
    raised = [a for a in ops.alerts(ctx.db, config.tenant_id) if a.subject == "github"]
    assert [(a.kind, a.severity) for a in raised] == [("source.failing", "high")]


# -- policy.show says the dry run in force (H12) --------------------------------
def test_policy_show_says_the_dry_run_in_force_and_where_it_comes_from(ctx, config, monkeypatch):
    from shoc.cases.policy import Policy

    monkeypatch.setattr(config, "dry_run", False)
    shown = call("policy.show", ctx, {}).data
    assert shown.defaults["dry_run"] is False and shown.dry_run_from == "env"
    monkeypatch.setattr(config, "dry_run", None)
    shown = call("policy.show", ctx, {}).data
    assert shown.dry_run_from == "policy"
    assert shown.defaults["dry_run"] is Policy.load(config).dry_run_for()


# -- case.list filters before its limit (ux-6) ----------------------------------
def test_a_verdict_filter_finds_a_case_older_than_the_limit(ctx, config, clean):
    for uid, verdict, state, days in (
        ("CASE-0000000000000000a001", "needs_human", "analysis", 30),
        ("CASE-0000000000000000a002", "needs_human", "closed", 20),
        *((f"CASE-0000000000000000b00{n}", "malicious", "analysis", 0) for n in range(3)),
    ):
        execute(
            ctx.db,
            """INSERT INTO shoc.cases
                   (case_uid, tenant_id, title, severity, entity_key, verdict, state, updated_at)
               VALUES (%s, %s, 'test', 'high', 'user:jane', %s, %s,
                       now() - %s * interval '1 day')""",
            (uid, config.tenant_id, verdict, state, days),
        )
    waiting = call("case.list", ctx, {"verdict": "needs_human", "limit": 2}).data.rows
    assert [r["case_uid"] for r in waiting] == [
        "CASE-0000000000000000a002",
        "CASE-0000000000000000a001",
    ]
    still_open = call("case.list", ctx, {"verdict": "needs_human", "open": True, "limit": 2})
    assert [r["case_uid"] for r in still_open.data.rows] == ["CASE-0000000000000000a001"]


# -- the hourly check (sre-10, live-12) -----------------------------------------
def test_the_hourly_check_decides_its_pages_before_a_step_that_raises(
    conn, config, clean, monkeypatch
):
    from shoc.errors import ConfigError

    ran: list[str] = []

    def review(*_a: object, **_k: object) -> dict:
        raise ConfigError("unknown LLM provider 'antropic'")

    monkeypatch.setattr(manager, "coverage", lambda *_a, **_k: ran.append("coverage") or 0)
    monkeypatch.setattr(ops, "review", review)
    job = {"kind": "ops.check", "tenant_id": config.tenant_id, "payload": {}}
    with pytest.raises(RuntimeError, match="review: ConfigError"):
        worker.handle(job, config)
    assert ran == ["coverage"]


@pytest.mark.parametrize(
    ("detail", "wakes"),
    [
        ("only 3 day(s) of history: a 30-day hunt has its whole baseline from 2026-11-09", False),
        ("actor_user_name is empty in 80% of Okta rows: 2 rule(s) keyed on it are blind", True),
    ],
)
def test_only_a_field_gone_empty_wakes_the_integrator(
    conn, config, clean, monkeypatch, detail, wakes
):
    monkeypatch.setattr(
        ops, "alerts", lambda *_a, **_k: [ops.OpsAlert("source.quality", "Okta", detail, "medium")]
    )
    worker.handle({"kind": "ops.check", "tenant_id": config.tenant_id, "payload": {}}, config)
    queued = fetch_all(
        conn,
        "SELECT 1 FROM shoc.jobs WHERE tenant_id = %s AND kind = 'source.onboard'",
        (config.tenant_id,),
    )
    assert bool(queued) is wakes
