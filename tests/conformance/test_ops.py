"""Health, cost, reports, tuning, hunts and the world graph (OPS-1, AGT-3, AGT-4)."""

from __future__ import annotations

import pytest

from shoc.agents import detection_engineer, hunter, ops, reporter
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all, fetch_one

pytestmark = pytest.mark.postgres


@pytest.fixture
def scenario(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id=%s LIMIT 1", (config.tenant_id,)
    )
    assert row
    return row["case_uid"]


# -- health -----------------------------------------------------------------
def test_a_source_that_has_never_succeeded_is_stale(ctx, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_run_at)
           VALUES (%s, 'okta', '{}'::jsonb, now())""",
        (config.tenant_id,),
    )
    health = ops.source_health(ctx.db, config.tenant_id)
    assert health[0].stale and health[0].last_ok_at is None
    result = call("health.sources", ctx, {})
    assert not result.data.ok and "okta" in result.summary


def test_a_source_polled_recently_is_fresh(ctx, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_run_at, last_ok_at)
           VALUES (%s, 'github', '{}'::jsonb, now(), now())""",
        (config.tenant_id,),
    )
    assert not ops.source_health(ctx.db, config.tenant_id)[0].stale


def _delivered(ctx, config, source: str, ago: str) -> None:
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state (tenant_id, source, last_ok_at, events_seen)
           VALUES (%s, %s, now() - %s::interval, 5)
           ON CONFLICT (tenant_id, source) DO UPDATE SET last_ok_at = EXCLUDED.last_ok_at""",
        (config.tenant_id, source, ago),
    )


@pytest.mark.parametrize("ago", ["3 hours", "30 hours"])
def test_a_webhook_only_source_is_quiet_on_a_quiet_day_not_dark(ctx, config, clean, ago):
    """A webhook-only GitHub hears nothing at night or on a Sunday (OPS-1, ING-2)."""
    from shoc.agents import manager

    _delivered(ctx, config, "github:quiet", ago)
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.pushed and health.quiet and not health.stale
    assert not [a for a in ops.alerts(ctx.db, config.tenant_id) if a.kind == "source.stale"]
    assert manager.coverage(ctx.db, config.tenant_id) == 0, "a quiet day pages nobody"


def test_a_webhook_only_source_silent_for_a_week_is_dark(ctx, config, clean):
    from shoc.agents import manager

    _delivered(ctx, config, "github:quiet", "8 days")
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.stale and not health.quiet
    stale = [a for a in ops.alerts(ctx.db, config.tenant_id) if a.kind == "source.stale"]
    assert stale and "no successful delivery" in stale[0].detail
    assert manager.coverage(ctx.db, config.tenant_id) == 1


def test_a_polled_source_keeps_its_own_clock(ctx, config, clean):
    """The same connector with a sync schedule is pulled, so three quiet hours are late."""
    schedule = f"{config.tenant_id}:sync:github:quiet"
    execute(
        ctx.db,
        "INSERT INTO shoc.schedules (schedule_id, tenant_id, kind) VALUES (%s, %s, 'source.sync')",
        (schedule, config.tenant_id),
    )
    try:
        _delivered(ctx, config, "github:quiet", "3 hours")
        [health] = ops.source_health(ctx.db, config.tenant_id)
        assert health.stale and not health.pushed
    finally:
        execute(ctx.db, "DELETE FROM shoc.schedules WHERE schedule_id = %s", (schedule,))


def test_a_deleted_webhook_darkens_its_source_at_once(ctx, config, clean):
    """The deletion is the last thing the webhook delivers, so nothing comes after it."""
    _delivered(ctx, config, "github:quiet", "3 hours")
    execute(
        ctx.db,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                window_start, window_end, first_seen, last_seen, event_count, event_uids)
           VALUES ('F-hook', %s, 'github_webhook_deleted', 'Webhook deleted', 'high', 'u',
                   now(), now(), now(), now(), 1, ARRAY['e1'])""",
        (config.tenant_id,),
    )
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.stale and not health.quiet


@pytest.mark.parametrize(
    ("status", "org", "dark"),
    [
        ("triage", "example-org", True),
        ("closed", "example-org", False),
        ("new", "other-org", False),
    ],
)
def test_only_an_open_deletion_for_its_own_org_darkens_a_webhook(
    ctx, config, clean, status, org, dark
):
    """A person closed it, or it was another organisation's hook."""
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, settings, interval_seconds)
           VALUES (%s, 'github:quiet', '{"org": "example-org"}', 0)""",
        (config.tenant_id,),
    )
    _delivered(ctx, config, "github:quiet", "3 hours")
    execute(
        ctx.db,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key, status,
                window_start, window_end, first_seen, last_seen, event_count, event_uids,
                evidence)
           VALUES ('F-hook', %s, 'github_webhook_deleted', 'Webhook deleted', 'high', 'u', %s,
                   now(), now(), now(), now(), 1, ARRAY['e1'],
                   jsonb_build_object('kind', 'match',
                                      'sample', jsonb_build_object('cloud_account_uid', %s::text)))""",
        (config.tenant_id, status, org),
    )
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.stale is dark and health.quiet is not dark


def test_deliveries_refused_for_an_hour_darken_a_webhook(ctx, config, clean):
    """GitHub still signs with the key `source.push_key --rotate` replaced (ING-2)."""
    _delivered(ctx, config, "github:quiet", "3 hours")
    ops.record_push_refused(ctx.db, config.tenant_id, "github:quiet")
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.quiet and not health.stale, "one refusal a minute ago is not an outage"

    execute(
        ctx.db,
        "UPDATE shoc.connector_state SET push_refused_at = now() - interval '2 hours' "
        "WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    ops.record_push_refused(ctx.db, config.tenant_id, "github:quiet")
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.stale and not health.quiet, "the first refusal since the delivery counts"

    _delivered(ctx, config, "github:quiet", "1 minute")
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert not health.stale, "a delivery that loads ends it"


@pytest.mark.parametrize(("ago", "outage"), [(30, False), (8 * 24, True)])
def test_a_quiet_webhook_is_no_quality_outage(ctx, store, config, clean, now, ago, outage):
    """Quality says outage only where health does (OPS-1, ING-2)."""
    from datetime import timedelta

    from shoc.ingest import batch, ocsf
    from shoc.ingest.replay import expand

    _delivered(ctx, config, "github:quiet", f"{ago} hours")
    record = {"action": "repo.create", "actor": "dev-1", "org": "example-org"}
    when = now - timedelta(hours=ago)
    mapping = ocsf.load_mapping("github")
    rows = [mapping.map_record(r, config.tenant_id) for r in expand([record], "github", when)]
    batch.load(store, rows)
    [scored] = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert any("not a quiet day" in note for note in scored.notes) is outage


@pytest.mark.parametrize(
    ("columns", "values"),
    [
        ("last_run_at", "now()"),  # configured, never once succeeded
        ("last_run_at, last_error", "now(), 'okta rejected the credential (401).'"),
        ("last_run_at, last_ok_at", "now() - interval '3 days', now() - interval '3 days'"),
        ("last_run_at, last_ok_at", "now(), now()"),  # healthy
    ],
)
def test_status_and_sources_never_disagree(ctx, store, config, pager, columns, values):
    """`health.status` is what a monitor polls; it may not be kinder than the detail.

    It used to run its own query comparing `now() - last_ok_at` against a fixed
    hour, which is NULL for a source that had never succeeded — so the worst
    state a connector can be in was the one state that read as healthy.
    """
    execute(
        ctx.db,
        f"""INSERT INTO shoc.connector_state (tenant_id, source, cursor, {columns})
            VALUES (%s, 'okta', '{{}}'::jsonb, {values})""",
        (config.tenant_id,),
    )
    status = call("health.status", ctx, {})
    sources = call("health.sources", ctx, {})
    assert status.data.ok == sources.data.ok


def test_a_source_with_one_stream_refused_is_named_not_failing(ctx, store, config, pager):
    """Entra without P2 refuses the risk streams for good while the rest loads:
    health stays ok and names it; a pull refused whole is failing (ING-1, OPS-1)."""
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state
               (tenant_id, source, cursor, last_run_at, last_ok_at, last_error)
           VALUES (%s, 'entra', '{}'::jsonb, now(), now(),
                   'riskDetections: entra rejected the credential (403).')""",
        (config.tenant_id,),
    )
    status, sources = call("health.status", ctx, {}), call("health.sources", ctx, {})
    assert status.data.ok and sources.data.ok
    assert "entra" in status.summary and "entra" in sources.summary
    assert [s["partial"] for s in sources.data.sources] == [True]
    execute(
        ctx.db,
        """UPDATE shoc.connector_state SET last_ok_at = now() - interval '1 minute'
           WHERE tenant_id = %s""",
        (config.tenant_id,),
    )
    assert not call("health.status", ctx, {}).data.ok
    assert not call("health.sources", ctx, {}).data.ok


def test_sources_show_late_events_rows_left_out_and_times_replaced(ctx, config, clean):
    """Each was only a log line; the counts add up across pulls (ING-1, STO-2, D164)."""
    from shoc.ingest.connectors.base import write_state

    for late in ({"signIns": 2}, {"signIns": 1, "riskDetections": 4}):
        write_state(ctx.db, config.tenant_id, "entra", {}, 0, None, None, False, late, 1, 3)
    [health] = ops.source_health(ctx.db, config.tenant_id)
    assert health.late_events == {"signIns": 3, "riskDetections": 4}
    assert (health.skipped, health.replaced) == (2, 6)


def test_status_is_degraded_while_a_job_has_given_up(ctx, store, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, finished_at)
           VALUES (%s, 'intel.refresh', 'failed', now())""",
        (config.tenant_id,),
    )
    status = call("health.status", ctx, {})
    assert not status.data.ok and "failed" in status.summary


def test_a_job_that_failed_long_ago_does_not_hold_health_red(ctx, store, config, pager):
    execute(
        ctx.db,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, created_at, finished_at)
           VALUES (%s, 'intel.refresh', 'failed', now() - interval '9 days',
                   now() - interval '9 days')""",
        (config.tenant_id,),
    )
    assert call("health.status", ctx, {}).data.ok


def test_status_is_degraded_while_no_worker_ticks_the_scheduler(ctx, store, config, pager):
    """Every scheduled job needs the cron leader, ops.check included."""
    execute(
        ctx.db,
        """INSERT INTO shoc.schedules (schedule_id, tenant_id, kind, next_run_at, enabled)
           VALUES (%s, %s, 'detect.run', now() - interval '2 hours', true),
                  (%s, %s, 'retention', now() - interval '2 hours', false)""",
        (f"{config.tenant_id}:late", config.tenant_id, f"{config.tenant_id}:off", config.tenant_id),
    )
    try:
        status = call("health.status", ctx, {})
        assert not status.data.ok and "detect.run" in status.summary
        assert status.data.jobs["overdue_schedules"] == ["detect.run"], "disabled ones do not count"
    finally:
        execute(ctx.db, "DELETE FROM shoc.schedules WHERE tenant_id = %s", (config.tenant_id,))
    assert call("health.status", ctx, {}).data.ok


def test_status_counts_the_rules_rule_list_gives(ctx, store, config, clean):
    """The Overview's rule count is Detection's: not the indicator matcher, not a reverted rule."""
    execute(
        ctx.db,
        """INSERT INTO shoc.rule_state (tenant_id, rule_id, last_error)
           VALUES (%s, 'ioc_match', 'boom'), (%s, 'reverted_rule', 'boom')""",
        (config.tenant_id, config.tenant_id),
    )
    rules = call("health.status", ctx, {}).data.rules
    assert rules["tracked"] == call("rule.list", ctx, {}).data.count
    assert rules["failing"] == 0


def test_rule_counts_say_what_they_count(ctx, store, config, clean):
    """'0 rule(s) tracked' under a filter read as no rules loaded, and a sum of
    firings beside `tracked` read as how many rules fired (live-18)."""
    loaded = call("rule.list", ctx, {}).data.count
    assert call("health.rules", ctx, {"only": "noisy"}).summary.startswith(
        f"{loaded} rule(s) tracked; 0 noisy"
    )
    assert call("health.rules", ctx, {}).summary.startswith(f"{loaded} rule(s) tracked: ")

    # The noisy and failing counts are of every rule, whatever the filter shows.
    def counts(only: str) -> str:
        return call("health.rules", ctx, {"only": only}).summary.split(": ", 1)[1]

    assert counts("silent") == counts("all")
    rules = call("health.status", ctx, {}).data.rules
    assert "firings" in rules and "fires" not in rules


def _high(ctx, config, uid: str, status: str, evidence: str = "{}") -> None:
    execute(
        ctx.db,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key, status,
                window_start, window_end, first_seen, last_seen, event_count, event_uids,
                evidence)
           VALUES (%s, %s, 'google_oauth_token_authorized', 'Token authorized', 'high', 'u', %s,
                   now(), now(), now(), now(), 1, ARRAY['e1'], %s::jsonb)""",
        (uid, config.tenant_id, status, evidence),
    )


def test_high_findings_and_top_rules_leave_out_shocs_own_and_suppressed(ctx, store, config, clean):
    """259 high findings on the main instance were nearly all shoc's own token
    refreshes, and the weekly's top rule was one of them (live-14)."""
    for uid, status in (("F-own", "self"), ("F-aside", "suppressed"), ("F-real", "new")):
        _high(ctx, config, uid, status)
    assert call("health.status", ctx, {}).data.findings["high"] == 1
    weekly = reporter.build(ctx.db, store, config.tenant_id, "weekly", config=config)
    assert [(r["rule_id"], r["n"]) for r in weekly.body["top_rules"]] == [
        ("google_oauth_token_authorized", 1)
    ]


def test_a_finding_list_carries_only_the_evidence_a_row_is_read_by(ctx, config, clean):
    """170 findings with their samples came to 300k characters, past what an
    assistant's client reads in one result (live-13)."""
    _high(
        ctx,
        config,
        "F-ev",
        "new",
        '{"kind": "match", "sample": {"src_endpoint.ip": "203.0.113.9"},'
        ' "indicator": {"type": "ip", "value": "203.0.113.9"}}',
    )
    [row] = call("finding.list", ctx, {}).data.rows
    assert row["evidence"] == {"kind": "match", "indicator": {"type": "ip", "value": "203.0.113.9"}}
    whole = call("finding.get", ctx, {"finding_uid": "F-ev"}).data.finding["evidence"]
    assert whole["sample"] == {"src_endpoint.ip": "203.0.113.9"}


def test_a_database_near_its_disk_budget_alerts_then_pages(ctx, config, clean, monkeypatch):
    """Postgres filling its disk silences the notices a page is sent from (po-19)."""
    from shoc.agents import manager

    def size() -> list:
        return [
            a for a in ops.alerts(ctx.db, config.tenant_id, config=config) if a.kind == "store.size"
        ]

    monkeypatch.setattr(config, "disk_budget_gb", 0.0)
    assert not size(), "no budget, no check"
    used = ops.disk(ctx.db, config)["bytes"] / 1e9
    monkeypatch.setattr(config, "disk_budget_gb", used / 0.85)
    assert [a.severity for a in size()] == ["medium"]
    assert manager.coverage(ctx.db, config.tenant_id, config) == 0
    monkeypatch.setattr(config, "disk_budget_gb", used / 0.95)
    assert [a.severity for a in size()] == ["high"]
    assert manager.coverage(ctx.db, config.tenant_id, config) == 1
    status = call("health.status", ctx, {})
    assert not status.data.ok and "SHOC_DISK_BUDGET_GB" in status.summary
    assert status.data.disk["bytes"] > 0


def test_rule_health_reports_what_fired(ctx, store, config, scenario):
    result = call("health.rules", ctx, {})
    assert result.data.rules, "a detection cycle must leave rule health behind"
    fired = [r for r in result.data.rules if r["findings_7d"]]
    assert fired and all(r["error"] is None for r in result.data.rules)


def test_alerts_surface_an_approval_nobody_answered(ctx, store, config, scenario):
    execute(
        ctx.db,
        """INSERT INTO shoc.actions (action_uid, tenant_id, case_uid, type, target, state,
                                     autonomy, created_at)
           VALUES ('ACT-old', %s, %s, 'okta.suspend_user', 'jane', 'proposed', 'L2',
                   now() - interval '3 hours')""",
        (config.tenant_id, scenario),
    )
    result = call("ops.alerts", ctx, {})
    kinds = {a["kind"] for a in result.data.alerts}
    assert "approval.waiting" in kinds


def test_alerts_surface_a_case_no_agent_has_spoken_about(ctx, store, config, scenario):
    execute(
        ctx.db,
        """UPDATE shoc.cases SET tokens_used = 0, state = 'analysis',
               opened_at = now() - interval '4 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, scenario),
    )
    result = call("ops.alerts", ctx, {})
    stalled = [a for a in result.data.alerts if a["kind"] == "case.stalled"]
    assert stalled and stalled[0]["subject"] == scenario
    assert "no agent has spoken" in stalled[0]["detail"]


def test_a_case_the_crew_worked_on_is_not_stalled(ctx, store, config, scenario):
    execute(
        ctx.db,
        """UPDATE shoc.cases SET tokens_used = 4200, opened_at = now() - interval '4 hours'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, scenario),
    )
    result = call("ops.alerts", ctx, {})
    assert not [a for a in result.data.alerts if a["kind"] == "case.stalled"]


def test_a_failing_model_provider_raises_an_alert(ctx, config, clean):
    ops.record_failure(ctx.db, config.tenant_id, "gemini-3-pro", "returned no completion: code 500")
    result = call("ops.alerts", ctx, {})
    failing = [a for a in result.data.alerts if a["kind"] == "llm.failing"]
    assert failing and failing[0]["subject"] == "gemini-3-pro"
    assert failing[0]["severity"] == "high", "nothing succeeded today, so nothing is working"
    assert "code 500" in failing[0]["detail"]


def test_a_provider_that_mostly_works_is_a_lesser_alert(ctx, config, clean):
    ops.record_spend(ctx.db, config.tenant_id, "gemini-3-pro", 1_000, 100)
    ops.record_failure(ctx.db, config.tenant_id, "gemini-3-pro", "timeout")
    failing = [a for a in call("ops.alerts", ctx, {}).data.alerts if a["kind"] == "llm.failing"]
    assert failing and failing[0]["severity"] == "medium"


def _answered(ctx, config, model: str, ago: str) -> None:
    ops.record_spend(ctx.db, config.tenant_id, model, 1_000, 100)
    execute(
        ctx.db,
        "UPDATE shoc.llm_spend SET last_ok_at = now() - %s::interval "
        "WHERE tenant_id = %s AND model = %s",
        (ago, config.tenant_id, model),
    )


def test_a_failure_a_model_answered_after_is_not_an_outage(ctx, config, clean):
    """A cheap model failing must not stand the case sweep down while the main one works."""
    ops.record_failure(ctx.db, config.tenant_id, "cheap-model", "code 500 after 31s")
    execute(
        ctx.db,
        "UPDATE shoc.llm_spend SET last_error_at = now() - interval '5 minutes' "
        "WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    _answered(ctx, config, "main-model", "1 minute")
    assert ops.provider_failing(ctx.db, config.tenant_id) == ""


def test_a_failure_after_the_last_answer_is_an_outage(ctx, config, clean):
    _answered(ctx, config, "main-model", "5 minutes")
    ops.record_failure(ctx.db, config.tenant_id, "main-model", "code 500 after 31s")
    assert "code 500" in ops.provider_failing(ctx.db, config.tenant_id)


def test_a_reply_that_failed_its_schema_is_not_an_outage(ctx, config, clean):
    """The provider answered; the role's JSON did not fit (AGT-1)."""
    said = "Hunter: ValidationError: $.outcomes: expected an array"
    ops.record_failure(ctx.db, config.tenant_id, "main-model", said)
    assert ops.provider_failing(ctx.db, config.tenant_id) == ""


# -- the hunt backlog (DET-11) ------------------------------------------------
def test_a_hunt_nobody_worked_for_two_days_is_an_alert_with_its_reason(
    ctx, config, clean, monkeypatch
):
    monkeypatch.setenv("SHOC_LLM_PROVIDER", "none")
    execute(
        ctx.db,
        """INSERT INTO shoc.hunt_backlog (item_uid, tenant_id, title, created_at, evidence)
           VALUES ('HB-old', %s, 'old', now() - interval '3 days', '{}'),
                  ('HB-new', %s, 'new', now() - interval '3 hours', '{}'),
                  ('HB-done', %s, 'worked', now() - interval '3 days',
                   jsonb_build_object('worked_at', now()::text))""",
        (config.tenant_id, config.tenant_id, config.tenant_id),
    )
    stale = [a for a in ops.alerts(ctx.db, config.tenant_id) if a.kind == "hunt.backlog_stale"]
    assert len(stale) == 1 and stale[0].detail.startswith("1 open hunt backlog item(s)")
    assert "no model is configured" in stale[0].detail


def test_spend_is_recorded_per_model_and_day(ctx, config, clean):
    ops.record_spend(ctx.db, config.tenant_id, "claude-sonnet-5", 1_000_000, 100_000)
    ops.record_spend(ctx.db, config.tenant_id, "claude-sonnet-5", 500_000, 0)
    money = ops.spend(ctx.db, config.tenant_id)
    assert money["tokens"] == 1_600_000
    assert money["usd_total"] > 0
    row = fetch_one(
        ctx.db, "SELECT calls FROM shoc.llm_spend WHERE tenant_id=%s", (config.tenant_id,)
    )
    assert row and row["calls"] == 2


def test_a_free_model_costs_nothing(ctx, config, clean):
    assert ops.record_spend(ctx.db, config.tenant_id, "scripted", 10_000, 10_000) == 0.0


def test_the_stored_spend_budget_reaches_the_scheduled_check(ctx, config, clean):
    """`ops.check` passes no budget; the one set with llm.configure applies."""
    ops.record_spend(ctx.db, config.tenant_id, "claude-sonnet-5", 1_000_000, 0)
    kinds = lambda: {a["kind"] for a in call("ops.alerts", ctx, {}).data.alerts}  # noqa: E731
    assert "cost.over_budget" not in kinds()
    call("llm.configure", ctx, {"spend_usd_per_day": 1.0})
    assert "cost.over_budget" in kinds()


def test_a_model_with_no_price_is_an_alert_not_free(ctx, config, clean):
    assert ops.record_spend(ctx.db, config.tenant_id, "mystery-model-9", 10_000, 10_000) == 0.0
    unpriced = [a for a in call("ops.alerts", ctx, {}).data.alerts if a["kind"] == "cost.unpriced"]
    assert [a["subject"] for a in unpriced] == ["mystery-model-9"]
    ops.record_spend(ctx.db, config.tenant_id, "scripted", 10, 10)
    assert (
        len([a for a in call("ops.alerts", ctx, {}).data.alerts if a["kind"] == "cost.unpriced"])
        == 1
    ), "a model priced at $0 is not unpriced"


def test_cost_reports_events_and_spend(ctx, store, config, scenario):
    result = call("health.cost", ctx, {"days": 7})
    assert result.data.volume["events"] > 0
    assert "event(s) stored" in result.summary


# -- reports ----------------------------------------------------------------
def test_a_shift_report_counts_what_happened(ctx, store, config, scenario):
    result = call("report.get", ctx, {"kind": "shift"})
    body = result.data.body
    assert body["cases"]["total"] >= 1
    assert body["findings"]["total"] >= 5
    assert result.citations and result.data.report_uid.startswith("REP-")
    # The shift report is a handover now: the briefing leads, then the counts.
    assert result.summary.startswith("Handover for")
    assert set(body["handover"]) >= {"briefing", "checklist", "log"}


def test_a_sent_report_is_kept_so_it_can_be_read_again(ctx, store, config, scenario):
    result = call("report.send", ctx, {"kind": "weekly"})
    row = fetch_one(
        ctx.db,
        "SELECT kind, summary FROM shoc.reports WHERE report_uid=%s",
        (result.data.report_uid,),
    )
    assert row and row["kind"] == "weekly" and row["summary"].startswith("Weekly report")


def test_the_weekly_holds_a_repeated_digest_once_with_its_count(ctx, store, config, clean):
    """35 of the weekly's 50 held rows were one hourly Ops digest, 110k characters
    of a report too large for an assistant to read (live-13)."""
    from shoc.agents import manager

    for hour in range(3):
        manager.tell(
            ctx.db,
            config.tenant_id,
            "Ops",
            "digest",
            f"okta lagged for {hour + 1}h. " + "x" * 600,
            group_key="source:okta",
            deliver=False,
        )
    held = reporter.build(ctx.db, store, config.tenant_id, "weekly", config=config).body["held"]
    assert [(h["source"], h["group_key"], h["count"]) for h in held] == [("Ops", "source:okta", 3)]
    assert held[0]["body"].startswith("okta lagged for") and len(held[0]["body"]) == 300
    # Sent counts notices, as report.ready does; with no channel, Slack refused nothing.
    sent = call("report.send", ctx, {"kind": "weekly"})
    assert sent.data.held == 3 and "3 held notice(s)" in sent.summary
    assert sent.data.undelivered == "not delivered: no channel"
    assert sent.data.slack_error == sent.data.undelivered, "the console reads slack_error"
    assert "Slack:" not in sent.summary and sent.summary.endswith("; not delivered: no channel")


def test_the_weekly_says_what_intel_read_and_matched(ctx, store, config, clean):
    """The weekly said nothing about threat intel, and the founder's indicator
    count held expired and prevalent values nothing matches (cti-24)."""
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_reports (report_uid, tenant_id, title, relevance, techniques)
           VALUES ('RPT-test', %s, 'A loader in build pipelines',
                   'It targets the CI runners this company uses', ARRAY['T1195.002'])""",
        (config.tenant_id,),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                window_start, window_end, first_seen, last_seen, event_count, event_uids)
           VALUES ('F-ioc', %s, 'ioc_match:ip', 'Known C2 address', 'high', '198.51.100.7',
                   now(), now(), now(), now(), 1, ARRAY['e1'])""",
        (config.tenant_id,),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.iocs (tenant_id, type, value, source, tags, expires_at)
           VALUES (%s, 'ip', '198.51.100.7', 'test', '{}', NULL),
                  (%s, 'ip', '198.51.100.8', 'test', '{}', now() - interval '1 day'),
                  (%s, 'ip', '198.51.100.9', 'test', '{prevalent}', NULL)""",
        (config.tenant_id, config.tenant_id, config.tenant_id),
    )
    weekly = reporter.build(ctx.db, store, config.tenant_id, "weekly", config=config)
    intel = weekly.body["intel"]
    assert intel["reports_read"] == 1 and intel["reports"][0]["techniques"] == ["T1195.002"]
    assert (intel["ioc_match"], intel["ioc_retrohunt"]) == (1, 0)
    assert "Intel: 1 report(s) read, 1 indicator finding(s)." in weekly.summary
    exec_ = reporter.build(ctx.db, store, config.tenant_id, "exec", config=config)
    assert exec_.body["posture"]["indicators_known"] == 1, "only what would be matched"


def test_reading_a_report_keeps_nothing(ctx, store, config, scenario):
    """The console calls report.get on every Overview and Measurement view."""

    def kept() -> int:
        row = fetch_one(
            ctx.db, "SELECT count(*) AS n FROM shoc.reports WHERE tenant_id=%s", (config.tenant_id,)
        )
        return int(row["n"]) if row else 0

    before = kept()
    call("report.get", ctx, {"kind": "weekly"})
    call("report.get", ctx, {"kind": "weekly"})
    assert kept() == before


def test_the_executive_report_answers_what_a_founder_asks(ctx, store, config, scenario):
    result = call("report.get", ctx, {"kind": "exec"})
    posture = result.data.body["posture"]
    assert set(posture) >= {
        "entities_watched",
        "indicators_known",
        "rules_narrowed_here",
        "human_actionable_per_day",
        # The two numbers somebody paying for this actually asks about.
        "exposed_entities",
        "what_we_would_not_have_seen",
        "caveat",
    }


def test_an_unknown_report_kind_is_refused(ctx, store, config, clean):
    from shoc.errors import ValidationError

    with pytest.raises(ValidationError):
        reporter.build(ctx.db, store, config.tenant_id, "horoscope")


def test_a_report_needs_no_model(ctx, store, config, scenario):
    result = call("report.get", ctx, {"kind": "shift", "narrate": True})
    assert result.data.narrative == "", "with no LLM the numbers still stand on their own"


# -- world graph ------------------------------------------------------------
def test_the_graph_is_built_from_events(ctx, store, config, scenario):
    result = call("graph.refresh", ctx, {"days": 30})
    assert result.data.nodes >= 3 and result.data.edges >= 3
    kinds = {
        r["kind"]
        for r in fetch_all(
            ctx.db, "SELECT kind FROM shoc.graph_nodes WHERE tenant_id = %s", (config.tenant_id,)
        )
    }
    assert {"user", "key", "ip"} <= kinds


def _graph(ctx, config, edges):
    """Hand-built nodes and edges, so a walk's shape does not rest on a scenario."""
    for src, dst in edges:
        for node in (src, dst):
            execute(
                ctx.db,
                """INSERT INTO shoc.graph_nodes (tenant_id, node_id, kind, label)
                   VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                (config.tenant_id, node, *node.split(":", 1)),
            )
        execute(
            ctx.db,
            "INSERT INTO shoc.graph_edges (tenant_id, src, dst) VALUES (%s, %s, %s)",
            (config.tenant_id, src, dst),
        )


def test_an_account_is_reached_but_never_walked_through(ctx, config, clean):
    from shoc.agents import graph as world

    account = "account:000000000001"
    _graph(ctx, config, [(account, "user:a@example.test"), (account, "user:b@example.test")])

    def walk(root, hops):
        return {n["node_id"] for n in world.neighbours(ctx.db, config.tenant_id, root, hops).nodes}

    near = walk("user:a@example.test", 3)
    assert account in near, "the account the user was seen in is next to it"
    assert "user:b@example.test" not in near, "through the account everything is two hops away"
    inside = walk(account, 1)
    assert {"user:a@example.test", "user:b@example.test"} <= inside, "who is in the account"


def test_the_account_behind_a_target_counts_as_a_principal(ctx, config, clean):
    """Three users in one account is four principals: the review escalates with no model asked."""
    from shoc.cases import review

    target = "ip:192.0.2.77"
    users = [f"user:{name}@example.test" for name in ("alice", "bob", "carol")]
    _graph(ctx, config, [(target, n) for n in [*users, "account:000000000002"]])
    context = review.gather_context(ctx.db, config.tenant_id, "ip", "192.0.2.77")
    assert context.seen and len(context.principals) == 4
    assert context.shared


def test_a_rebuild_drops_what_its_window_no_longer_holds(ctx, store, config, scenario):
    execute(
        ctx.db,
        """INSERT INTO shoc.graph_nodes (tenant_id, node_id, kind, label, last_seen)
           VALUES (%s, 'user:gone@example.test', 'user', 'gone@example.test',
                   now() - interval '60 days')""",
        (config.tenant_id,),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.graph_edges (tenant_id, src, dst, last_seen)
           VALUES (%s, 'ip:192.0.2.99', 'user:gone@example.test', now() - interval '60 days')""",
        (config.tenant_id,),
    )
    result = call("graph.refresh", ctx, {"days": 30})
    left = fetch_all(
        ctx.db,
        """SELECT node_id AS id FROM shoc.graph_nodes WHERE tenant_id = %s
           UNION ALL SELECT src FROM shoc.graph_edges WHERE tenant_id = %s""",
        (config.tenant_id, config.tenant_id),
    )
    assert "user:gone@example.test" not in {r["id"] for r in left}
    assert "ip:192.0.2.99" not in {r["id"] for r in left}
    assert len(left) == result.data.nodes + result.data.edges, "nothing but this rebuild stays"


def test_neighbours_walks_from_a_value(ctx, store, config, scenario):
    call("graph.refresh", ctx, {"days": 30})
    result = call("graph.neighbours", ctx, {"node": "AKIAIOSFODNN7EXAMPLE", "hops": 2})
    labels = {n["label"] for n in result.data.nodes}
    assert "deploy-ci" in labels, "the key and the user it belongs to are connected"
    assert result.data.hops == 2
    # How much history the walk answers from (data-8).
    assert result.data.since and result.data.since <= result.data.until
    assert f"Graph covers {result.data.since} to {result.data.until}." in result.summary


def test_the_walk_is_capped_at_three_hops(ctx, store, config, scenario):
    call("graph.refresh", ctx, {"days": 30})
    result = call("graph.neighbours", ctx, {"node": "user:deploy-ci", "hops": 9})
    assert result.data.hops == 3


def test_a_graph_cut_at_its_limit_says_so(ctx, store, config, scenario):
    from shoc.agents import graph as world

    cut = world.refresh(ctx.db, store, config.tenant_id, 30, limit=2)
    assert cut.truncated and cut.limit == 2 and cut.events_read == 2
    since, until = world.coverage(ctx.db, config.tenant_id)
    assert since and until and since <= until, "a reader of the cut graph sees its span"
    whole = call("graph.refresh", ctx, {"days": 30})
    wider = world.coverage(ctx.db, config.tenant_id)[0]
    assert wider and wider <= since, "the whole window reaches back at least as far"
    assert not whole.data.truncated and "Cut at" not in whole.summary


def test_the_graph_window_is_bounded_and_an_agent_never_narrows_it(ctx, store, config, scenario):
    from shoc.capabilities.registry import Caller, Context

    assert call("graph.refresh", ctx, {"days": 3650}).data.window_days == 90
    assert call("graph.refresh", ctx, {"days": 0}).data.window_days == 1
    crew = Caller(kind="agent", id="crew")
    agent = Context(tenant_id=config.tenant_id, caller=crew, config=config)
    agent._store = store
    narrow = call("graph.refresh", agent, {"days": 1})
    assert narrow.data.window_days == 30, "the daily rebuild's counts stay"
    assert narrow.data.nodes >= 3 and narrow.data.edges >= 3


# -- the Investigator's reads (AGT-13) -----------------------------------------
def test_a_timeline_starts_in_the_source_that_alerted_oldest_first(ctx, store, config, scenario):
    built = call("timeline.build", ctx, {"case_uid": scenario, "limit": 500})
    events = built.data.events
    assert events and built.data.products == ["AWS CloudTrail"]
    assert [e["time"] for e in events] == sorted(e["time"] for e in events)
    assert any(e["cited"] for e in events), "the case's own events are on it"
    cut = call("timeline.build", ctx, {"case_uid": scenario, "limit": 1})
    assert cut.data.truncated and cut.data.limit == 1 and "cut at the 1 oldest" in cut.summary


def test_a_timeline_extends_on_one_identity(ctx, store, config, scenario):
    out = call("timeline.extend", ctx, {"case_uid": scenario, "value": "user:deploy-ci"})
    assert out.data.events and {e["actor_user_name"] for e in out.data.events} == {"deploy-ci"}


def test_case_history_is_what_earlier_cases_on_the_entities_concluded(ctx, store, config, scenario):
    shared = fetch_one(
        ctx.db,
        "SELECT entity FROM shoc.case_entities WHERE case_uid = %s AND entity LIKE 'user:%%'",
        (scenario,),
    )
    assert shared
    execute(
        ctx.db,
        """INSERT INTO shoc.cases (case_uid, tenant_id, title, state, verdict, closed_by)
           VALUES ('CASE-earlier', %s, 'before', 'closed', 'benign_expected', 'human')""",
        (config.tenant_id,),
    )
    execute(
        ctx.db,
        "INSERT INTO shoc.case_entities VALUES (%s, 'CASE-earlier', %s)",
        (config.tenant_id, shared["entity"]),
    )
    out = call("case.history", ctx, {"case_uid": scenario})
    assert [c["case_uid"] for c in out.data.cases] == ["CASE-earlier"]
    assert out.data.cases[0]["verdict"] == "benign_expected"


def test_cti_hands_the_hunter_a_hypothesis(ctx, config, clean):
    out = call(
        "hunt.propose",
        ctx,
        {"title": "Infostealer cookies replayed into Okta", "attack": ["t1539"]},
    )
    item = hunter.backlog(ctx.db, config.tenant_id)[0]
    assert item["item_uid"] == out.data.item_uid and item["attack"] == ["T1539"]


# -- memory (AGT-4) -----------------------------------------------------------
def test_memory_search_finds_a_fact_by_its_words(ctx, config, clean):
    call("memory.add_fact", ctx, {"body": "The VPN pool is 10.8.0.0/16", "subject": "vpn"})
    call("memory.add_fact", ctx, {"body": "Backups run every Sunday at 02:00", "subject": "backup"})
    hits = call("memory.search", ctx, {"query": "vpn pools"}).data.rows  # stemmed: pools, pool
    assert [h["body"] for h in hits] == ["The VPN pool is 10.8.0.0/16"]
    assert hits[0]["rank"] > 0
    assert not call("memory.search", ctx, {"query": "kubernetes"}).data.rows


def test_a_person_confirming_a_crew_fact_makes_it_theirs(ctx, config, clean):
    from shoc.agents import memory

    def held(uid: str) -> dict:
        return (
            fetch_one(
                ctx.db, "SELECT source, confidence FROM shoc.memory WHERE memory_id = %s", (uid,)
            )
            or {}
        )

    uid = memory.add(
        ctx.db,
        config.tenant_id,
        "deploy-ci reads secrets on release",
        subject="deploy-ci",
        source="crew",
        confidence=0.6,
    )
    confirmed = call(
        "memory.add_fact",
        ctx,
        {"body": "deploy-ci reads secrets on release", "subject": "deploy-ci"},
    ).data.memory_id
    assert confirmed == uid and held(uid) == {"source": "human", "confidence": 1.0}
    memory.add(
        ctx.db,
        config.tenant_id,
        "deploy-ci reads secrets on release",
        subject="deploy-ci",
        source="crew",
        confidence=0.3,
    )
    assert held(uid) == {"source": "human", "confidence": 1.0}, "the crew cannot take it back"


# -- tuning -----------------------------------------------------------------
def test_a_noisy_aggregate_rule_becomes_one_backlog_item(ctx, store, config, scenario):
    """D77: aggregate volume over the threshold is a defect item; the dominant
    entity is evidence, never a suppression nobody asked for."""
    from shoc.detect import rules as ruleset

    rule = next(r for r in ruleset.load(ctx.config) if r.is_aggregate)
    for i in range(30):
        execute(
            ctx.db,
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                    window_start, window_end, first_seen, last_seen, event_uids)
               VALUES (%s,%s,%s,'noisy','medium','robot@acme.com',
                       now() - %s * interval '1 minute', now(), now(), now(), ARRAY['e1'])""",
            (f"F-noise-{i}", config.tenant_id, rule.id, i),
        )
    items = [
        i
        for i in detection_engineer.intake(ctx.db, config.tenant_id, ctx.config)
        if i.rule_id == rule.id
    ]
    assert len(items) == 1 and items[0].kind == "defect"
    assert items[0].evidence["dominant_entity"] == "robot@acme.com"
    assert not fetch_all(
        ctx.db, "SELECT 1 FROM shoc.suppressions WHERE tenant_id = %s", (config.tenant_id,)
    )


# -- hunts ------------------------------------------------------------------
def test_the_hunter_suggests_indicators_nobody_searched_yet(ctx, store, config, scenario):
    from shoc.detect import intel

    intel.store_indicators(
        ctx.db,
        config.tenant_id,
        [intel.Indicator(type="ip", value="203.0.113.99", source="test", confidence=0.9)],
    )
    result = call("hunt.suggest", ctx, {})
    values = [s["value"] for s in result.data.suggestions]
    assert "203.0.113.99" in values
    top = result.data.suggestions[0]
    assert top["priority"] == 1 and "nobody has searched" in top["reason"]


def test_suggestions_include_entities_behind_serious_findings(ctx, store, config, scenario):
    found = hunter.suggest(ctx.db, config.tenant_id)
    assert any("finding" in s.reason for s in found)


def test_failed_jobs_are_listed_once_per_error(ctx, config, clean):
    """The Worker alert has to lead somewhere: retries of one broken job are one row."""
    from shoc.db import jobs

    for _ in range(2):
        job_id = jobs.enqueue(ctx.db, config.tenant_id, "source.sync", {"source": "okta"})
        assert job_id is not None
        # As claimed by this process: `fail` writes only a job its caller holds.
        execute(
            ctx.db,
            """UPDATE shoc.jobs SET attempts = 5, state = 'running', locked_by = %s
               WHERE job_id = %s""",
            (jobs.WORKER_ID, job_id),
        )
        jobs.fail(ctx.db, job_id, "ConfigError: source 'okta' is not configured")
    failed = call("health.jobs", ctx, {"days": 7}).data.failed
    assert [(f["kind"], f["jobs"]) for f in failed] == [("source.sync", 2)]
    assert any(a.kind == "jobs.failed" for a in ops.alerts(ctx.db, config.tenant_id))
