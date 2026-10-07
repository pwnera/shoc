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


@pytest.mark.parametrize(
    ("columns", "values"),
    [
        ("last_run_at", "now()"),  # configured, never once succeeded
        ("last_run_at, last_error", "now(), 'okta rejected the credential (401).'"),
        ("last_run_at, last_ok_at", "now() - interval '3 days', now() - interval '3 days'"),
        ("last_run_at, last_ok_at", "now(), now()"),  # healthy
    ],
)
def test_status_and_sources_never_disagree(ctx, store, config, clean, columns, values):
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


def test_status_is_degraded_while_a_job_has_given_up(ctx, store, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, finished_at)
           VALUES (%s, 'intel.refresh', 'failed', now())""",
        (config.tenant_id,),
    )
    status = call("health.status", ctx, {})
    assert not status.data.ok and "failed" in status.summary


def test_a_job_that_failed_long_ago_does_not_hold_health_red(ctx, store, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, created_at, finished_at)
           VALUES (%s, 'intel.refresh', 'failed', now() - interval '9 days',
                   now() - interval '9 days')""",
        (config.tenant_id,),
    )
    assert call("health.status", ctx, {}).data.ok


def test_status_is_degraded_while_no_worker_ticks_the_scheduler(ctx, store, config, clean):
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


def test_neighbours_walks_from_a_value(ctx, store, config, scenario):
    call("graph.refresh", ctx, {"days": 30})
    result = call("graph.neighbours", ctx, {"node": "AKIAIOSFODNN7EXAMPLE", "hops": 2})
    labels = {n["label"] for n in result.data.nodes}
    assert "deploy-ci" in labels, "the key and the user it belongs to are connected"
    assert result.data.hops == 2


def test_the_walk_is_capped_at_three_hops(ctx, store, config, scenario):
    call("graph.refresh", ctx, {"days": 30})
    result = call("graph.neighbours", ctx, {"node": "user:deploy-ci", "hops": 9})
    assert result.data.hops == 3


def test_a_graph_cut_at_its_limit_says_so(ctx, store, config, scenario):
    from shoc.agents import graph as world

    cut = world.refresh(ctx.db, store, config.tenant_id, 30, limit=2)
    assert cut.truncated and cut.limit == 2 and cut.events_read == 2
    whole = call("graph.refresh", ctx, {"days": 30})
    assert not whole.data.truncated and "Cut at" not in whole.summary


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
        execute(ctx.db, "UPDATE shoc.jobs SET attempts = 5 WHERE job_id = %s", (job_id,))
        jobs.fail(ctx.db, job_id, "ConfigError: source 'okta' is not configured")
    failed = call("health.jobs", ctx, {"days": 7}).data.failed
    assert [(f["kind"], f["jobs"]) for f in failed] == [("source.sync", 2)]
    assert any(a.kind == "jobs.failed" for a in ops.alerts(ctx.db, config.tenant_id))
