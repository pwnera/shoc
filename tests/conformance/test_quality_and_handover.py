"""Source quality, the metric set, and the shift handover (OPS-1, AGT-3).

Ops believes a detection you are not ingesting for is worse than no detection,
because it looks like coverage. These tests are mostly about the failures a
green dashboard hides: a source that is fresh but half-empty, a retention window
too short for the hunts running over it, and an aggregate MTTR that describes
nothing.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.agents import ops, reporter
from shoc.capabilities.registry import call
from shoc.ingest import batch, ocsf
from tests.support import expand

pytestmark = pytest.mark.postgres


def _load(store, tenant: str, when, records: list[dict], conn=None) -> None:
    """Load CloudTrail events; with `conn`, as a configured source's."""
    from shoc.ingest.connectors.base import write_state

    mapping = ocsf.load_mapping("aws_cloudtrail")
    rows = [mapping.map_record(r, tenant) for r in expand(records, "aws_cloudtrail", when)]
    batch.load(store, rows)
    if conn is not None:
        write_state(conn, tenant, "aws_cloudtrail", {}, len(rows), None)


def _event(name: str = "ListBuckets", user: str | None = "deploy-ci", **kw) -> dict:
    identity = {"type": "IAMUser", "accessKeyId": "AKIAEXAMPLE"}
    if user:
        identity["userName"] = user
    return {
        "eventID": f"q-{name}-{user}",
        "eventName": name,
        "eventSource": "s3.amazonaws.com",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": identity,
        **kw,
    }


# -- the four axes ----------------------------------------------------------
def test_a_source_that_is_arriving_scores_well(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [{**_event(), "_repeat": 5}], conn=ctx.db)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored
    assert scored[0].completeness > 0.9
    assert scored[0].field_fidelity > 0.9


def test_a_fresh_source_whose_fields_are_empty_is_the_worse_outage(ctx, store, config, clean, now):
    """Everything still looks green, and a rule keyed on that field is decoration."""
    _load(store, config.tenant_id, now, [{**_event(user=None), "_repeat": 10}], conn=ctx.db)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].completeness > 0.9, "it is arriving, which is the point"
    assert scored[0].fields["actor_user_name"] == 0.0
    assert any("are blind" in note for note in scored[0].notes)


def test_the_vendors_own_changes_are_not_a_missing_user(ctx, store, config, clean, now):
    """Cloudflare renewing a certificate has no user, and that is most of a quiet
    account's audit log; nine of ten rows read as 90% blind."""
    from shoc.ingest.connectors.base import write_state

    def change(actor: dict) -> dict:
        action = {"type": "update", "result": "success", "description": "Certificate pack deployed"}
        resource = {"id": "cp-1", "type": "certificate_pack"}
        return {"id": "q-cf", "action": action, "actor": actor, "resource": resource}

    records = [{**change({"type": "system"}), "_repeat": 9}]
    records.append(change({"type": "user", "email": "ops@example.com", "id": "u-1"}))
    mapping = ocsf.load_mapping("cloudflare")
    rows = [mapping.map_record(r, config.tenant_id) for r in expand(records, "cloudflare", now)]
    batch.load(store, rows)
    write_state(ctx.db, config.tenant_id, "cloudflare", {}, len(rows), None)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].fields["actor_user_name"] == 1.0
    assert not any("are blind" in note for note in scored[0].notes)


def test_a_new_sources_backfill_is_not_lateness(ctx, store, config, clean, now):
    """A first run loads the last day; that is the past arriving, and averaged in
    it read as hours late for the month the rows stay in the window."""
    from shoc.db.pool import execute

    _load(store, config.tenant_id, now - timedelta(hours=20), [_event()], conn=ctx.db)
    assert ops.source_quality(ctx.db, ctx.store, config.tenant_id)[0].timeliness == 0.0
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_loaded_at)
           VALUES (%s, 'aws_cloudtrail', '{AWS CloudTrail}', now() - interval '10 minutes')""",
        (config.tenant_id,),
    )
    _load(store, config.tenant_id, now, [_event(name="GetObject")], conn=ctx.db)
    assert ops.source_quality(ctx.db, ctx.store, config.tenant_id)[0].timeliness > 0.9


def test_short_retention_is_reported_rather_than_assumed(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [_event()], conn=ctx.db)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].retention < 1.0
    assert any("is a lie" in note for note in scored[0].notes), (
        "a 30-day hunt over a week of data is a lie, and saying so is the job"
    )


def test_a_source_with_a_long_history_is_not_short_of_retention(ctx, store, config, clean, now):
    """The scoring window cannot see past 30 days; the source's history can."""
    from shoc.db.pool import execute

    _load(store, config.tenant_id, now - timedelta(days=29, hours=12), [_event()], conn=ctx.db)
    _load(store, config.tenant_id, now, [{**_event(name="GetObject"), "_repeat": 3}], conn=ctx.db)
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_event_at)
           VALUES (%s, 'aws_cloudtrail', '{AWS CloudTrail}', now() - interval '80 days')""",
        (config.tenant_id,),
    )
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].retention_days > 79
    assert not any("is a lie" in note for note in scored[0].notes)


def test_a_gap_that_ended_today_still_counts_against_completeness(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now - timedelta(days=19), [_event()], conn=ctx.db)
    _load(store, config.tenant_id, now, [{**_event(name="GetObject"), "_repeat": 3}], conn=ctx.db)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].completeness == round(2 / 20, 3), "events on 2 of the 20 days since"


def test_a_source_that_stopped_is_an_outage_not_a_quiet_day(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now - timedelta(days=3), [_event()], conn=ctx.db)
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert scored[0].completeness == 0.0
    assert any("outage" in note for note in scored[0].notes)


def test_events_from_an_unconfigured_source_are_not_scored(ctx, store, config, clean, now):
    """A removed source or replayed fixtures leave events with nothing to fix."""
    _load(store, config.tenant_id, now - timedelta(days=3), [_event()])
    assert ops.source_quality(ctx.db, ctx.store, config.tenant_id) == []


def test_a_connector_error_reaches_its_source_quality(ctx, store, config, clean, now):
    """Events carry the product name and connector state the connector's, so the
    error was looked up under the wrong key and never shown."""
    from shoc.ingest.connectors.base import write_state

    _load(store, config.tenant_id, now, [_event()], conn=ctx.db)
    write_state(ctx.db, config.tenant_id, "aws_cloudtrail", {}, 0, "AccessDenied on LookupEvents")
    scored = ops.source_quality(ctx.db, ctx.store, config.tenant_id)
    assert any("AccessDenied" in note for note in scored[0].notes)


def test_quality_reaches_the_alerts_the_ops_role_raises(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [{**_event(user=None), "_repeat": 10}], conn=ctx.db)
    raised = ops.alerts(ctx.db, config.tenant_id, store=ctx.store)
    assert any(a.kind == "source.quality" for a in raised)


def test_health_quality_through_the_registry(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [{**_event(), "_repeat": 3}], conn=ctx.db)
    result = call("health.quality", ctx, {"days": 30})
    assert result.data.sources
    assert set(result.data.sources[0]) >= {
        "completeness",
        "retention",
        "timeliness",
        "field_fidelity",
        "score",
    }


# -- the metric set ---------------------------------------------------------
def test_metrics_are_per_incident_type(ctx, store, config, clean):
    """An aggregate over every kind of case describes none of them."""
    ctx.db.execute(
        """INSERT INTO shoc.cases (case_uid, tenant_id, title, severity, verdict, attack,
                                   entity_key, opened_at, closed_at, state)
           VALUES (%s,%s,%s,%s,%s,%s,%s, now() - interval '2 hours', now(), 'closed')""",
        (
            f"CASE-cred-{config.tenant_id}",
            config.tenant_id,
            "leaked key",
            "high",
            "malicious",
            ["T1078.004"],
            "key:AKIAEXAMPLE",
        ),
    )
    ctx.db.execute(
        """INSERT INTO shoc.cases (case_uid, tenant_id, title, severity, verdict, attack,
                                   entity_key, opened_at, closed_at, state)
           VALUES (%s,%s,%s,%s,%s,%s,%s, now() - interval '20 minutes', now(), 'closed')""",
        (
            f"CASE-data-{config.tenant_id}",
            config.tenant_id,
            "bulk read",
            "medium",
            "suspicious",
            ["T1530"],
            "user:analyst",
        ),
    )
    measured = ops.metrics(ctx.db, config.tenant_id, 30)
    assert set(measured["by_incident_type"]) == {"credential", "data"}
    assert (
        measured["by_incident_type"]["credential"]["mttr_minutes"]
        > (measured["by_incident_type"]["data"]["mttr_minutes"])
    )


def test_the_false_positive_rate_counts_only_decided_cases(ctx, store, config, clean):
    for uid, verdict in (("fp", "false_positive"), ("real", "malicious"), ("na", "needs_human")):
        ctx.db.execute(
            """INSERT INTO shoc.cases
                   (case_uid, tenant_id, title, severity, verdict, entity_key, opened_at)
               VALUES (%s,%s,%s,'medium',%s,%s, now())""",
            (f"CASE-{uid}-{config.tenant_id}", config.tenant_id, uid, verdict, f"user:{uid}"),
        )
    measured = ops.metrics(ctx.db, config.tenant_id, 30)
    assert measured["false_positive_rate"] == 0.5, (
        "an undecided case is not evidence either way, so it is not in the denominator"
    )


def test_metrics_get_through_the_registry(ctx, store, config, clean):
    result = call("metrics.get", ctx, {"days": 30})
    assert "per type" in result.summary


# -- the handover -----------------------------------------------------------
def test_a_quiet_shift_says_so_plainly(ctx, store, config, clean):
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "shift", config=config)
    handover = report.body["handover"]
    assert handover["nothing_to_do"] is True
    assert "Nothing from this shift needs you" in handover["briefing"]
    assert handover["briefing"] in report.summary


def test_the_handover_has_three_layers(ctx, store, config, clean):
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "shift", config=config)
    assert set(report.body["handover"]) >= {"briefing", "checklist", "log"}


def test_an_action_waiting_for_a_human_is_on_the_checklist(ctx, store, config, clean):
    ctx.db.execute(
        """INSERT INTO shoc.actions (action_uid, tenant_id, type, target, state, autonomy)
           VALUES (%s,%s,'cloudflare.block_ip','203.0.113.4','proposed','L2')""",
        (f"ACT-{config.tenant_id}", config.tenant_id),
    )
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "shift", config=config)
    handover = report.body["handover"]
    assert not handover["nothing_to_do"]
    assert any("approve or reject" in item["do"] for item in handover["checklist"])
    assert "waiting for your approval" in handover["briefing"]


def test_a_lapsing_suppression_asks_nothing_of_the_person_on_shift(ctx, store, config, clean):
    """D77: a suppression lasts a week and lapses by itself; renewing it is not a chore."""
    ctx.db.execute(
        """INSERT INTO shoc.suppressions
               (suppression_uid, tenant_id, rule_id, entity, reason, case_uid, expires_at)
           VALUES (%s,%s,'a_rule','user:backup','the backup job','CASE-x',
                   now() + interval '2 days')""",
        (f"SUP-{config.tenant_id}", config.tenant_id),
    )
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "shift", config=config)
    assert not any("suppression" in item["do"] for item in report.body["handover"]["checklist"])


def test_the_weekly_carries_hunting_detection_and_quality(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [{**_event(), "_repeat": 3}], conn=ctx.db)
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "weekly", config=config)
    assert set(report.body) >= {"hunting", "detection", "quality", "metrics"}
    assert "Hunts:" in report.summary and "Detection backlog:" in report.summary


def test_the_founders_page_answers_what_is_exposed_and_what_we_would_miss(
    ctx, store, config, clean, now
):
    _load(store, config.tenant_id, now, [{**_event(), "_repeat": 3}], conn=ctx.db)
    call("posture.get", ctx, {"days": 30, "refresh": True})
    report = reporter.build(ctx.db, ctx.store, config.tenant_id, "exec", config=config)
    posture = report.body["posture"]
    assert "exposed_entities" in posture and "what_we_would_not_have_seen" in posture
    assert "did nothing in the window is not counted" in posture["caveat"], (
        "a number a founder acts on must carry its own limit"
    )


def test_the_numbers_never_come_from_a_model(ctx, store, config, clean, monkeypatch):
    """A report is reproducible and citable even when the crew is switched off."""
    monkeypatch.setenv("SHOC_LLM_PROVIDER", "none")
    first = reporter.build(ctx.db, ctx.store, config.tenant_id, "weekly", config=config)
    second = reporter.build(ctx.db, ctx.store, config.tenant_id, "weekly", config=config)
    assert first.body["cases"] == second.body["cases"]
    assert first.summary == second.summary
