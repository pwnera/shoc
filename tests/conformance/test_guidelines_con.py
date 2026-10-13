"""Detection, hunting and intel content guidelines that need a database (CON-G5 to CON-G11).

Each test names its guideline in its docstring. A case the code does not meet
today sits in a dict with the reason it is allowed for now; the test fails on
any other case that breaks the rule and on an entry the code now meets, so the
dicts only shrink.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
import yaml

from shoc.agents import ops
from shoc.capabilities.registry import call
from shoc.db.pool import execute
from shoc.detect import engine
from shoc.detect import rules as ruleset
from shoc.detect.engine import run_all, run_rule
from shoc.errors import GateRefused
from shoc.ingest import batch
from shoc.store import ocsf as layout
from tests.conformance.test_detection_engineer import _spec
from tests.conformance.test_intel import _indicator
from tests.conformance.test_playbook_merge import _ours
from tests.conformance.test_rules import MATCH, _findings, _trail
from tests.support import ROOT, fixture_rows, fixture_source, load_fixture

pytestmark = pytest.mark.postgres

SEQUENCES = [r for r in ruleset.load() if r.detection.sequence]


# -- CON-G5 a sequence starts on an attacker-shaped event -------------------------
@pytest.mark.parametrize("rule", SEQUENCES, ids=lambda r: r.id)
def test_a_sequence_rule_is_quiet_on_its_positive_fixture_reversed(rule, store, config, clean, now):
    """CON-G5: a sequence's positive fixture delivered in reverse order fires nothing.

    A fixture record carries no time of its own, so replay places the first record
    latest: reversing the records puts each `then` before its `first`.
    """
    records = list(reversed(load_fixture(rule.id, "positive")))
    batch.load(store, fixture_rows(records, fixture_source(rule), config.tenant_id, now))
    findings = run_rule(
        store, config.tenant_id, rule, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert not findings, f"{rule.id} paired its events in the wrong order: {findings[:1]}"


# -- CON-G7 a cap sorts, filters first and reports what it cut --------------------
# The address `_trail`'s records come from, listed as an indicator.
TRAIL_IP = "203.0.113.20"


def _rule_cycle(conn: Any, store: Any, tenant: str, at: Any) -> list[str]:
    run_all(conn, store, tenant, [MATCH], now=at)
    return [str(r["finding_uid"]) for r in _findings(conn, tenant, MATCH.id)]


def _indicator_cycle(conn: Any, store: Any, tenant: str, at: Any) -> list[str]:
    return engine.match_indicators(conn, store, tenant, now=at)


READERS = {"rules": _rule_cycle, "indicators": _indicator_cycle}


@pytest.mark.parametrize("reader", sorted(READERS))
def test_every_reader_sees_a_late_load(reader, conn, store, config, clean, now):
    """CON-G7: a load stamped before a reader's cursor and committed after it is read.

    The Hunter's window is held to the same rule by
    tests/unit/test_hunter.py::test_a_load_that_committed_late_pulls_the_window_back.
    """
    tenant, cycle = config.tenant_id, READERS[reader]
    _indicator(conn, tenant, TRAIL_IP)
    assert not cycle(conn, store, tenant, now - timedelta(minutes=5))
    stamped = now - timedelta(hours=2)
    rows = _trail(tenant, [stamped], stamped, "late", op="DeleteTrail")
    batch.load(store, rows)
    batch.loaded(conn, tenant, rows)
    assert cycle(conn, store, tenant, now), f"the {reader} cycle skipped a load committed late"


OLD_CASE = "CASE-con-g7-waiting"


def _id(stem: str, tenant: str) -> str:
    """A table-wide primary key that carries the tenant, so it outlives no run (TST-G4)."""
    return f"{stem}-{tenant}"


def _seed_lists(db: Any, tenant: str) -> None:
    """One old row each filter keeps, then newer rows it leaves out, more than the limit."""
    execute(
        db,
        """INSERT INTO shoc.cases (case_uid, tenant_id, title, verdict, state, entity_key,
                                   updated_at)
           VALUES (%s, %s, 'waiting on a person', 'needs_human', 'analysis', 'user:old',
                   now() - interval '1 day')""",
        (_id(OLD_CASE, tenant), tenant),
    )
    execute(
        db,
        """INSERT INTO shoc.actions (action_uid, tenant_id, case_uid, type, target, state,
                                     created_at)
           VALUES (%s, %s, %s, 'aws.disable_access_key',
                   'AKIAIOSFODNN7EXAMPLE', 'proposed', now() - interval '1 day')""",
        (_id("ACT-con-g7-waiting", tenant), tenant, _id(OLD_CASE, tenant)),
    )
    execute(
        db,
        """INSERT INTO shoc.findings
               (finding_uid, tenant_id, rule_id, title, severity, entity_key, status,
                window_start, window_end, first_seen, last_seen, event_count, event_uids)
           VALUES (%s, %s, 'r', 'old', 'high', 'user:old', 'triage',
                   now() - interval '1 day', now() - interval '1 day',
                   now() - interval '1 day', now() - interval '1 day', 1, ARRAY['e0'])""",
        (_id("F-con-g7-waiting", tenant), tenant),
    )
    for n in range(3):
        execute(
            db,
            """INSERT INTO shoc.cases (case_uid, tenant_id, title, verdict, state, entity_key)
               VALUES (%s, %s, 'newer', 'malicious', 'triage', %s)""",
            (_id(f"CASE-con-g7-{n}", tenant), tenant, f"user:new-{n}"),
        )
        execute(
            db,
            """INSERT INTO shoc.actions (action_uid, tenant_id, type, target, state)
               VALUES (%s, %s, 'aws.disable_access_key', 'AKIAIOSFODNN7EXAMPLE', 'done')""",
            (_id(f"ACT-con-g7-{n}", tenant), tenant),
        )
        execute(
            db,
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key, status,
                    window_start, window_end, first_seen, last_seen, event_count, event_uids)
               VALUES (%s, %s, 'r', 'newer', 'high', %s, 'new',
                       now(), now(), now(), now(), 1, ARRAY['e1'])""",
            (_id(f"F-con-g7-{n}", tenant), tenant, f"user:new-{n}"),
        )


LIST_FILTERS = {
    "case.list verdict": ("case.list", {"verdict": "needs_human"}, "case_uid", OLD_CASE),
    "case.list state": ("case.list", {"state": "analysis"}, "case_uid", OLD_CASE),
    "action.list state": ("action.list", {"state": "proposed"}, "action_uid", "ACT-con-g7-waiting"),
    "action.list case_uid": (
        "action.list",
        {"case_uid": OLD_CASE},
        "action_uid",
        "ACT-con-g7-waiting",
    ),
    "finding.list status": (
        "finding.list",
        {"status": "triage"},
        "finding_uid",
        "F-con-g7-waiting",
    ),
}


@pytest.mark.parametrize("case", sorted(LIST_FILTERS))
def test_a_filter_runs_before_the_limit(case, ctx, config, clean):
    """CON-G7: a list's filter applies in SQL before its LIMIT, so an old row it keeps is
    not lost behind newer rows it leaves out (ux-6)."""
    capability, wanted, key, stem = LIST_FILTERS[case]
    tenant = config.tenant_id
    _seed_lists(ctx.db, tenant)
    wanted = {k: _id(v, tenant) if v == OLD_CASE else v for k, v in wanted.items()}
    rows = call(capability, ctx, {**wanted, "limit": 2}).data.rows
    assert [r[key] for r in rows] == [_id(stem, tenant)], f"{case}: {[r[key] for r in rows]}"


# -- CON-G10 a failing feed shows in ops.alerts -----------------------------------
# Whether an empty pull counts as failing is tests/unit/test_guidelines_con.py's
# test_an_empty_pull_is_a_failure; shoc.intel_feeds keeps no per-run count to
# seed "empty for a day" here.
def test_a_feed_failing_or_empty_for_a_day_is_an_ops_alert(ctx, config, clean):
    """CON-G10: a feed that has not pulled for a day is named in ops.alerts."""
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_feeds (tenant_id, feed, last_run_at, last_ok_at, last_error)
           VALUES (%s, 'abuse_ch_feodo', now(), now() - interval '25 hours',
                   'HTTPStatusError: 503 Service Unavailable')""",
        (config.tenant_id,),
    )
    alerts = ops.alerts(ctx.db, config.tenant_id)
    named = [a for a in alerts if "abuse_ch_feodo" in f"{a.subject} {a.detail}"]
    assert named, f"no Ops alert names the failing feed: {[a.kind for a in alerts]}"


# -- CON-G11 merged content gets the shipped checks -------------------------------
def _rule(**over: Any) -> dict[str, Any]:
    """A new CloudTrail rule the detection gate accepts, with `over` laid on it."""
    spec = _spec(dry_run=True)
    spec["rule"] = {**spec["rule"], "id": "con_g11_user_deleted", "severity": "high", **over}
    return spec


def _pack(**baseline: Any) -> dict[str, Any]:
    path = ROOT / "content" / "hunts" / "aws_role_first_assumed.yaml"
    body = json.loads(json.dumps(yaml.safe_load(path.read_text()), default=str))
    body["id"] = "con_g11_role_first_assumed"
    body["baseline"] = {**body["baseline"], **baseline}
    shipped = ROOT / "tests" / "fixtures" / "hunts" / "aws_role_first_assumed"
    fixtures = {
        "source": "aws_cloudtrail",
        "surfaced": json.loads((shipped / "surfaced.json").read_text()),
        "baseline": json.loads((shipped / "baseline.json").read_text()),
    }
    return {"pack": body, "fixtures": fixtures, "dry_run": True}


def _without_negative() -> dict[str, Any]:
    spec = _rule()
    spec["fixtures"] = {k: v for k, v in spec["fixtures"].items() if k != "negative"}
    return spec


# name -> (capability, payload, the stage that should refuse it, words a reason holds)
MUTANTS: dict[str, tuple[str, Any, str, tuple[str, ...]]] = {
    "rule without a playbook": (
        "detection.merge",
        lambda: {**_rule(), "playbook_id": "no_such_playbook"},
        "lint",
        ("no playbook",),
    ),
    "rule below its playbook's trigger": (
        "detection.merge",
        lambda: _rule(severity="medium"),
        "lint",
        ("severity", "trigger"),
    ),
    "rule tagged off the ATT&CK map": (
        "detection.merge",
        lambda: _rule(attack=["T1562.008"]),
        "lint",
        ("T1562.008",),
    ),
    "rule first-seen on an unindexed column": (
        "detection.merge",
        lambda: _rule(baseline={"first_seen": ["resource.uid"]}),
        "parse",
        ("index",),
    ),
    "rule on an unknown field": (
        "detection.merge",
        lambda: _rule(
            detection={
                "selection": {"api.operation": "DeleteUser", "no.such.field": "x"},
                "condition": "selection",
            }
        ),
        "parse",
        ("no.such.field",),
    ),
    "rule without a negative fixture": (
        "detection.merge",
        _without_negative,
        "fixtures",
        ("no negative fixture",),
    ),
    "pack reading ten years": (
        "hunt.merge",
        lambda: _pack(lookback="3650d"),
        "parse",
        ("lookback",),
    ),
    "pack first-seen on an unindexed column": (
        "hunt.merge",
        lambda: _pack(first_seen=["resource.uid"]),
        "lint",
        ("index",),
    ),
    "playbook step on another platform": (
        "playbook.merge",
        lambda: {
            "playbook": _ours(rules=["okta_mfa_push_fatigue", "aws_access_key_created"]),
            "dry_run": True,
        },
        "lint",
        ("can never run on a case from aws_access_key_created",),
    ),
    "playbook trigger above its rules": (
        "playbook.merge",
        lambda: {
            "playbook": _ours(trigger={"verdict": ["malicious"], "severity_at_least": "critical"}),
            "dry_run": True,
        },
        "lint",
        ("severity", "okta_mfa_push_fatigue"),
    ),
}
GATE_GAPS = {
    "rule below its playbook's trigger": (
        "CON-G1: detection.merge does not compare a rule's severity with its playbook's trigger"
    ),
    "rule tagged off the ATT&CK map": (
        "CON-G3: detection.merge does not check tags against content/attack_platforms.json"
    ),
    "pack first-seen on an unindexed column": (
        "CON-G4: hunt.merge accepts a first_seen pack on any column"
    ),
    "playbook trigger above its rules": (
        "CON-G1: playbook.merge does not compare its trigger with its rules' severities"
    ),
}


def _connect_cloudtrail(ctx) -> None:
    """A connected CloudTrail source, as test_hunts._connect makes one."""
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, settings)
           VALUES (%s, 'aws_cloudtrail', '{}') ON CONFLICT DO NOTHING""",
        (ctx.tenant_id,),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_event_at)
           VALUES (%s, 'aws_cloudtrail', %s, now() - interval '60 days')
           ON CONFLICT (tenant_id, source) DO UPDATE SET products = EXCLUDED.products,
               first_event_at = EXCLUDED.first_event_at, last_loaded_at = now()""",
        (ctx.tenant_id, list(layout.products_for("aws", "cloudtrail"))),
    )


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_a_gate_refuses_what_shipped_tests_refuse(mutant, ctx, clean):
    """CON-G11: a merge gate's dry run refuses, at the right stage, a defect the shipped
    content's tests refuse."""
    capability, payload, stage, words = MUTANTS[mutant]
    if capability == "hunt.merge":
        # A pack whose product no connected source sends is refused at lint for
        # that, which would hide the defect the mutant carries.
        _connect_cloudtrail(ctx)
    refused, refused_at, reasons = False, "", []
    try:
        call(capability, ctx, payload())
    except GateRefused as exc:
        refused, refused_at, reasons = True, exc.stage, exc.reasons
    caught = refused_at == stage and any(w.lower() in r.lower() for r in reasons for w in words)
    if mutant in GATE_GAPS:
        # A gap is a dry run that passes, so a refusal for another reason (a bad
        # fixture, a backtest) cannot keep the entry green.
        assert not refused, f"{capability} refused it at '{refused_at}' with {reasons}: " + (
            f"take '{mutant}' out of GATE_GAPS" if caught else "fix the mutant"
        )
    else:
        assert caught, f"{capability}: refused at '{refused_at}' with {reasons}, not at '{stage}'"
