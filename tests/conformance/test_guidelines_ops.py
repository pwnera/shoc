"""Operability guidelines that need Postgres (OPS-G1, OPS-G3, OPS-G4)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.capabilities.registry import all_capabilities, call
from shoc.db.pool import execute, fetch_one

pytestmark = pytest.mark.postgres


# -- OPS-G1: a stopped shoc is visible from outside shoc -----------------------
def test_a_model_failure_never_skips_the_coverage_page(conn, config, clean, monkeypatch):
    """OPS-G1: a model setting Ops' review cannot read still leaves the dark-source page."""
    from shoc import worker
    from shoc.agents import ops
    from shoc.errors import ConfigError

    tenant = config.tenant_id
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, created_at)
           VALUES (%s, 'okta', now() - interval '30 hours')""",
        (tenant,),
    )
    execute(
        conn,
        """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_error)
           VALUES (%s, 'okta', '{}', 'okta rejected the credential (401).')""",
        (tenant,),
    )

    def review(*_a: object, **_k: object) -> dict:
        raise ConfigError("unknown LLM provider 'antropic'")

    monkeypatch.setattr(ops, "review", review)
    monkeypatch.setattr(config, "heartbeat_url", "")
    job = {"kind": "ops.check", "tenant_id": tenant, "payload": {}}
    with pytest.raises(RuntimeError, match="review: ConfigError"):
        worker.handle(job, config)
    page = fetch_one(
        conn,
        """SELECT condition, body FROM shoc.notices
           WHERE tenant_id = %s AND kind = 'page' AND group_key = 'source:okta'""",
        (tenant,),
    )
    assert page, "the review's ConfigError skipped the dark-source page (sre-10)"
    assert page["condition"] == "coverage_dark"
    assert page["body"].startswith("okta has never succeeded since it was set up")


# -- OPS-G3: an alert is something a person can act on -------------------------
def test_a_healthy_new_install_says_nothing(ctx, conn, store, config, pager, monkeypatch):
    """OPS-G3: a new install in good health raises nothing: no alert, no decision, no page.

    A pager, an outside monitor and a response credential for each source read;
    a polled source that pulled five minutes ago, a webhook-only GitHub quiet for
    three hours, detection finishing on time, and 50 high findings that are
    shoc's own credentials at work. Response is on (SHOC_DRY_RUN=0), since dry
    run left on is a decision for a person and is reported as one.
    """
    from shoc.agents import manager, reporter
    from shoc.cases import credentials
    from shoc.db import jobs
    from shoc.detect import osint

    tenant = config.tenant_id
    monkeypatch.setattr(config, "heartbeat_url", "https://hc.example.test/ping/0000-test")
    monkeypatch.setattr(config, "dry_run", False)
    # What this process's earlier tests left in the lookup lists' load state.
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    monkeypatch.setattr(osint, "_FAILED", {})
    for provider in ("okta", "github"):
        credentials.store(conn, tenant, provider, {}, {"api_token": "test"}, config.master_key)
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, interval_seconds, created_at)
           VALUES (%s, 'okta', 900, now() - interval '2 days'),
                  (%s, 'github', 900, now() - interval '2 days')""",
        (tenant, tenant),
    )
    execute(
        conn,
        """INSERT INTO shoc.connector_state
               (tenant_id, source, cursor, last_run_at, last_ok_at, events_seen)
           VALUES (%s, 'okta', '{}', now() - interval '5 minutes',
                   now() - interval '5 minutes', 40),
                  (%s, 'github', '{}', NULL, now() - interval '3 hours', 12)""",
        (tenant, tenant),
    )
    sync = {"source": "okta"}
    jobs.upsert_schedule(conn, f"{tenant}:sync:okta", tenant, "source.sync", 900, sync)
    jobs.upsert_schedule(conn, f"{tenant}:detect", tenant, "detect.run", 900, {})
    execute(
        conn,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, created_at, finished_at)
           VALUES (%s, 'detect.run', 'done', now() - interval '2 days', now() - interval '2 days'),
                  (%s, 'detect.run', 'done', now() - interval '10 minutes',
                   now() - interval '10 minutes')""",
        (tenant, tenant),
    )
    for n in range(50):
        execute(
            conn,
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key, status,
                    window_start, window_end, first_seen, last_seen, event_count, event_uids)
               VALUES (%s, %s, 'google_oauth_token_authorized', 'Token authorized', 'high',
                       'u', 'self', now(), now(), now(), now(), 1, ARRAY['e1'])""",
            (f"F-own-{n:02d}-{tenant}", tenant),
        )
    try:
        alerts = call("ops.alerts", ctx, {}).data.alerts
        assert not [a for a in alerts if a["severity"] in ("medium", "high", "critical")], alerts
        assert reporter.exceptions(conn, tenant, config) == []
        status = call("health.status", ctx, {})
        assert status.data.ok, status.summary
        assert status.data.findings["high"] == 0, "shoc's own findings are not high findings"
        assert manager.coverage(conn, tenant, config) == 0, "a healthy install pages nobody"
    finally:
        execute(conn, "DELETE FROM shoc.schedules WHERE tenant_id = %s", (tenant,))


# -- OPS-G4: a read result fits an MCP client ---------------------------------
# What an MCP client takes in one tool result before it truncates (live-13).
RESULT_BUDGET = 100_000
REPORT_KINDS = ("shift", "weekly", "exec", "exception")

# Each is past the budget with the volume seeded below.
KNOWN_OVERSIZE = {
    "rule.list": "OPS-G4 known gap: every shipped rule whole, about 640 KB of JSON",
    "playbook.list": "OPS-G4 known gap: every playbook whole, about 110 KB of JSON",
    "capability.list": "OPS-G4 known gap: every capability's input and output schema, "
    "about 150 KB (contract/v1.json)",
    "action.list": "OPS-G4 known gap: a person's caller, as SHOC_MCP_ROLE and a person's "
    "token are, gets whole rows; only an external agent's are cut to LISTED_CHARS",
}


def _production_volume(conn: Any, tenant: str) -> None:
    """300 findings carrying 3 KB of evidence, 300 actions with a platform's
    answer, 100 notices with 3 KB bodies and 50 cases, as on the main instance."""
    from shoc.agents import manager

    pad = "x" * 3000
    for n in range(50):
        execute(
            conn,
            """INSERT INTO shoc.cases (case_uid, tenant_id, title, severity, entity_key, summary)
               VALUES (%s, %s, %s, 'high', %s, %s)""",
            (
                f"CASE-size-{n:04d}-{tenant}",
                tenant,
                f"Case {n}",
                f"user:u{n}@example.com",
                pad[:1500],
            ),
        )
    for n in range(300):
        case_uid = f"CASE-size-{n % 50:04d}-{tenant}"
        execute(
            conn,
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key, case_uid,
                    evidence, window_start, window_end, first_seen, last_seen, event_count,
                    event_uids)
               VALUES (%s, %s, 'google_oauth_token_authorized', 'Token authorized', 'high',
                       %s, %s, %s::jsonb, now(), now(), now(), now(), 1, ARRAY['e1'])""",
            (
                f"F-size-{n:04d}-{tenant}",
                tenant,
                f"user:u{n % 50}@example.com",
                case_uid,
                json.dumps({"kind": "match", "sample": {"unmapped": pad}}),
            ),
        )
        execute(
            conn,
            """INSERT INTO shoc.actions
                   (action_uid, tenant_id, case_uid, type, target, state, params, result)
               VALUES (%s, %s, %s, 'aws.disable_access_key', 'AKIAIOSFODNN7EXAMPLE', 'done',
                       %s::jsonb, %s::jsonb)""",
            (
                f"ACT-size-{n:04d}-{tenant}",
                tenant,
                case_uid,
                json.dumps({"user_name": "ci"}),
                json.dumps({"answer": pad[:2500]}),
            ),
        )
    for n in range(100):
        manager.tell(conn, tenant, "Hunter", "digest", f"{n}: {pad}", deliver=False)


def test_every_list_fits_an_mcp_result(ctx, conn, config, clean):
    """OPS-G4: every list, report and health read fits one MCP result at production volume."""
    _production_volume(conn, config.tenant_id)
    reads: list[tuple[str, str, dict[str, Any]]] = [
        (cap.name, cap.name, {})
        for cap in all_capabilities()
        if cap.name.endswith(".list") or cap.name in ("health.status", "health.sources")
    ]
    reads += [(f"report.get {kind}", "report.get", {"kind": kind}) for kind in REPORT_KINDS]
    found = {}
    for label, name, payload in reads:
        size = len(json.dumps(call(name, ctx, payload).to_json(), default=str))
        if size >= RESULT_BUDGET:
            found[label] = f"{label} answers {size} characters; an MCP client reads {RESULT_BUDGET}"
    new = sorted(set(found) - set(KNOWN_OVERSIZE))
    assert not new, "past an MCP result:\n" + "\n".join(f"  {found[k]}" for k in new)
    gone = sorted(set(KNOWN_OVERSIZE) - set(found))
    assert not gone, f"fits now; take out of KNOWN_OVERSIZE: {', '.join(gone)}"
