"""Pushes kept for the cycle, loads stamped once, retention floored, secrets kept
to their host (ING-2, DET-3, STO-2, SEC-1)."""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest import mock

import pytest
from starlette.testclient import TestClient

from shoc import worker
from shoc.api.rest import build_app
from shoc.capabilities.events import GITHUB_WEBHOOK, SPOOL_ERROR, SPOOL_TRIES, flush_spool
from shoc.capabilities.registry import Caller, Context, call
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.errors import Denied, ValidationError
from shoc.ingest.connectors import github
from tests.conformance.test_rest import _webhook
from tests.support import ROOT

pytestmark = pytest.mark.postgres

CLOUDTRAIL = ROOT / "tests" / "fixtures" / "mappings" / "aws_cloudtrail.json"


def _count(conn: Any, sql: str, tenant: str) -> int:
    row = fetch_one(conn, sql, (tenant,))
    return int(row["n"]) if row else 0


def test_a_batch_stored_already_is_no_new_load(conn, ctx, config, clean):
    """A redelivery inserts nothing, and stamped as a load it woke every rule (D71)."""
    records = json.loads(CLOUDTRAIL.read_text())
    first = call("events.ingest", ctx, {"source": "aws_cloudtrail", "records": records})
    again = call("events.ingest", ctx, {"source": "aws_cloudtrail", "records": records})
    assert first.data.loaded > 0 and again.data.loaded == 0
    loads = "SELECT count(*) AS n FROM shoc.store_loads WHERE tenant_id = %s"
    assert _count(conn, loads, config.tenant_id) == 1


def test_a_warehouse_keeps_a_push_for_the_cycle(conn, ctx, store, config, clean, monkeypatch):
    """One load per cycle, and a load that fails keeps the delivery for the next (ING-2)."""
    tenant = config.tenant_id
    key = call("source.push_key", ctx, {"source": "github", "rotate": True}).data.push_key
    body = json.dumps(
        {
            "action": "publicized",
            "repository": {"full_name": "acme/payments"},
            "sender": {"login": "mallory", "id": 4242},
        }
    ).encode()
    delivery = "c0ffee00-0000-4000-8000-000000000066"
    backend = config.backend
    if backend == "postgres":
        monkeypatch.setattr(config, "backend", "databricks")  # the webhook spools; nothing loads
    with TestClient(build_app(config), base_url="https://shoc.example.com") as github:
        resp = github.post(
            f"/ingest/github?tenant={tenant}", content=body, headers=_webhook(key, body, delivery)
        )
    monkeypatch.setattr(config, "backend", backend)
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["spooled"] == 1 and resp.json()["data"]["loaded"] == 0
    kept = "SELECT count(*) AS n FROM shoc.push_spool WHERE tenant_id = %s"
    assert _count(conn, kept, tenant) == 1
    events = "SELECT event_uid FROM ocsf_events WHERE tenant_id = :t"
    assert store.query(events, {"t": tenant}).rows == []
    published = fetch_all(
        conn,
        "SELECT 1 FROM shoc.stream_events WHERE tenant_id = %s AND type = 'events.loaded'",
        (tenant,),
    )
    assert published == [], "a kept delivery wakes no detection run of its own"

    job = {"tenant_id": tenant, "kind": "detect.run", "payload": {}}
    with mock.patch("shoc.ingest.batch.load", side_effect=RuntimeError("store down")):
        assert "not loaded" in worker.handle(job, config)
    assert _count(conn, kept, tenant) == 1, "a failed load keeps the delivery"

    assert "Loaded 1 pushed event(s)" in worker.handle(job, config)
    assert _count(conn, kept, tenant) == 0
    rows = store.query(events, {"t": tenant}).rows
    assert [r["event_uid"] for r in rows] == [f"github-webhook-{delivery}"]


def _delivery() -> list[dict[str, Any]]:
    body = json.dumps(
        {
            "action": "publicized",
            "repository": {"full_name": "acme/payments"},
            "sender": {"login": "mallory", "id": 4242},
        }
    ).encode()
    headers = {"x-github-event": "repository", "x-github-delivery": str(uuid.uuid1())}
    return github.from_webhook(headers, body)


def test_only_githubs_webhook_keeps_a_push(ctx, config, clean):
    """Kept records load as GitHub's own push: its history and its health (wh-2)."""
    records = _delivery()
    keep = {"source": "github", "records": records, "spool": True}
    with pytest.raises(Denied):
        call("events.ingest", ctx, keep)
    # A token can be given the webhook's name; it is still not the webhook.
    named = Caller(kind="service", id=GITHUB_WEBHOOK.id, scopes=("events:write",))
    with pytest.raises(Denied):
        call("events.ingest", Context(config.tenant_id, named, config, _db=ctx.db), keep)
    push = Context(config.tenant_id, GITHUB_WEBHOOK, config, _db=ctx.db)
    with pytest.raises(Denied):
        call("events.ingest", push, {**keep, "source": "aws_cloudtrail"})
    assert call("events.ingest", push, keep).data.spooled == 1


def test_one_bad_kept_push_holds_back_no_other(conn, ctx, config, clean, monkeypatch):
    """A delivery that always failed blocked every later one until the prune (wh-2)."""
    tenant = config.tenant_id
    push = Context(tenant, GITHUB_WEBHOOK, config, _db=ctx.db)
    for records in (_delivery() * 3, _delivery(), _delivery()):
        call("events.ingest", push, {"source": "github", "records": records, "spool": True})
    monkeypatch.setattr(config, "max_ingest_records", 2)  # the first is refused every time

    # Another detection run of the tenant holds the spool: this one loads nothing.
    lock = "hashtext('shoc.push_spool'), hashtext(%s)"
    fetch_one(conn, f"SELECT pg_advisory_lock({lock})", (tenant,))
    try:
        assert flush_spool(ctx) == (0, 0)
    finally:
        fetch_one(conn, f"SELECT pg_advisory_unlock({lock})", (tenant,))

    # First in line with nothing loaded yet, it reads as a store that is down.
    assert flush_spool(ctx) == (0, 1)
    assert flush_spool(ctx) == (2, 1), "tried alone, after the others"
    kept = "SELECT attempts FROM shoc.push_spool WHERE tenant_id = %s"
    assert [r["attempts"] for r in fetch_all(ctx.db, kept, (tenant,))] == [2]
    for _ in range(SPOOL_TRIES - 2):
        flush_spool(ctx)
    assert flush_spool(ctx) == (0, 0), "set aside: tried once a day"
    state = "SELECT last_error FROM shoc.connector_state WHERE tenant_id = %s AND source = %s"
    row = fetch_one(ctx.db, state, (tenant, "github"))
    assert row and str(row["last_error"]).startswith(SPOOL_ERROR), "on the source's health"
    execute(ctx.db, "DELETE FROM shoc.push_spool WHERE tenant_id = %s", (tenant,))  # pruned
    flush_spool(ctx)
    row = fetch_one(ctx.db, state, (tenant, "github"))
    assert row and row["last_error"] is None


def test_retention_never_keeps_less_than_configured(conn, ctx, config, clean):
    """One call steered by a log line would delete the evidence; lowering it is config.apply's."""
    tenant = config.tenant_id
    schedule = f"{tenant}:retention"
    before = fetch_one(
        conn, "SELECT payload FROM shoc.schedules WHERE schedule_id = %s", (schedule,)
    )
    execute(
        conn,
        """INSERT INTO shoc.schedules
               (schedule_id, tenant_id, kind, payload, interval_seconds, enabled)
           VALUES (%s, %s, 'retention', %s, 86400, false)
           ON CONFLICT (schedule_id) DO UPDATE SET payload = EXCLUDED.payload""",
        (schedule, tenant, json.dumps({"days": 120, "set_by": "config.apply"})),
    )
    try:
        with pytest.raises(ValidationError, match="configured 120"):
            call("events.retain", ctx, {"days": 1})
        with pytest.raises(ValidationError):
            call("events.retain", ctx, {"days": 90})
        kept = call("events.retain", ctx, {"days": 400})
        assert kept.data.unit == ("partition(s)" if config.backend == "postgres" else "row(s)")
        # The nightly job keeps what is configured: its own schedule's days.
        summary = worker.handle({"tenant_id": tenant, "kind": "retention", "payload": {}}, config)
        assert "older than 120 day(s)" in summary
    finally:
        if before:
            execute(
                conn,
                "UPDATE shoc.schedules SET payload = %s WHERE schedule_id = %s",
                (json.dumps(before["payload"]), schedule),
            )
        else:
            execute(conn, "DELETE FROM shoc.schedules WHERE schedule_id = %s", (schedule,))


def test_a_stored_source_secret_never_goes_to_a_new_host(ctx, clean):
    """RFC 0017's case: org_url repointed, and the next sync carried the token there."""
    okta = {"source": "okta", "secret": {"api_token": "t"}, "verify": False, "enabled": False}
    call("source.configure", ctx, {**okta, "settings": {"org_url": "https://acme.okta.com"}})
    moved = {**okta, "secret": {}, "settings": {"org_url": "https://okta.example.net"}}
    with pytest.raises(ValidationError, match="org_url"):
        call("source.configure", ctx, moved)
    same = {**okta, "secret": {}, "settings": {"org_url": "https://acme.okta.com/", "x": 1}}
    call("source.configure", ctx, same)
    call("source.configure", ctx, {**moved, "secret": {"api_token": "new"}})


def test_a_push_key_alone_lets_the_host_change(ctx, clean):
    """GitHub signs with the push key and shoc checks it: it is never sent anywhere."""
    call("source.push_key", ctx, {"source": "github", "rotate": True})
    github = {"source": "github", "secret": {}, "verify": False, "enabled": False}
    call("source.configure", ctx, {**github, "settings": {"base_url": "https://github.com"}})
    call("source.configure", ctx, {**github, "settings": {"base_url": "https://git.example.net"}})


def test_a_credential_is_not_tried_on_a_new_host_with_its_stored_secret(ctx, clean, monkeypatch):
    """credential.configure reads with what it saved at once: the refusal comes first."""
    import shoc.actions

    secret = {"client_id": "c", "client_secret": "s"}
    call(
        "credential.configure",
        ctx,
        {
            "provider": "crowdstrike",
            "settings": {"base_url": "https://api.eu-1.crowdstrike.com"},
            "secret": secret,
            "verify": False,
        },
    )
    tried: list[Any] = []
    monkeypatch.setattr(shoc.actions, "probe", lambda creds: tried.append(creds) or "ok")
    with pytest.raises(ValidationError, match="base_url"):
        call(
            "credential.configure",
            ctx,
            {"provider": "crowdstrike", "settings": {"base_url": "https://falcon.example.net"}},
        )
    assert tried == [], "the stored client secret was sent to the new host"


def test_an_intel_feed_key_stays_with_its_host(ctx, clean):
    feed = {"feed": "misp", "secret": {"api_key": "k"}}
    call("intel.configure", ctx, {**feed, "settings": {"url": "https://misp.example.org"}})
    with pytest.raises(ValidationError, match="url"):
        call(
            "intel.configure",
            ctx,
            {"feed": "misp", "settings": {"url": "https://misp.example.net"}},
        )
