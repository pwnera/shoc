"""Connector run loop: mapping, batching, cursor persistence and health (ING-1)."""

from __future__ import annotations

import pytest

from shoc.db.pool import fetch_one
from shoc.ingest.connectors.base import read_state, run
from tests.support import ROOT

pytestmark = pytest.mark.postgres

SCENARIO = ROOT / "evals" / "scenarios" / "leaked_aws_key" / "events.json"
SETTINGS = {"path": str(SCENARIO), "mapping": "aws_cloudtrail"}


def test_file_connector_loads_maps_and_records_a_cursor(conn, store, config, clean):
    stats = run(conn, store, config.tenant_id, "file", SETTINGS, {}, limit=1000)
    assert stats.error is None
    assert stats.loaded == stats.fetched > 100, "a recorded scenario is expanded on replay"
    assert read_state(conn, config.tenant_id, "file")["offset"] == stats.fetched


def test_a_second_run_resumes_and_loads_nothing_new(conn, store, config, clean):
    first = run(conn, store, config.tenant_id, "file", SETTINGS, {}, limit=1000)
    second = run(conn, store, config.tenant_id, "file", SETTINGS, {}, limit=1000)
    assert second.fetched == 0, "the stored cursor must survive between runs"
    row = fetch_one(
        conn,
        "SELECT events_seen, last_error FROM shoc.connector_state WHERE tenant_id=%s AND source=%s",
        (config.tenant_id, "file"),
    )
    assert row and row["last_error"] is None
    assert row["events_seen"] == first.fetched


def test_events_read_again_are_not_counted_again(conn, store, config, clean):
    # Timestamped records, as a pull connector's overlap would read them twice.
    recorded = {
        "path": str(ROOT / "tests" / "fixtures" / "mappings" / "aws_cloudtrail.json"),
        "mapping": "aws_cloudtrail",
    }
    first = run(conn, store, config.tenant_id, "file", recorded, {}, limit=1000)
    again = run(conn, store, config.tenant_id, "file", recorded, {}, cursor={}, limit=1000)
    assert first.loaded == first.fetched > 0
    assert again.fetched == first.fetched and again.loaded == 0, "the store drops a re-read"
    row = fetch_one(
        conn,
        "SELECT events_seen FROM shoc.connector_state WHERE tenant_id=%s AND source=%s",
        (config.tenant_id, "file"),
    )
    assert row and row["events_seen"] == first.loaded, "an overlap re-read is not new traffic"


def test_verifying_a_credential_leaves_the_cursor_alone(conn, config, ctx, clean):
    from shoc.capabilities.registry import call

    out = call(
        "source.configure",
        ctx,
        {"source": "file", "settings": SETTINGS, "secret": {"unused": "x"}},
    )
    assert out.data.verified is True
    assert read_state(conn, config.tenant_id, "file") == {}, (
        "a one-record probe must not leave a cursor the scheduled sync would resume from"
    )


def test_a_broken_source_is_recorded_as_health_not_raised(conn, store, config, clean):
    stats = run(
        conn,
        store,
        config.tenant_id,
        "file",
        {"path": "/nope/missing.json", "mapping": "aws_cloudtrail"},
        {},
    )
    assert stats.error and "no such path" in stats.error
    row = fetch_one(
        conn,
        "SELECT last_error, last_ok_at FROM shoc.connector_state WHERE tenant_id=%s AND source=%s",
        (config.tenant_id, "file"),
    )
    assert row and row["last_error"] and row["last_ok_at"] is None


def test_secrets_round_trip_through_the_encrypted_column(conn, config, ctx, clean):
    from shoc.capabilities.registry import call
    from shoc.ingest.connectors.base import read_config

    call(
        "source.configure",
        ctx,
        {
            "source": "okta",
            "settings": {"org_url": "https://acme.okta.com"},
            "secret": {"api_token": "00-secret"},
            "verify": False,
        },
    )
    settings, secret, enabled = read_config(conn, config.tenant_id, "okta", config.master_key)
    assert settings["org_url"] == "https://acme.okta.com"
    assert secret["api_token"] == "00-secret"
    assert enabled
    stored = fetch_one(
        conn,
        "SELECT secret FROM shoc.connector_config WHERE tenant_id=%s AND source=%s",
        (config.tenant_id, "okta"),
    )
    assert stored and b"00-secret" not in bytes(stored["secret"]), (
        "the token must not be at rest in the clear"
    )


def test_two_accounts_of_one_connector_keep_their_own_config_and_cursor(conn, config, ctx, clean):
    from shoc.capabilities.registry import call
    from shoc.ingest.connectors.base import read_config

    for source, interval in (("file", 300), ("file:second", 600)):
        call(
            "source.configure",
            ctx,
            {"source": source, "settings": SETTINGS, "interval_seconds": interval, "verify": False},
        )
    assert read_config(conn, config.tenant_id, "file:second", config.master_key)[0] == SETTINGS
    first = call("source.sync", ctx, {"source": "file:second"})
    assert first.data.fetched > 0
    assert read_state(conn, config.tenant_id, "file:second")["offset"] == first.data.fetched
    assert read_state(conn, config.tenant_id, "file") == {}, "each account has its own cursor"
    listed = {r["source"]: r for r in call("source.list", ctx, {}).data.configured}
    assert listed["file"]["interval_seconds"] == 300
    assert listed["file:second"]["interval_seconds"] == 600


def test_an_account_label_must_be_plain(ctx, clean):
    from shoc.capabilities.registry import call
    from shoc.errors import ConfigError

    with pytest.raises(ConfigError, match="connector:label"):
        call(
            "source.configure",
            ctx,
            {"source": "file:Bad Label", "settings": SETTINGS, "verify": False},
        )


def test_a_disabled_source_is_neither_scheduled_nor_pulled_nor_late(conn, config, ctx, clean):
    """`connector_config.enabled` used to be stored and never read (ING-1)."""
    from shoc.agents.ops import source_health
    from shoc.capabilities.registry import call

    def scheduled() -> bool:
        row = fetch_one(
            conn,
            "SELECT enabled FROM shoc.schedules WHERE schedule_id = %s",
            (f"{config.tenant_id}:sync:file",),
        )
        return bool(row and row["enabled"])

    call("source.configure", ctx, {"source": "file", "settings": SETTINGS, "verify": False})
    assert scheduled()
    assert call("source.sync", ctx, {"source": "file"}).data.fetched > 0

    off = call(
        "source.configure",
        ctx,
        {"source": "file", "settings": SETTINGS, "enabled": False, "verify": False},
    )
    assert off.data.enabled is False and not scheduled()
    pulled = call("source.sync", ctx, {"source": "file"})
    assert pulled.data.fetched == 0 and "disabled" in pulled.summary
    assert "file" not in {s.source for s in source_health(conn, config.tenant_id, 0)}

    call("source.configure", ctx, {"source": "file", "settings": SETTINGS, "verify": False})
    assert scheduled(), "turning it back on schedules it again"


def test_a_snapshot_replaces_what_the_source_listed_before(conn, ctx, config, clean, monkeypatch):
    """D49: a snapshot is what exists now, so a user removed at the vendor leaves."""
    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    listed = [base.Asset("user:a@example.com", "user"), base.Asset("user:b@example.com", "user")]

    class Lister:
        source = "okta"

        def snapshot(self, settings, secret):
            return listed

    monkeypatch.setattr(connectors, "get", lambda source: Lister())
    assert base.snapshot_due(conn, config.tenant_id, "okta")
    assert base.take_snapshot(conn, config.tenant_id, "okta", {}, {}) == 2
    assert not base.snapshot_due(conn, config.tenant_id, "okta"), "once a day"
    listed.pop()
    base.take_snapshot(conn, config.tenant_id, "okta", {}, {})
    from shoc.capabilities.registry import call

    rows = call("snapshot.list", ctx, {"source": "okta"}).data.rows
    assert [r["entity"] for r in rows] == ["user:a@example.com"]
