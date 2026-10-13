"""Connector run loop: mapping, batching, cursor persistence and health (ING-1)."""

from __future__ import annotations

import json

import pytest

from shoc.db.pool import execute, fetch_all, fetch_one
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
    # Timestamped records, as a run that failed before its cursor moved reads them twice.
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
    assert row and row["events_seen"] == first.loaded, "a re-read is not new traffic"


def test_a_page_read_again_never_reaches_the_store(conn, store, config, clean, monkeypatch):
    """A filter that includes its start reads the newest event again every poll;
    on a warehouse each load of it was three statements (ING-1, ING-3, STO-3,
    D71, D150, D154)."""
    from shoc.ingest import connectors
    from shoc.ingest.batch import read_unique
    from shoc.ingest.connectors import base

    path = ROOT / "tests" / "fixtures" / "mappings" / "aws_cloudtrail.json"
    records = sorted(json.loads(path.read_text()), key=lambda r: r["eventTime"])
    late, rest = records[0], records[1:]
    pages = [rest, rest, [], rest, [late, *rest]]

    class Overlap:
        source = "aws_cloudtrail"

        def fetch(self, settings, secret, cursor, limit):
            return base.FetchResult(records=pages.pop(0), cursor={"since": rest[-1]["eventTime"]})

    batches: list[int] = []
    load_batch = store.load_batch
    monkeypatch.setattr(
        store, "load_batch", lambda p, *a: batches.append(len(read_unique(p))) or load_batch(p, *a)
    )
    monkeypatch.setattr(connectors, "get", lambda source: Overlap())

    def stamps() -> int:
        row = fetch_one(
            conn,
            "SELECT count(*) AS n FROM shoc.store_loads WHERE tenant_id = %s",
            (config.tenant_id,),
        )
        return int(row["n"]) if row else 0

    def poll() -> int:
        stats = run(conn, store, config.tenant_id, "aws_cloudtrail", {}, {})
        assert stats.error is None, stats.detail
        return stats.loaded

    assert poll() == len(rest) and batches == [len(rest)] and stamps() == 1
    assert poll() == 0 and batches == [len(rest)], "a page already stored is not sent again"
    assert poll() == 0, "an empty window"
    assert poll() == 0 and batches == [len(rest)], "an empty window forgets nothing"
    assert stamps() == 1, "a page that added nothing is not a load (D71)"
    assert poll() == 1 and batches == [len(rest), 1], (
        "an event delivered late, older than every stored one, is still loaded, and alone"
    )
    assert stamps() == 2


def test_each_event_of_a_workspace_activity_is_stored(conn, store, config, clean, monkeypatch):
    """A Workspace activity that changed two settings is two rows; live ingest
    stored only its first event (ING-3)."""
    from datetime import UTC, datetime

    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    activity = {
        "id": {
            "time": datetime.now(UTC).isoformat(),
            "uniqueQualifier": "act-1",
            "applicationName": "admin",
            "customerId": "C01",
        },
        "actor": {"email": "admin@example.com"},
        "events": [
            {"type": "SECURITY_SETTINGS", "name": "ENFORCE_STRONG_AUTHENTICATION"},
            {"type": "SECURITY_SETTINGS", "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS"},
        ],
    }

    class Workspace:
        source = "google_workspace"

        def fetch(self, settings, secret, cursor, limit):
            return base.FetchResult(records=[activity], cursor={"read": True})

    monkeypatch.setattr(connectors, "get", lambda source: Workspace())
    stats = run(conn, store, config.tenant_id, "google_workspace", {}, {})
    assert stats.error is None, stats.detail
    assert stats.fetched == 1 and stats.loaded == 2


def test_an_account_that_joins_later_keeps_its_own_start(conn, config, clean):
    """A member account added to an organisation trail learns from its own first
    event, not the trail's (D79); each account's start only moves earlier."""
    from datetime import UTC, datetime

    from shoc.ingest.connectors.base import history

    for events in (
        [("111111111111", "2026-06-01T00:00:00Z")],
        [("222222222222", "2026-10-05T00:00:00Z"), ("111111111111", "2026-05-01T00:00:00Z")],
        [("222222222222", "2026-10-09T00:00:00Z")],
    ):
        rows = [
            {"time": t, "metadata_product": "AWS CloudTrail", "cloud_account_uid": a}
            for a, t in events
        ]
        history(conn, config.tenant_id, "aws_cloudtrail", rows)
    row = fetch_one(
        conn,
        "SELECT account_starts FROM shoc.source_history WHERE tenant_id = %s AND source = %s",
        (config.tenant_id, "aws_cloudtrail"),
    )
    assert row
    starts = {
        a: f"{datetime.fromisoformat(t).astimezone(UTC):%Y-%m-%d}"
        for a, t in row["account_starts"].items()
    }
    assert starts == {"111111111111": "2026-05-01", "222222222222": "2026-10-05"}


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

    for source, interval in (("file", 1800), ("file:second", 3600)):
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
    assert listed["file"]["interval_seconds"] == 1800
    assert listed["file:second"]["interval_seconds"] == 3600


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


def test_a_replay_into_a_tenant_with_a_live_source_is_refused_unless_forced(conn, config, clean):
    """Lab data replayed into the main instance's tenant opened real cases there."""
    from shoc.cli import build_parser, cmd_replay
    from shoc.errors import ConfigError

    words = ["replay", "--scenario", "leaked_aws_key"]
    execute(
        conn,
        "INSERT INTO shoc.connector_config (tenant_id, source, enabled) VALUES (%s, 'okta', false)",
        (config.tenant_id,),
    )
    assert cmd_replay(build_parser().parse_args(words), config) == 0, "disabled is not live"
    execute(
        conn,
        "UPDATE shoc.connector_config SET enabled = true WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    with pytest.raises(ConfigError, match="--tenant"):
        cmd_replay(build_parser().parse_args(words), config)
    assert cmd_replay(build_parser().parse_args([*words, "--force"]), config) == 0


def configured(conn, config, source: str) -> None:
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, %s, true, '{"region": "us-east-1"}'::jsonb, NULL)""",
        (config.tenant_id, source),
    )


def test_a_source_with_one_refused_stream_is_ingesting_not_stale(
    conn, ctx, config, clean, monkeypatch
):
    """An Entra tenant without P2 refuses the risk streams for good; the source
    still loads the others, so health must not call it down (ING-1, OPS-1)."""
    import httpx

    from shoc.agents import ops
    from shoc.capabilities.registry import call
    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    refused = httpx.HTTPStatusError(
        "403", request=httpx.Request("GET", "https://x"), response=httpx.Response(403)
    )

    class Split:
        source = "google_workspace"

        def fetch(self, settings, secret, cursor, limit):
            if settings["application"] == "drive":
                raise refused
            return base.FetchResult(cursor={"since": "2026-09-20T10:00:00+00:00"})

    streams = base.Streams(Split(), "application", ("login", "drive"))
    monkeypatch.setattr(connectors, "get", lambda source: streams)
    configured(conn, config, "google_workspace")
    out = call("source.sync", ctx, {"source": "google_workspace"})
    assert out.data.error and out.data.error.startswith("drive: google_workspace rejected")
    assert "Not all of it was read" in out.summary, "said in the result, not raised"
    row = fetch_one(
        conn,
        "SELECT last_ok_at, last_error FROM shoc.connector_state WHERE tenant_id=%s AND source=%s",
        (config.tenant_id, "google_workspace"),
    )
    assert row and row["last_ok_at"] is not None and "drive" in row["last_error"]
    health = {h.source: h for h in ops.source_health(conn, config.tenant_id)}
    assert health["google_workspace"].stale is False


def test_a_source_still_behind_queues_the_rest_and_wakes_detection_when_caught_up(
    conn, ctx, config, clean, monkeypatch
):
    """A run hands the worker back at its page or time cap; the rest is read in
    a job of its own instead of a cycle later, and detection wakes once (ING-1, D153)."""
    from shoc.capabilities.registry import call
    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    path = ROOT / "tests" / "fixtures" / "mappings" / "aws_cloudtrail.json"
    records = json.loads(path.read_text())

    class Behind:
        source = "aws_cloudtrail"

        def fetch(self, settings, secret, cursor, limit):
            n = int(cursor.get("n", 0))
            return base.FetchResult(records=[records[n]], cursor={"n": n + 1}, more=n < 2)

    monkeypatch.setattr(connectors, "get", lambda source: Behind())
    configured(conn, config, "aws_cloudtrail")

    def queued(kind: str) -> list[dict]:
        return [
            row["payload"]
            for row in fetch_all(
                conn,
                "SELECT payload FROM shoc.jobs WHERE tenant_id = %s AND kind = %s",
                (config.tenant_id, kind),
            )
        ]

    first = call("source.sync", ctx, {"source": "aws_cloudtrail", "max_pages": 2})
    assert first.data.pages == 2 and "the rest is queued" in first.summary
    assert queued("source.sync") == [{"source": "aws_cloudtrail"}]
    assert not queued("detect.run"), "a source catching up wakes detection once, at the end"

    last = call("source.sync", ctx, {"source": "aws_cloudtrail", "max_pages": 2})
    assert last.data.pages == 1 and last.data.loaded == 1
    assert "the rest is queued" not in last.summary
    assert len(queued("source.sync")) == 1, "nothing more is queued once it has caught up"
    assert queued("detect.run"), "caught up: detection reads what it loaded"


def test_a_subscription_whose_cursor_never_moves_queues_the_rest_every_time(
    conn, ctx, config, clean, monkeypatch
):
    """A Pub/Sub pull has no cursor: every capped run says {} and still has more.
    Each one queues the rest once the last continuation has run (ING-1, ING-5)."""
    from shoc.capabilities.registry import call
    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    path = ROOT / "tests" / "fixtures" / "mappings" / "aws_cloudtrail.json"
    records = json.loads(path.read_text())

    class Subscription:
        source = "aws_cloudtrail"

        def fetch(self, settings, secret, cursor, limit):
            return base.FetchResult(records=[records[0]], cursor={}, more=True)

    monkeypatch.setattr(connectors, "get", lambda source: Subscription())
    configured(conn, config, "aws_cloudtrail")

    def pending() -> int:
        row = fetch_one(
            conn,
            "SELECT count(*) AS n FROM shoc.jobs WHERE tenant_id = %s AND kind = 'source.sync' "
            "AND state = 'pending'",
            (config.tenant_id,),
        )
        return int(row["n"]) if row else 0

    first = call("source.sync", ctx, {"source": "aws_cloudtrail", "max_pages": 2})
    assert "the rest is queued" in first.summary and pending() == 1
    again = call("source.sync", ctx, {"source": "aws_cloudtrail", "max_pages": 2})
    assert "the rest is queued" in again.summary
    assert pending() == 1, "a sync already waiting reads the rest; a second copy is not queued"
    execute(
        conn,
        "UPDATE shoc.jobs SET state = 'done' WHERE tenant_id = %s AND kind = 'source.sync'",
        (config.tenant_id,),
    )
    call("source.sync", ctx, {"source": "aws_cloudtrail", "max_pages": 2})
    assert pending() == 1, "the continuation ran; the next capped run queues another"


def test_a_new_credential_keeps_the_push_key(conn, config, ctx, clean):
    """GitHub signs its webhook with the push key; a new audit-log token replaced it."""
    from shoc.capabilities.registry import call
    from shoc.ingest.connectors.base import read_config

    key = call("source.push_key", ctx, {"source": "github"}).data.push_key
    settings = {"org": "example-org"}
    call(
        "source.configure",
        ctx,
        {"source": "github", "settings": settings, "secret": {"token": "t"}, "enabled": False},
    )
    _, secret, _ = read_config(conn, config.tenant_id, "github", config.master_key)
    assert secret == {"push_key": key, "token": "t"}


def test_a_new_credential_replaces_a_stored_one_that_will_not_open(conn, config, ctx, clean):
    """A blob sealed under another master key is lost; configuring again is the way back."""
    from shoc.capabilities.registry import call
    from shoc.ingest.connectors.base import read_config

    call("source.push_key", ctx, {"source": "github"})
    execute(
        conn,
        "UPDATE shoc.connector_config SET secret = %s WHERE tenant_id = %s AND source = 'github'",
        (b"not a sealed secret", config.tenant_id),
    )
    call(
        "source.configure",
        ctx,
        {
            "source": "github",
            "settings": {"org": "example-org"},
            "secret": {"token": "t"},
            "enabled": False,
        },
    )
    _, secret, _ = read_config(conn, config.tenant_id, "github", config.master_key)
    assert secret == {"token": "t"}


@pytest.mark.parametrize(
    ("settings", "warned"),
    [
        ({"verify_tls": False}, True),
        ({"verify_tls": False, "ca_cert": "-----BEGIN CERTIFICATE-----"}, False),
        ({}, False),
    ],
)
def test_a_wazuh_source_that_skips_tls_checks_says_so(ctx, clean, settings, warned):
    """verify_tls false sends the indexer password to whoever answers."""
    from shoc.capabilities.registry import call

    out = call(
        "source.configure",
        ctx,
        {
            "source": "wazuh",
            "settings": {"indexer_url": "https://192.0.2.20:9200", **settings},
            "secret": {"username": "shoc", "password": "p"},
            "enabled": False,
        },
    )
    assert ("ca_cert" in out.summary) is warned
