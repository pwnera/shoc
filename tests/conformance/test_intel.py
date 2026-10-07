"""Indicators, matching and retro-hunts against a real store (DET-4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shoc.capabilities.registry import call
from shoc.db.pool import fetch_all, fetch_one
from shoc.detect import intel
from shoc.ingest import batch, ocsf

pytestmark = pytest.mark.postgres

BAD_IP = "203.0.113.55"


def _events(tenant: str, now: datetime, ip: str = BAD_IP, count: int = 3, age_days: int = 0):
    mapping = ocsf.load_mapping("aws_cloudtrail")
    from shoc.ingest.replay import expand

    records = expand(
        [
            {
                "eventID": f"intel-{ip}",
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": ip,
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "deploy-ci",
                    "accessKeyId": "AKIATEST",
                },
                "_repeat": count,
            }
        ],
        "aws_cloudtrail",
        now - timedelta(days=age_days),
    )
    return [mapping.map_record(r, tenant) for r in records]


def _indicator(conn, tenant, value=BAD_IP, kind="ip"):
    return intel.store_indicators(
        conn,
        tenant,
        [
            intel.Indicator(
                type=kind,
                value=value,
                source="test",
                confidence=0.9,
                severity="high",
                description="test indicator",
            )
        ],
    )


def test_storing_an_indicator_twice_only_counts_once(ctx, config, clean):
    assert _indicator(ctx.db, config.tenant_id) == 1
    assert _indicator(ctx.db, config.tenant_id) == 0


def test_a_match_in_the_window_becomes_a_cited_finding(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now))
    _indicator(ctx.db, config.tenant_id)
    hits = intel.match_window(ctx.db, store, config.tenant_id, now - timedelta(hours=1))
    assert len(hits) == 3
    findings = intel.findings_from_hits(ctx.db, config.tenant_id, hits)
    assert len(findings) == 1
    row = fetch_one(ctx.db, "SELECT * FROM shoc.findings WHERE finding_uid = %s", (findings[0],))
    assert row and row["rule_id"] == "ioc_match:ip"
    assert row["event_uids"] and row["severity"] == "high"
    assert "user:deploy-ci" in row["entities"] and f"ip:{BAD_IP}" in row["entities"]


def test_events_that_touch_nothing_known_produce_nothing(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now, ip="198.51.100.7"))
    _indicator(ctx.db, config.tenant_id)
    hits = intel.match_window(ctx.db, store, config.tenant_id, now - timedelta(hours=1))
    assert hits == []


def test_a_retro_hunt_finds_the_indicator_that_arrived_late(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now, age_days=21))
    _indicator(ctx.db, config.tenant_id)
    report = intel.retro_hunt(ctx.db, store, config.tenant_id, days=90)
    assert report["indicators"] == 1 and report["hits"] == 3
    assert len(report["findings"]) == 1
    row = fetch_one(
        ctx.db, "SELECT rule_id FROM shoc.findings WHERE finding_uid=%s", (report["findings"][0],)
    )
    assert row and row["rule_id"] == "ioc_retrohunt:ip"


def test_a_retro_hunt_does_not_repeat_itself(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now, age_days=5))
    _indicator(ctx.db, config.tenant_id)
    intel.retro_hunt(ctx.db, store, config.tenant_id)
    second = intel.retro_hunt(ctx.db, store, config.tenant_id)
    assert second["indicators"] == 0


def test_expired_indicators_are_pruned(ctx, config, clean):
    intel.store_indicators(
        ctx.db,
        config.tenant_id,
        [
            intel.Indicator(
                type="ip",
                value="198.51.100.9",
                source="test",
                expires_at=datetime.now(UTC) - timedelta(days=1),
            ),
            intel.Indicator(type="ip", value="198.51.100.10", source="test"),
        ],
    )
    assert intel.prune(ctx.db, config.tenant_id) == 1
    left = fetch_all(ctx.db, "SELECT value FROM shoc.iocs WHERE tenant_id=%s", (config.tenant_id,))
    assert [r["value"] for r in left] == ["198.51.100.10"]


def test_detection_cycles_match_indicators(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now))
    _indicator(ctx.db, config.tenant_id)
    report = call("detect.run", ctx, {"lookback": "1h"})
    assert report.data.ioc_matches == 1
    assert "indicator match" in report.summary


def test_a_hunt_records_what_it_searched_and_what_it_found(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now, count=4))
    result = call("hunt.run", ctx, {"value": BAD_IP, "days": 30})
    assert result.data.matches == 4
    assert result.citations and not result.data.findings, (
        "a value somebody searched for is not a known-bad one (RFC 0022)"
    )
    row = fetch_one(ctx.db, "SELECT * FROM shoc.hunts WHERE hunt_uid = %s", (result.data.hunt_uid,))
    assert row and row["matches"] == 4 and row["kind"] == "src_ip"
    assert row["run_by"].startswith("human:")


def test_a_hunt_for_a_user_searches_the_actor(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now))
    result = call("hunt.run", ctx, {"value": "deploy-ci", "days": 7, "field": "actor"})
    assert result.data.matches == 3


def test_listing_shows_indicators_and_feed_health(ctx, config, clean):
    _indicator(ctx.db, config.tenant_id)
    page = call("intel.list", ctx, {})
    assert page.data.count == 1 and page.data.total == 1


def test_configuring_an_unknown_feed_is_refused(ctx, config, clean):
    from shoc.errors import ValidationError

    with pytest.raises(ValidationError, match="unknown parser"):
        call("intel.configure", ctx, {"feed": "my_mate_dave"})


def test_a_feed_failure_is_recorded_as_health_not_raised(ctx, config, clean, monkeypatch):
    def boom(settings, secret):
        raise RuntimeError("feed is down")

    monkeypatch.setitem(intel.FEEDS, "abuse_ch_feodo", boom)
    result = intel.refresh(ctx.db, config.tenant_id, "abuse_ch_feodo", {}, {})
    assert result.error and "feed is down" in result.error
    row = fetch_one(
        ctx.db,
        "SELECT last_error, last_ok_at FROM shoc.intel_feeds WHERE tenant_id=%s AND feed=%s",
        (config.tenant_id, "abuse_ch_feodo"),
    )
    assert row and row["last_error"] and row["last_ok_at"] is None


def test_an_explicit_lookback_rescans_the_window_even_after_a_cycle(ctx, store, config, clean):
    """`shoc detect run --lookback 1h` must mean the last hour, not "since last time"."""
    from evals.run import SCENARIOS, replay
    from shoc.db.pool import execute

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    first = fetch_all(
        ctx.db, "SELECT finding_uid FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert len(first) >= 5

    # Forget the findings but keep the watermarks, exactly as a re-scan would find them.
    execute(ctx.db, "DELETE FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,))
    call("detect.run", ctx, {"lookback": "1h"})
    again = fetch_all(
        ctx.db, "SELECT finding_uid FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert len(again) == len(first), "the same window must produce the same findings"


def test_without_a_lookback_a_cycle_only_reads_what_arrived_since_the_last(
    ctx, store, config, clean
):
    from evals.run import SCENARIOS, replay
    from shoc.db.pool import execute
    from shoc.detect.engine import SETTLE, run_all

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    # The replay's lookback left the watermarks alone, so the first scheduled
    # cycle still reads those events; it only refreshes what the replay found.
    later = datetime.now(UTC) + SETTLE + timedelta(minutes=1)
    first = run_all(ctx.db, store, config.tenant_id, now=later, config=config)
    assert first.findings_new == 0 and first.findings_updated >= 5
    execute(ctx.db, "DELETE FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,))
    again = run_all(
        ctx.db, store, config.tenant_id, now=later + timedelta(minutes=5), config=config
    )
    assert again.findings_new == 0, "nothing was ingested since the last cycle"


def test_a_cycle_matches_an_indicator_on_an_event_that_arrived_late(ctx, store, config, clean, now):
    from shoc.detect.engine import match_indicators

    _indicator(ctx.db, config.tenant_id)
    assert match_indicators(ctx.db, store, config.tenant_id, now=now) == []
    # Three hours old when it is delivered, two minutes after that cycle.
    rows = _events(config.tenant_id, now - timedelta(hours=3))
    for row in rows:
        row["ingested_at"] = (now + timedelta(minutes=2)).isoformat()
    batch.load(store, rows)
    found = match_indicators(ctx.db, store, config.tenant_id, now=now + timedelta(minutes=5))
    assert len(found) == 1


# -- indicators handed in, sources managed (RFC 0016) -----------------------
def _agent(ctx):
    from shoc.capabilities.registry import Caller, Context

    agent = Context(
        tenant_id=ctx.tenant_id, caller=Caller(kind="external_agent", id="mcp"), config=ctx.config
    )
    agent._db, agent._store = ctx._db, ctx._store
    return agent


def test_added_indicators_keep_their_type_and_skip_internal_ones(ctx, config, clean):
    out = call(
        "intel.add",
        ctx,
        {
            "values": ["hxxps://evil.example.test/login", "203.0.113[.]77", "10.0.0.5", "nonsense"],
            "retro_hunt": False,
        },
    )
    assert {(a["type"], a["value"]) for a in out.data.added} == {
        ("url", "https://evil.example.test/login"),
        ("ip", "203.0.113.77"),
    }
    assert out.data.rejected == ["10.0.0.5", "nonsense"]
    rows = fetch_all(
        ctx.db,
        "SELECT type, source, confidence FROM shoc.iocs WHERE tenant_id=%s",
        (config.tenant_id,),
    )
    assert {r["source"] for r in rows} == {"manual:human:test"}
    assert all(r["confidence"] == 0.8 for r in rows)


def test_an_agent_cannot_add_an_indicator_an_action_would_trust(ctx, config, clean):
    call(
        "intel.add",
        _agent(ctx),
        {"values": ["203.0.113.78"], "confidence": 1.0, "retro_hunt": False},
    )
    row = fetch_one(
        ctx.db, "SELECT confidence, source FROM shoc.iocs WHERE tenant_id=%s", (config.tenant_id,)
    )
    assert row and row["confidence"] == 0.55 and row["source"] == "manual:external_agent:mcp"


def test_indicators_are_withdrawn_by_value_or_by_source(ctx, config, clean):
    call("intel.add", ctx, {"values": ["203.0.113.79", "198.51.100.79"], "retro_hunt": False})
    _indicator(ctx.db, config.tenant_id)
    assert call("intel.remove", ctx, {"values": ["203.0.113.79"]}).data.removed == 1
    assert call("intel.remove", ctx, {"source": "manual:human:test"}).data.removed == 1
    left = fetch_all(ctx.db, "SELECT value FROM shoc.iocs WHERE tenant_id=%s", (config.tenant_id,))
    assert [r["value"] for r in left] == [BAD_IP]


def test_sources_are_added_listed_and_removed(ctx, config, clean):
    from shoc.errors import ValidationError

    with pytest.raises(ValidationError, match=r"settings\.url"):
        call("intel.configure", ctx, {"feed": "vendor-blog", "parser": "rss"})
    with pytest.raises(ValidationError, match="internal host"):
        call(
            "intel.configure",
            ctx,
            {"feed": "lan", "parser": "list", "settings": {"url": "http://10.0.0.8/iocs.txt"}},
        )
    call(
        "intel.configure",
        ctx,
        {
            "feed": "vendor-blog",
            "parser": "rss",
            "settings": {"url": "https://blog.example.test/feed"},
        },
    )
    feeds = call("intel.list", _agent(ctx), {}).data.feeds
    assert [(f["feed"], f["parser"]) for f in feeds] == [("vendor-blog", "rss")]
    assert call("intel.configure", ctx, {"feed": "vendor-blog", "remove": True}).data.removed
    assert call("intel.list", ctx, {}).data.feeds == []


def test_a_disabled_default_feed_is_not_polled(ctx, config, clean, monkeypatch):
    called: list[str] = []
    monkeypatch.setitem(intel.FEEDS, "abuse_ch_feodo", lambda s, k: called.append("feodo") or [])
    monkeypatch.setitem(
        intel.FEEDS, "abuse_ch_urlhaus", lambda s, k: called.append("urlhaus") or []
    )
    call("intel.configure", ctx, {"feed": "abuse_ch_feodo", "enabled": False})
    call("intel.refresh", ctx, {"retro_hunt": False})
    assert called == ["urlhaus"]


# -- matching by type, one finding per contact (DET-4) -----------------------
PAYLOAD_URL = "https://bad.example.test/loader.bin"
PAYLOAD_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_url_and_hash_indicators_match_their_own_columns(ctx, store, config, clean, now):
    fetched = _events(config.tenant_id, now, ip="198.51.100.30", count=1)
    fetched[0]["http_request_url"] = PAYLOAD_URL
    written = _events(config.tenant_id, now, ip="198.51.100.31", count=1)
    written[0]["file_hash_sha256"] = PAYLOAD_SHA
    batch.load(store, fetched + written)
    _indicator(ctx.db, config.tenant_id, PAYLOAD_URL, "url")
    _indicator(ctx.db, config.tenant_id, PAYLOAD_SHA, "sha256")
    # The URL's host as a domain is matched on domain columns, never the URL.
    _indicator(ctx.db, config.tenant_id, "bad.example.test", "domain")
    report = intel.retro_hunt(ctx.db, store, config.tenant_id)
    assert report["indicators"] == 3 and report["hits"] == 2
    rules = {
        r["rule_id"]
        for r in fetch_all(
            ctx.db, "SELECT rule_id FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,)
        )
    }
    assert rules == {"ioc_retrohunt:url", "ioc_retrohunt:sha256"}


def test_a_retro_hunt_and_a_forward_match_share_one_finding(ctx, store, config, clean, now):
    batch.load(store, _events(config.tenant_id, now))
    _indicator(ctx.db, config.tenant_id)
    retro = intel.retro_hunt(ctx.db, store, config.tenant_id)
    hits = intel.match_window(ctx.db, store, config.tenant_id, now - timedelta(hours=1))
    assert intel.findings_from_hits(ctx.db, config.tenant_id, hits) == retro["findings"]
    rows = fetch_all(
        ctx.db, "SELECT 1 FROM shoc.findings WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert len(rows) == 1


def test_steady_contact_grows_the_open_finding(ctx, store, config, clean, now):
    from shoc.db.pool import execute

    _indicator(ctx.db, config.tenant_id)
    batch.load(store, _events(config.tenant_id, now - timedelta(hours=2)))
    earlier = intel.match_window(
        ctx.db, store, config.tenant_id, now - timedelta(hours=3), now - timedelta(hours=1)
    )
    [first] = intel.findings_from_hits(ctx.db, config.tenant_id, earlier)
    later = _events(config.tenant_id, now)
    for row in later:
        row["event_uid"] = f"{row['event_uid']}-later"
    batch.load(store, later)

    def this_cycle() -> list[str]:
        hits = intel.match_window(ctx.db, store, config.tenant_id, now - timedelta(minutes=30))
        return intel.findings_from_hits(ctx.db, config.tenant_id, hits)

    assert this_cycle() == [first]
    row = fetch_one(
        ctx.db, "SELECT last_seen, event_uids FROM shoc.findings WHERE finding_uid = %s", (first,)
    )
    assert row and row["last_seen"] > now - timedelta(minutes=30)
    assert any(u.endswith("-later") for u in row["event_uids"])
    # Once a person closes it, the next contact is a new finding.
    execute(ctx.db, "UPDATE shoc.findings SET status = 'closed' WHERE finding_uid = %s", (first,))
    assert this_cycle() != [first]


def test_withdrawing_a_defanged_value_removes_it(ctx, config, clean):
    call("intel.add", ctx, {"values": ["hxxps://evil.example.test/login"], "retro_hunt": False})
    removed = call("intel.remove", ctx, {"values": ["hxxps://evil[.]example[.]test/login"]})
    assert removed.data.removed == 1


def test_the_company_own_domain_and_address_cannot_be_added(ctx, config, clean):
    from shoc.cases import own

    own.register(ctx.db, config.tenant_id, "operator", "ana@acme.example")
    own.register(ctx.db, config.tenant_id, "address", "198.51.100.200")
    out = call(
        "intel.add",
        ctx,
        {
            "values": [
                "mail.acme.example",
                "https://acme.example/login",
                "198.51.100.200",
                "evil.example.test",
            ],
            "retro_hunt": False,
        },
    )
    assert [a["value"] for a in out.data.added] == ["evil.example.test"]
    assert len(out.data.rejected) == 3
