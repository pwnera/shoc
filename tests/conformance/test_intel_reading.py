"""Research, report digestion and report polling against a real store (DET-6, DET-7).

No test reaches a third party or a model: research sources are replaced by a
stub, and `intel.digest` reads with a scripted client.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from shoc.agents.llm import ScriptedClient
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.detect import intel, osint
from shoc.ingest import batch
from tests.conformance.test_intel import BAD_IP, _events

pytestmark = pytest.mark.postgres


# -- intel.lookup (DET-6) -----------------------------------------------------
@pytest.fixture
def asked(monkeypatch) -> list[str]:
    """One third-party source that knows nothing, and counts how often it is asked."""
    calls: list[str] = []

    def nobody(value: str, kind: str) -> osint.Observation:
        calls.append(value)
        return osint.Observation(source="stub", verdict="informational", summary="no record")

    monkeypatch.setattr(
        osint,
        "SOURCES",
        {
            "stub": osint.Source("stub", ("ip", "domain", "url"), ("stub.example.test",), nobody),
        },
    )
    return calls


def test_a_lookup_caches_third_parties_and_rereads_our_own_data(
    ctx, store, config, clean, now, asked
):
    first = call("intel.lookup", ctx, {"value": BAD_IP})
    assert first.data.verdict == "unknown" and not first.data.cached
    assert first.data.seen_in_our_logs == 0 and asked == [BAD_IP]

    # A feed and the logs bring the value in after the first answer.
    call("intel.add", ctx, {"values": [BAD_IP], "retro_hunt": False})
    batch.load(store, _events(config.tenant_id, now))

    again = call("intel.lookup", ctx, {"value": BAD_IP})
    assert again.data.cached and asked == [BAD_IP], "the third party is not asked twice"
    assert again.data.verdict == "suspicious", "our own indicator is in the answer at once"
    assert again.data.seen_in_our_logs == 3 and len(again.citations) == 3

    call("intel.lookup", ctx, {"value": BAD_IP, "refresh": True})
    assert asked == [BAD_IP, BAD_IP]


def test_an_internal_value_is_never_sent_out(ctx, config, clean, asked):
    found = call("intel.lookup", ctx, {"value": "10.0.0.5"})
    assert found.data.internal and asked == []
    assert "disclosure_guard" in found.data.sources_ok


def test_a_lookup_on_some_sources_is_not_cached(ctx, config, clean, asked):
    call("intel.lookup", ctx, {"value": BAD_IP, "sources": ["stub"]})
    assert (
        fetch_all(
            ctx.db, "SELECT 1 FROM shoc.intel_lookups WHERE tenant_id = %s", (config.tenant_id,)
        )
        == []
    )


# -- intel.digest end to end (DET-7) -----------------------------------------
REPORT = """Stealer campaign against SaaS admins.
The lure links to hxxps://drop.example[.]test/stage2.bin, which beacons to 203.0.113[.]55.
Assets were cached on cdn.example.test. One sample also reached 10.0.0.5 inside the victim
network and mail.acme.example.
"""

DIGEST = {
    "title": "Stealer campaign against SaaS admins",
    "summary": "A phishing link drops a stealer that beacons to one address.",
    "actors": ["TA-Example"],
    "malware": ["ExampleStealer"],
    "techniques": [
        {
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "evidence": "the lure",
            "seen_in": ["email", "web", "not a kind"],
        },
        {"id": "T1528", "name": "Steal Application Access Token", "evidence": "a consent screen"},
    ],
    "indicators": [
        {
            "type": "url",
            "value": "hxxps://drop.example[.]test/stage2.bin",
            "context": "payload",
            "severity": "high",
            "ttl_days": 30,
        },
        {"type": "domain", "value": "drop.example.test", "derived_from": "the payload URL"},
        {"type": "ip", "value": "203.0.113.55", "context": "C2", "ttl_days": 3650},
        {"type": "domain", "value": "cdn.example.test", "do_not_match": "a CDN edge"},
        {"type": "ip", "value": "10.0.0.5", "context": "victim host"},
        {"type": "domain", "value": "mail.acme.example", "context": "victim mail"},
    ],
    "keep": True,
    "suggested_hunts": [
        {
            "title": "OAuth consent soon after a link click",
            "hypothesis": "A phished admin grants a look-alike app access to mail",
            "procedure": "the lure led to a consent screen for a look-alike app",
            "logic": "a token grant to an app nobody granted before, within an hour of a sign-in",
            "false_positives": "a team rolling out a new SaaS tool",
            "seen_in": ["sign_in", "admin api"],
            "would_confirm": "a grant nobody on the team asked for",
            "attack": ["T1528", "not an id"],
        }
    ],
    "relevance": "Targets SaaS admins at small companies.",
    "confidence": 0.7,
}


@pytest.fixture
def model(monkeypatch):
    """The model `intel.digest` reads with, scripted to answer `DIGEST`."""
    from shoc.agents import llm

    reply = dict(DIGEST)
    monkeypatch.setattr(
        llm,
        "from_config",
        lambda *a, **k: ScriptedClient(replies={"Digest this threat report": json.dumps(reply)}),
    )
    return reply


def _iocs(ctx, config) -> dict[str, dict]:
    rows = fetch_all(ctx.db, "SELECT * FROM shoc.iocs WHERE tenant_id = %s", (config.tenant_id,))
    return {r["value"]: r for r in rows}


def test_a_digest_stores_what_cti_curated_and_nothing_it_held_back(
    ctx, store, config, clean, now, model
):
    from shoc.cases import own

    own.register(ctx.db, config.tenant_id, "operator", "ana@acme.example")
    # A feed already holds the C2 address, for 30 days.
    feed_expiry = datetime.now(UTC) + timedelta(days=30)
    intel.store_indicators(
        ctx.db,
        config.tenant_id,
        [
            intel.Indicator(
                type="ip",
                value=BAD_IP,
                source="abuse.ch/feodo",
                confidence=0.9,
                severity="high",
                expires_at=feed_expiry,
            )
        ],
    )
    batch.load(store, _events(config.tenant_id, now, age_days=10))

    out = call("intel.digest", ctx, {"text": REPORT, "title": "Stealer campaign"})

    held = {i["value"]: i["held_back"] for i in out.data.indicators}
    assert held["drop.example.test"].startswith("derived from")
    assert held["cdn.example.test"].startswith("do not match")
    assert held["10.0.0.5"] and held["mail.acme.example"]
    assert not held["https://drop.example.test/stage2.bin"] and not held[BAD_IP]

    iocs = _iocs(ctx, config)
    assert set(iocs) == {"https://drop.example.test/stage2.bin", BAD_IP}
    url = iocs["https://drop.example.test/stage2.bin"]
    assert url["type"] == "url" and url["source"] == "report:pasted"
    assert url["report_uid"] == out.data.report_uid and url["confidence"] == 0.55
    assert url["expires_at"] < datetime.now(UTC) + timedelta(days=31), "the model's TTL"
    feed = iocs[BAD_IP]
    assert feed["source"] == "abuse.ch/feodo" and feed["report_uid"] is None
    assert feed["expires_at"] >= feed_expiry - timedelta(seconds=1), "a report never shortens it"

    assert out.data.retro_hunt["hits"] == 3, "the report's C2 was in our logs ten days ago"
    report = fetch_one(
        ctx.db,
        "SELECT techniques, hunts, procedures FROM shoc.intel_reports WHERE report_uid = %s",
        (out.data.report_uid,),
    )
    assert report and report["techniques"] == ["T1566.002", "T1528"]
    assert report["hunts"] == ["OAuth consent soon after a link click"]
    assert report["procedures"][0]["seen_in"] == ["email", "web"]
    backlog = fetch_all(
        ctx.db, "SELECT * FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
    )
    # The hunt names the technique it tests, not every one the report does.
    assert [(b["trigger"], b["attack"]) for b in backlog] == [("cti", ["T1528"])]
    (hunt,) = backlog
    assert hunt["evidence"]["report_uid"] == out.data.report_uid
    assert hunt["hypothesis"] == "A phished admin grants a look-alike app access to mail"
    assert hunt["data_needed"] == "sign-ins, admin and API actions"
    assert hunt["evidence"]["seen_in"] == ["sign_in", "admin_api"]
    assert hunt["would_confirm"] == "a grant nobody on the team asked for"
    assert hunt["why_now"] == DIGEST["relevance"]
    assert hunt["evidence"]["procedure"].startswith("the lure led to a consent screen")
    assert hunt["evidence"]["logic"].startswith("a token grant to an app")
    assert hunt["evidence"]["false_positives"] == "a team rolling out a new SaaS tool"

    # Withdrawing the report takes back what it brought, and leaves the feed's row.
    assert call("intel.remove", ctx, {"report_uid": out.data.report_uid}).data.removed == 1
    assert set(_iocs(ctx, config)) == {BAD_IP}


def test_a_report_read_again_replaces_the_hunts_nothing_answered(ctx, config, clean, model):
    first = call("intel.digest", ctx, {"text": REPORT, "retro_hunt": False}).data.report_uid
    model["suggested_hunts"] = [
        {**DIGEST["suggested_hunts"][0], "hypothesis": "Now with what the report saw"},
        {"title": "A new consent screen", "hypothesis": "h", "attack": ["T1528"]},
    ]
    again = call("intel.digest", ctx, {"text": REPORT, "retro_hunt": False}).data.report_uid
    assert again == first
    rows = {
        r["title"]: r
        for r in fetch_all(
            ctx.db, "SELECT * FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
        )
    }
    kept = rows["OAuth consent soon after a link click"]
    assert kept["state"] == "open" and kept["hypothesis"] == "Now with what the report saw"
    assert rows["A new consent screen"]["state"] == "open"

    model["suggested_hunts"] = [{"title": "Only this one", "hypothesis": "h", "attack": []}]
    call("intel.digest", ctx, {"text": REPORT, "retro_hunt": False})
    rows = {
        r["title"]: r
        for r in fetch_all(
            ctx.db, "SELECT * FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
        )
    }
    gone = rows["A new consent screen"]
    assert gone["state"] == "rejected" and gone["evidence"]["decision"] == "superseded"
    assert rows["Only this one"]["state"] == "open"

    # Read again and found not to apply, the report suggests nothing, and what it did goes.
    model["keep"] = False
    call("intel.digest", ctx, {"text": REPORT, "retro_hunt": False})
    (last,) = fetch_all(
        ctx.db,
        "SELECT state, evidence FROM shoc.hunt_backlog WHERE tenant_id = %s AND title = %s",
        (config.tenant_id, "Only this one"),
    )
    assert last["state"] == "rejected"
    assert last["evidence"]["because"] == "the report was read again and does not apply here"


def test_a_discarded_report_is_read_and_steers_nothing(ctx, config, clean, model):
    model["keep"] = False
    out = call("intel.digest", ctx, {"text": REPORT})
    assert not out.data.kept and out.data.indicators_stored == 0
    assert _iocs(ctx, config) == {}
    row = fetch_one(
        ctx.db,
        "SELECT techniques, hunts, procedures FROM shoc.intel_reports WHERE report_uid = %s",
        (out.data.report_uid,),
    )
    assert row and row["techniques"] == [] and row["hunts"] == [] and row["procedures"] == []
    assert (
        fetch_all(
            ctx.db, "SELECT 1 FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
        )
        == []
    )


# -- report polling (DET-7) ---------------------------------------------------
def test_polling_reads_items_that_scrolled_off_the_feed(ctx, config, clean, monkeypatch, model):
    from shoc.detect.intel import ReportItem

    def post(n: int) -> ReportItem:
        # Each post names a threat class this company size meets, so it is read.
        return ReportItem(
            url=f"https://blog.example.test/{n}",
            title=f"Post {n}: infostealer and ransomware",
            text=f"Post {n}. {REPORT}",
        )

    pages = [[post(1), post(2), post(3)], [post(4)]]
    monkeypatch.setitem(intel.REPORT_FEEDS, "rss", lambda s, k: pages.pop(0) if pages else [])
    call(
        "intel.configure",
        ctx,
        {
            "feed": "blog",
            "parser": "rss",
            "settings": {"url": "https://blog.example.test/feed", "max_items": 2},
        },
    )

    def read() -> list[str]:
        return sorted(
            r["url"]
            for r in fetch_all(
                ctx.db,
                "SELECT url FROM shoc.intel_reports WHERE tenant_id = %s AND source = 'blog'",
                (config.tenant_id,),
            )
        )

    call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    assert read() == ["https://blog.example.test/1", "https://blog.example.test/2"]
    # Post 3 is no longer on the feed by the next poll; it is read anyway.
    second = call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    assert read() == [f"https://blog.example.test/{n}" for n in (1, 2, 3, 4)]
    assert second.data.feeds[0]["error"] is None
    assert (
        fetch_all(
            ctx.db, "SELECT 1 FROM shoc.intel_queue WHERE tenant_id = %s", (config.tenant_id,)
        )
        == []
    )
    hunts = fetch_all(
        ctx.db, "SELECT evidence FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert hunts and hunts[0]["evidence"]["source"] == "blog"


def test_a_report_that_keeps_failing_is_dropped_and_reported(ctx, config, clean, monkeypatch):
    from shoc.detect import report as reader
    from shoc.detect.intel import ReportItem

    def unreachable(url: str):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(reader, "fetch", unreachable)
    monkeypatch.setitem(
        intel.REPORT_FEEDS,
        "rss",
        lambda s, k: [
            ReportItem(url="https://blog.example.test/gone", title="Gone: infostealer ransomware")
        ],
    )
    call(
        "intel.configure",
        ctx,
        {"feed": "blog", "parser": "rss", "settings": {"url": "https://blog.example.test/feed"}},
    )
    for _ in range(3):
        call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    last = call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    assert "dropped unread" in last.data.feeds[0]["error"]


# -- picking reports before reading them (RFC 0029) --------------------------
def _feed(monkeypatch, ctx, items, **settings):
    monkeypatch.setitem(intel.REPORT_FEEDS, "rss", lambda s, k: list(items))
    call(
        "intel.configure",
        ctx,
        {
            "feed": "blog",
            "parser": "rss",
            "settings": {"url": "https://blog.example.test/feed", **settings},
        },
    )


def _queue(ctx, config) -> dict[str, dict]:
    rows = fetch_all(
        ctx.db,
        "SELECT url, state, reason, same_as FROM shoc.intel_queue WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    return {r["url"]: r for r in rows}


def _item(n: int, title: str, **kw) -> intel.ReportItem:
    return intel.ReportItem(url=f"https://blog.example.test/{n}", title=title, **kw)


def test_items_are_scored_before_anything_reads_them(ctx, config, clean, monkeypatch, model):
    old = datetime.now(UTC) - timedelta(days=20)
    _feed(
        monkeypatch,
        ctx,
        [
            _item(1, "Infostealer logs sold with ransomware access", text=REPORT),
            _item(2, "PLC firmware backdoor at an ICS water utility", text=REPORT),
            _item(3, "Infostealer campaign from last month", text=REPORT, published=old),
        ],
    )
    call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    queue = _queue(ctx, config)
    assert set(queue) == {"https://blog.example.test/2"}, "read, or older than a week"
    assert queue["https://blog.example.test/2"]["state"] == "skipped"
    assert "PLC" in queue["https://blog.example.test/2"]["reason"]
    skipped = call("intel.reports", ctx, {"state": "skipped"})
    assert [r["url"] for r in skipped.data.rows] == ["https://blog.example.test/2"]


def test_the_same_story_from_another_source_is_linked_not_read(
    ctx, config, clean, monkeypatch, model
):
    first = call("intel.digest", ctx, {"text": REPORT, "title": "x"})
    execute(
        ctx.db,
        "UPDATE shoc.intel_reports SET title = %s WHERE report_uid = %s",
        ("Akira ransomware abuses SonicWall SSL VPN accounts", first.data.report_uid),
    )
    _feed(monkeypatch, ctx, [_item(1, "SonicWall SSL VPN flaw exploited by Akira ransomware")])
    call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    row = _queue(ctx, config)["https://blog.example.test/1"]
    assert row["state"] == "same_story" and row["same_as"] == first.data.report_uid


def test_the_daily_cap_stops_reading_best_first(ctx, config, clean, monkeypatch, model):
    call("llm.configure", ctx, {"intel_reports_per_day": 1})
    _feed(
        monkeypatch,
        ctx,
        [
            _item(1, "Ransomware note", text=f"one {REPORT}"),
            _item(2, "Okta infostealer ransomware wave", text=f"two {REPORT}"),
        ],
    )
    call(
        "source.configure",
        ctx,
        {"source": "okta", "settings": {"domain": "x.okta.com"}, "verify": False},
    )
    call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    read = fetch_all(
        ctx.db, "SELECT url FROM shoc.intel_reports WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert [r["url"] for r in read] == ["https://blog.example.test/2"], "the higher score"
    assert _queue(ctx, config)["https://blog.example.test/1"]["state"] == "waiting"
    budget = call("intel.list", ctx, {"limit": 1}).data.budget
    assert budget["reports_per_day"] == 1 and budget["reports_today"] == 1


def test_a_middle_band_item_is_put_to_the_cheap_model_first(ctx, config, clean, monkeypatch):
    from shoc.agents import llm

    monkeypatch.setattr(
        llm,
        "from_config",
        lambda *a, **k: ScriptedClient(
            replies={
                "worth reading in full": json.dumps({"read": False, "why": "vendor marketing"}),
                "Digest this threat report": json.dumps(DIGEST),
            }
        ),
    )
    # One threat class and nothing the company runs: the middle band.
    item = _item(1, "Ransomware webinar next week", text=REPORT, summary="Join us live.")
    _feed(monkeypatch, ctx, [item])
    call("intel.refresh", ctx, {"feed": "blog", "retro_hunt": False})
    row = fetch_one(
        ctx.db,
        "SELECT state, reason, tokens FROM shoc.intel_queue WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert row and row["state"] == "skipped" and row["reason"] == "triage: vendor marketing"
    assert row["tokens"] > 0, "the triage call counts toward the day"


def test_an_agents_report_waits_when_the_day_is_spent_and_a_persons_does_not(
    ctx, config, clean, model
):
    from dataclasses import replace

    call("llm.configure", ctx, {"intel_reports_per_day": 1})
    call("intel.digest", ctx, {"text": REPORT, "title": "first"})
    agent = replace(ctx, caller=replace(ctx.caller, kind="agent", id="CTI"))
    waited = call("intel.digest", agent, {"text": f"other {REPORT}", "title": "second"})
    assert waited.data.queued and "queued" in waited.summary
    person = call("intel.digest", ctx, {"text": f"third {REPORT}", "title": "third"})
    assert not person.data.queued and person.data.report_uid


def test_a_preset_fills_in_the_source(ctx, config, clean):
    out = call("intel.configure", ctx, {"preset": "the_dfir_report"})
    assert out.data.feed == "the_dfir_report" and out.data.parser == "rss"
    assert "thedfirreport.com" in out.summary
    row = fetch_one(
        ctx.db,
        "SELECT settings FROM shoc.intel_feeds WHERE tenant_id = %s AND feed = %s",
        (config.tenant_id, "the_dfir_report"),
    )
    assert row and row["settings"]["url"] == "https://thedfirreport.com/feed/"
    assert row["settings"]["grade"] == 2
    presets = {p["name"]: p for p in call("intel.list", ctx, {"limit": 1}).data.presets}
    assert presets["the_dfir_report"]["configured"] and not presets["huntress"]["configured"]


def test_a_lookup_key_has_a_quota_and_a_free_non_commercial_key_is_refused(ctx, config, clean):
    import pytest

    from shoc.errors import NotFound, ValidationError

    with pytest.raises(ValidationError, match="non-commercial"):
        call("intel.configure", ctx, {"lookup": "virustotal", "secret": {"api_key": "v"}})
    with pytest.raises(ValidationError, match=r"secret\.auth_key"):
        call("intel.configure", ctx, {"lookup": "abuse_ch", "settings": {"per_day": 1}})
    with pytest.raises(ValidationError, match="per_day"):
        call("intel.configure", ctx, {"lookup": "abuse_ch", "settings": {"per_day": "lots"}})
    with pytest.raises(NotFound, match="no lookup"):
        call("intel.configure", ctx, {"lookup": "nope"})
    call(
        "intel.configure",
        ctx,
        {"lookup": "abuse_ch", "secret": {"auth_key": "k"}, "settings": {"per_day": 1}},
    )
    # Saved again without the key, the stored one is kept.
    call("intel.configure", ctx, {"lookup": "abuse_ch", "settings": {"per_day": 1}})
    lookups = {r["source"]: r for r in call("intel.list", ctx, {"limit": 1}).data.lookups}
    assert lookups["abuse_ch"]["configured"] and lookups["abuse_ch"]["per_day"] == 1
    assert not lookups["virustotal"]["configured"] and lookups["virustotal"]["licence_needed"]


def test_a_keyed_source_stops_at_its_daily_quota(ctx, config, clean, monkeypatch):
    calls: list[str] = []

    def keyed(value: str, kind: str, secret: dict) -> osint.Observation:
        calls.append(secret["auth_key"])
        return osint.Observation(source="keyed", verdict="informational", summary="seen")

    monkeypatch.setattr(
        osint,
        "SOURCES",
        {"keyed": osint.Source("keyed", ("ip",), ("x.example.test",), keyed, key="abuse_ch")},
    )
    found = call("intel.lookup", ctx, {"value": BAD_IP})
    assert calls == [], "not configured, not asked"
    assert "keyed" not in found.data.sources_ok
    call(
        "intel.configure",
        ctx,
        {"lookup": "abuse_ch", "secret": {"auth_key": "k"}, "settings": {"per_day": 1}},
    )
    call("intel.lookup", ctx, {"value": BAD_IP, "refresh": True})
    again = call("intel.lookup", ctx, {"value": BAD_IP, "refresh": True})
    assert calls == ["k"]
    assert "keyed" in again.data.sources_failed
    assert any("quota" in o["error"] for o in again.data.observations if o["source"] == "keyed")


def test_a_url_is_not_bad_because_its_host_is_on_a_feed(ctx, config, clean, asked):
    call("intel.add", ctx, {"values": ["shared.example.test"], "retro_hunt": False})
    found = call("intel.lookup", ctx, {"value": "https://shared.example.test/page.html"})
    local = next(o for o in found.data.observations if o["source"] == "local_iocs")
    assert local["data"]["relation"] == "host_of" and found.data.verdict != "malicious"


def test_a_warninglisted_value_is_held_back_and_refused_from_an_agent(
    ctx, config, clean, model, monkeypatch
):
    from dataclasses import replace

    benign = osint.Benign()
    benign.add("public-dns-hostname", "domain", "hostname", "cdn.example.test")
    monkeypatch.setitem(osint._LISTS, "warninglists", (datetime.now(UTC), benign))
    model["indicators"] = [{"type": "domain", "value": "cdn.example.test", "context": "C2"}]
    out = call("intel.digest", ctx, {"text": REPORT})
    [held] = out.data.indicators
    assert held["held_back"] == "on the public-dns-hostname warninglist"
    agent = replace(ctx, caller=replace(ctx.caller, kind="agent", id="CTI"))
    added = call("intel.add", agent, {"values": ["cdn.example.test"], "retro_hunt": False})
    assert added.data.rejected == ["cdn.example.test"]


def test_a_discarded_report_lists_nothing(ctx, config, clean, model):
    model["keep"] = False
    out = call("intel.digest", ctx, {"text": REPORT})
    assert out.data.indicators == [] and not out.data.kept


def test_a_report_is_read_once_unless_a_person_asks_again(ctx, config, clean, monkeypatch):
    from dataclasses import replace

    from shoc.agents import llm

    client = ScriptedClient(replies={"Digest this threat report": json.dumps(DIGEST)})
    monkeypatch.setattr(llm, "from_config", lambda *a, **k: client)
    agent = replace(ctx, caller=replace(ctx.caller, kind="agent", id="CTI"))
    first = call("intel.digest", agent, {"text": REPORT})
    again = call("intel.digest", agent, {"text": REPORT})
    assert again.data.report_uid == first.data.report_uid and "Already read" in again.summary
    assert len(client.calls) == 1, "a second read only spent the model and queued hunts twice"
    call("intel.digest", ctx, {"text": REPORT})
    assert len(client.calls) == 2, "a person may ask for a re-read"


def test_a_read_that_fails_gives_its_claim_back(ctx, config, clean, monkeypatch):
    from shoc.agents import llm

    class Broken(ScriptedClient):
        def complete(self, *a, **k):
            raise RuntimeError("the model is down")

    monkeypatch.setattr(llm, "from_config", lambda *a, **k: Broken())
    with pytest.raises(RuntimeError):
        call("intel.digest", ctx, {"text": REPORT})
    rows = fetch_all(
        ctx.db, "SELECT 1 FROM shoc.intel_reports WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert rows == [], "the next poll reads it again"


def test_a_read_queues_three_hunts_and_none_for_a_value_it_stored(ctx, config, clean, model):
    model["suggested_hunts"] = [
        {"title": t, "hypothesis": t, "attack": []}
        for t in (
            "Search proxy logs for 203.0.113.55",
            "OAuth consents granted to a new app within an hour of a link click",
            "Mail rules created right after a sign-in from a new country",
            "Admin role granted outside working hours",
            "A new device enrolled for an admin from a new address",
        )
    ]
    call("intel.digest", ctx, {"text": REPORT})
    backlog = fetch_all(
        ctx.db, "SELECT title FROM shoc.hunt_backlog WHERE tenant_id = %s", (config.tenant_id,)
    )
    titles = {b["title"] for b in backlog}
    assert len(titles) == 3 and not any("203.0.113.55" in t for t in titles), (
        "the retro-hunt looks for a stored value; the backlog is for behaviour"
    )
