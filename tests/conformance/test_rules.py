"""Every rule fires on its positive fixture and stays quiet on its negative one (DET-2).

The same fixtures run against every backend, so a rule that behaves differently
on Databricks or Snowflake fails here rather than in a customer's account.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.detect import engine
from shoc.detect import rules as ruleset
from shoc.detect.engine import _bucket, run_all, run_rule
from shoc.errors import StoreError
from shoc.ingest import batch, ocsf
from tests.support import fixture_rows, fixture_source, load_fixture

pytestmark = pytest.mark.postgres

RULES = ruleset.load()


def _ingest(store, tenant, rule, kind, now):
    rows = fixture_rows(load_fixture(rule.id, kind), fixture_source(rule), tenant, now)
    batch.load(store, rows)
    return len(rows)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_fires_on_its_positive_fixture(rule, store, config, clean, now):
    _ingest(store, config.tenant_id, rule, "positive", now)
    findings = run_rule(
        store, config.tenant_id, rule, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert findings, f"{rule.id} did not fire on its positive fixture"
    assert all(f.event_uids for f in findings), "a finding without cited events is not allowed"
    assert findings[0].severity == rule.severity


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_is_quiet_on_its_negative_fixture(rule, store, config, clean, now):
    _ingest(store, config.tenant_id, rule, "negative", now)
    findings = run_rule(
        store, config.tenant_id, rule, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert not findings, f"{rule.id} fired on its negative fixture: {findings[:1]}"


def test_a_rule_can_match_and_group_on_a_source_specific_field(store, config, clean, now):
    """A whole rule, not just its SQL, runs on a field no column holds (RFC 0009)."""
    mapping = ocsf.load_mapping("okta")
    rows = [
        mapping.map_record(
            {
                "uuid": f"src-{i}",
                "published": (now - timedelta(minutes=i + 1)).isoformat(),
                "eventType": "user.session.start",
                "outcome": {"result": "SUCCESS"},
                "actor": {"id": "u1", "alternateId": "alice@example.com", "type": "User"},
                "client": {"ipAddress": "203.0.113.9", "zone": zone},
                "debugContext": {"debugData": {"dtHash": "unknown-device"}},
            },
            config.tenant_id,
        )
        for i, zone in enumerate(["OffNetwork"] * 3 + ["Trusted"] * 2)
    ]
    batch.load(store, rows)

    rule = ruleset.from_dict(
        {
            "id": "TEST-SRC-1",
            "title": "Repeated sign-in from an untrusted zone on an unknown device",
            "logsource": {"product": "okta"},
            "detection": {
                "selection": {
                    "api.operation": "user.session.start",
                    "raw.debugContext.debugData.dtHash": "unknown-device",
                },
                "condition": "selection",
                "group_by": ["unmapped.client.zone"],
                "count": ">= 3",
            },
        }
    )
    findings = run_rule(
        store, config.tenant_id, rule, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert [f.entity_key for f in findings] == ["OffNetwork"]
    assert findings[0].evidence["group"] == {"unmapped_client_zone": "OffNetwork"}
    assert len(findings[0].event_uids) == 3


# -- scheduled cycles (DET-3) -----------------------------------------------
# Each test drives `run_all` with its own clock and stamps `ingested_at` by hand,
# so several unattended cycles run in a few seconds.
BURST = ruleset.from_dict(
    {
        "id": "TEST-BURST",
        "title": "Ten listings by one user in fifteen minutes",
        "logsource": {"product": "aws"},
        "detection": {
            "selection": {"api.operation": "ListBuckets"},
            "condition": "selection",
            "group_by": ["actor.user.name"],
            "count": ">= 10",
            "timeframe": "15m",
        },
    }
)
MATCH = ruleset.from_dict(
    {
        "id": "TEST-MATCH",
        "title": "A trail was deleted",
        "entity": "actor.user.name",
        "logsource": {"product": "aws"},
        "detection": {
            "selection": {"api.operation": "DeleteTrail"},
            "condition": "selection",
            "timeframe": "15m",
        },
    }
)


def _trail(
    tenant, times, ingested, tag, op="ListBuckets", user="deploy-ci", key: str | None = "AKIATEST"
):
    mapping = ocsf.load_mapping("aws_cloudtrail")
    rows = []
    for i, t in enumerate(times):
        row = mapping.map_record(
            {
                "eventID": f"{tag}-{i}",
                "eventTime": t.isoformat(),
                "eventName": op,
                "eventSource": "cloudtrail.amazonaws.com",
                "sourceIPAddress": "203.0.113.20",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": user,
                    **({"accessKeyId": key} if key else {}),
                },
            },
            tenant,
        )
        row["ingested_at"] = ingested.isoformat()
        rows.append(row)
    return rows


def _findings(conn, tenant, rule_id):
    return fetch_all(
        conn,
        """SELECT finding_uid, entity_key, event_count, event_uids
           FROM shoc.findings WHERE tenant_id = %s AND rule_id = %s ORDER BY window_start""",
        (tenant, rule_id),
    )


def _boundary(now):
    return _bucket(now - timedelta(hours=12), 900)


def test_a_burst_spread_over_two_cycles_reaches_its_threshold(conn, store, config, clean, now):
    tenant, edge = config.tenant_id, _boundary(now)
    first_cycle = edge + timedelta(minutes=1)
    before = [edge - timedelta(seconds=10 + 30 * i) for i in range(6)]
    batch.load(store, _trail(tenant, before, first_cycle - timedelta(seconds=30), "a"))
    run_all(conn, store, tenant, [BURST], now=first_cycle)
    assert not _findings(conn, tenant, BURST.id), "six events are under the threshold"

    # Six more, past a bucket boundary and past the first cycle's watermark.
    second_cycle = first_cycle + timedelta(minutes=5)
    after = [edge + timedelta(minutes=2, seconds=10 * i) for i in range(6)]
    batch.load(store, _trail(tenant, after, second_cycle - timedelta(seconds=30), "b"))
    run_all(conn, store, tenant, [BURST], now=second_cycle)

    rows = _findings(conn, tenant, BURST.id)
    assert [(r["event_count"], len(r["event_uids"])) for r in rows] == [(12, 12)]
    backfill = run_rule(store, tenant, BURST, edge - timedelta(hours=1), second_cycle)
    assert [(f.finding_uid, f.event_count) for f in backfill] == [(rows[0]["finding_uid"], 12)], (
        "cycles and one backfill over the same events must agree"
    )


def test_an_event_that_arrives_late_is_still_evaluated(conn, store, config, clean, now):
    tenant, cycle = config.tenant_id, _boundary(now)
    run_all(conn, store, tenant, [MATCH], now=cycle)
    # Its time is three hours before the watermark; it is delivered two minutes after.
    late = _trail(
        tenant, [cycle - timedelta(hours=3)], cycle + timedelta(minutes=2), "late", op="DeleteTrail"
    )
    batch.load(store, late)
    run_all(conn, store, tenant, [MATCH], now=cycle + timedelta(minutes=5))
    rows = _findings(conn, tenant, MATCH.id)
    assert [r["event_uids"] for r in rows] == [[late[0]["event_uid"]]]


def test_a_long_outage_is_caught_up_without_dropping_events(conn, store, config, clean, now):
    tenant, down = config.tenant_id, _boundary(now)
    run_all(conn, store, tenant, [MATCH], now=down)
    early, late = down + timedelta(hours=1), down + timedelta(hours=8)
    batch.load(store, _trail(tenant, [early], early, "early", op="DeleteTrail", user="early"))
    batch.load(store, _trail(tenant, [late], late, "late", op="DeleteTrail", user="late"))
    back = down + timedelta(hours=9)

    run_all(conn, store, tenant, [MATCH], now=back)
    assert [r["entity_key"] for r in _findings(conn, tenant, MATCH.id)] == ["early"]
    run_all(conn, store, tenant, [MATCH], now=back)
    assert [r["entity_key"] for r in _findings(conn, tenant, MATCH.id)] == ["early", "late"]
    state = fetch_one(
        conn,
        "SELECT watermark FROM shoc.rule_state WHERE tenant_id = %s AND rule_id = %s",
        (tenant, MATCH.id),
    )
    assert state and state["watermark"] == back


def test_every_hit_is_evaluated_however_many_there_are(
    conn, store, config, clean, now, monkeypatch
):
    monkeypatch.setattr(engine, "PAGE", 100)
    tenant, start = config.tenant_id, _boundary(now)
    # Three hits share each second, so page boundaries fall between equal times.
    times = [start + timedelta(seconds=i // 3) for i in range(250)]
    batch.load(store, _trail(tenant, times, start + timedelta(minutes=2), "a", op="DeleteTrail"))
    batch.load(
        store,
        _trail(
            tenant,
            [start + timedelta(minutes=5)],
            start + timedelta(minutes=5),
            "b",
            op="DeleteTrail",
            user="mallory",
        ),
    )
    run_all(conn, store, tenant, [MATCH], now=start + timedelta(minutes=6))
    rows = {r["entity_key"]: r for r in _findings(conn, tenant, MATCH.id)}
    assert set(rows) == {"deploy-ci", "mallory"}
    assert rows["deploy-ci"]["event_count"] == 250
    assert len(rows["deploy-ci"]["event_uids"]) == engine.MAX_EVIDENCE


def test_refreshing_a_finding_keeps_what_it_cited(conn, config, clean, now):
    tenant, start = config.tenant_id, _boundary(now)
    end = start + timedelta(minutes=15)
    first = engine._finding(
        MATCH,
        tenant,
        "deploy-ci",
        start,
        end,
        start,
        start,
        19,
        [f"e{i}" for i in range(19)],
        {"kind": "match"},
        ["user:deploy-ci"],
    )
    assert engine.upsert(conn, first)
    again = engine._finding(
        MATCH,
        tenant,
        "deploy-ci",
        start,
        end,
        start,
        end,
        3,
        ["e18", "x", "y"],
        {"kind": "match"},
        ["ip:203.0.113.20"],
    )
    assert not engine.upsert(conn, again)
    row = fetch_one(
        conn,
        "SELECT event_uids, event_count, entities FROM shoc.findings WHERE finding_uid = %s",
        (first.finding_uid,),
    )
    assert row and row["event_uids"] == [*(f"e{i}" for i in range(19)), "x"]
    assert row["event_count"] == 19
    assert row["entities"] == ["ip:203.0.113.20", "user:deploy-ci"]


SESSIONS = ruleset.from_dict(
    {
        "id": "TEST-SESSION-READS",
        "title": "Five reads from one session and address",
        "logsource": {"product": "aws"},
        "detection": {
            "selection": {"api.operation": "GetObject"},
            "condition": "selection",
            "group_by": ["actor.session.uid", "src_endpoint.ip"],
            "count": ">= 5",
            "timeframe": "15m",
        },
    }
)


def _state(conn, tenant, rule_id):
    return fetch_one(
        conn,
        "SELECT watermark, last_error FROM shoc.rule_state WHERE tenant_id = %s AND rule_id = %s",
        (tenant, rule_id),
    )


def _entities(conn, tenant, rule_id):
    return [r["entity_key"] for r in _findings(conn, tenant, rule_id)]


def test_a_group_with_no_session_still_fires_and_cites_its_events(conn, store, config, clean, now):
    """Anonymous reads of a public bucket carry no access key."""
    tenant, start = config.tenant_id, _boundary(now)
    times = [start + timedelta(seconds=i) for i in range(6)]
    batch.load(
        store, _trail(tenant, times, start + timedelta(minutes=1), "anon", op="GetObject", key=None)
    )
    run_all(conn, store, tenant, [SESSIONS], now=start + timedelta(minutes=2))
    rows = _findings(conn, tenant, SESSIONS.id)
    assert [(r["event_count"], len(r["event_uids"])) for r in rows] == [(6, 6)]


def test_a_cycle_evaluates_each_bucket_and_not_the_time_between(
    conn, store, config, clean, now, monkeypatch
):
    """An event whose parser lost the date must not make the cycle read decades."""
    tenant, start = config.tenant_id, _boundary(now)
    windows = []

    def spy(store_, tenant_, rule, lo, hi, *args):
        windows.append((lo, hi))
        return run_rule(store_, tenant_, rule, lo, hi, *args)

    monkeypatch.setattr(engine, "run_rule", spy)
    lost = datetime(2001, 1, 1, tzinfo=UTC)
    batch.load(
        store, _trail(tenant, [lost, start], start + timedelta(minutes=1), "t", op="DeleteTrail")
    )
    run_all(conn, store, tenant, [MATCH], now=start + timedelta(minutes=2))
    span = timedelta(minutes=15)
    assert windows == [(lost, lost + span), (start, start + span)]
    assert len(_findings(conn, tenant, MATCH.id)) == 2


def test_adjacent_buckets_are_read_in_one_statement_and_agree_with_a_backfill(
    conn, store, config, clean, now, monkeypatch
):
    """A backlog of adjacent buckets is one read, not one per bucket (D149)."""
    tenant, start = config.tenant_id, _boundary(now)
    span = timedelta(minutes=15)
    windows = []

    def spy(store_, tenant_, rule, lo, hi, *args):
        windows.append((lo, hi))
        return run_rule(store_, tenant_, rule, lo, hi, *args)

    monkeypatch.setattr(engine, "run_rule", spy)
    times = [start + i * span + timedelta(minutes=1) for i in range(4)]
    batch.load(store, _trail(tenant, times, start + 4 * span, "adj", op="DeleteTrail"))
    run_all(conn, store, tenant, [MATCH], now=start + 4 * span + timedelta(minutes=1))
    assert windows == [(start, start + 4 * span)]
    cycled = [r["finding_uid"] for r in _findings(conn, tenant, MATCH.id)]
    backfill = run_rule(store, tenant, MATCH, start - span, start + 5 * span)
    assert len(cycled) == 4 and sorted(cycled) == sorted(f.finding_uid for f in backfill)


def test_a_cycle_whose_rows_match_no_rule_reads_the_store_once(conn, store, config, clean, now):
    """One statement asks every woken rule whether anything it reads arrived (D149)."""
    from tests.support import Counting

    tenant, start = config.tenant_id, _boundary(now)
    rules = [MATCH, BURST, SESSIONS]
    run_all(conn, store, tenant, rules, now=start)
    cycle = start + timedelta(minutes=5)
    batch.load(store, _trail(tenant, [cycle], cycle, "quiet", op="DescribeTrails"))
    counting: Any = Counting(store)
    stats = run_all(conn, counting, tenant, rules, now=cycle + timedelta(minutes=1))
    assert not stats.errors and stats.rules_run == 3
    assert len(counting.sent) == 1

    later = cycle + timedelta(minutes=5)
    batch.load(store, _trail(tenant, [later], later, "loud", op="DeleteTrail"))
    counting.sent.clear()
    stats = run_all(conn, counting, tenant, rules, now=later + timedelta(minutes=1))
    assert stats.findings_new == 1
    # The probe, then MATCH's buckets and its one run; BURST and SESSIONS are not read.
    assert len(counting.sent) == 3


def test_a_run_that_fails_twice_is_read_again_bucket_by_bucket(
    conn, store, config, clean, now, monkeypatch
):
    tenant, start = config.tenant_id, _boundary(now)
    span = timedelta(minutes=15)
    bad = start + span

    def flaky(store_, tenant_, rule, lo, hi, *args):
        if lo <= bad < hi:
            raise StoreError("canceling statement due to statement timeout")
        return run_rule(store_, tenant_, rule, lo, hi, *args)

    monkeypatch.setattr(engine, "run_rule", flaky)
    ingested = start + 2 * span
    batch.load(store, _trail(tenant, [start], ingested, "good", op="DeleteTrail", user="good"))
    batch.load(store, _trail(tenant, [bad], ingested, "bad", op="DeleteTrail", user="bad"))
    first = run_all(conn, store, tenant, [MATCH], now=ingested + timedelta(minutes=1))
    assert MATCH.id in first.errors and not _findings(conn, tenant, MATCH.id)
    run_all(conn, store, tenant, [MATCH], now=ingested + timedelta(minutes=6))
    assert _entities(conn, tenant, MATCH.id) == ["good"]
    state = _state(conn, tenant, MATCH.id)
    assert state and f"{bad:%Y-%m-%d %H:%M} not evaluated" in state["last_error"]


def test_a_bucket_that_fails_twice_is_left_out_and_the_rule_goes_on(
    conn, store, config, clean, now, monkeypatch
):
    tenant, start = config.tenant_id, _boundary(now)
    bad = start - timedelta(days=3)

    def flaky(store_, tenant_, rule, lo, hi, *args):
        if lo == bad:
            raise StoreError("canceling statement due to statement timeout")
        return run_rule(store_, tenant_, rule, lo, hi, *args)

    monkeypatch.setattr(engine, "run_rule", flaky)
    ingested = start + timedelta(minutes=1)
    batch.load(store, _trail(tenant, [bad], ingested, "bad", op="DeleteTrail", user="old"))
    batch.load(store, _trail(tenant, [start], ingested, "good", op="DeleteTrail", user="new"))

    first = run_all(conn, store, tenant, [MATCH], now=start + timedelta(minutes=2))
    assert MATCH.id in first.errors and not _findings(conn, tenant, MATCH.id), "retried once"

    second = start + timedelta(minutes=7)
    run_all(conn, store, tenant, [MATCH], now=second)
    assert _entities(conn, tenant, MATCH.id) == ["new"]
    state = _state(conn, tenant, MATCH.id)
    assert state and state["watermark"] == second
    assert f"{bad:%Y-%m-%d %H:%M} not evaluated" in state["last_error"]
    notice = fetch_one(
        conn,
        "SELECT kind, body FROM shoc.notices WHERE tenant_id = %s AND source = 'detect'",
        (tenant,),
    )
    assert notice and notice["kind"] == "digest" and MATCH.id in notice["body"]

    later = start + timedelta(minutes=30)
    batch.load(store, _trail(tenant, [later], later, "later", op="DeleteTrail", user="later"))
    run_all(conn, store, tenant, [MATCH], now=later + timedelta(minutes=1))
    assert _entities(conn, tenant, MATCH.id) == ["new", "later"]


def test_a_rule_that_failed_from_its_first_cycle_resumes_where_it_started(
    conn, store, config, clean, now, monkeypatch
):
    tenant, start = config.tenant_id, _boundary(now)

    def down(*args):
        raise StoreError("warehouse is down")

    with monkeypatch.context() as patched:
        patched.setattr(engine, "_since_watermark", down)
        patched.setattr(engine, "_unmatched", lambda *args: set())
        run_all(conn, store, tenant, [MATCH], now=start)
    gap = start + timedelta(hours=1)
    batch.load(store, _trail(tenant, [gap], gap, "gap", op="DeleteTrail"))
    run_all(conn, store, tenant, [MATCH], now=start + timedelta(hours=2))
    assert _entities(conn, tenant, MATCH.id) == ["deploy-ci"]


def test_more_groups_than_the_cap_still_fire_on_the_heaviest(
    conn, store, config, clean, now, monkeypatch
):
    monkeypatch.setattr(engine, "MAX_GROUPS", 2)
    tenant, start = config.tenant_id, _boundary(now)
    for n, user in ((12, "a"), (11, "b"), (10, "c")):
        times = [start + timedelta(seconds=i) for i in range(n)]
        batch.load(store, _trail(tenant, times, start + timedelta(minutes=1), user, user=user))
    cycle = start + timedelta(minutes=2)
    stats = run_all(conn, store, tenant, [BURST], now=cycle)
    assert sorted(_entities(conn, tenant, BURST.id)) == ["a", "b"]
    assert "more than 2 groups reached the threshold" in stats.errors[BURST.id]
    state = _state(conn, tenant, BURST.id)
    assert state and state["watermark"] == cycle


def test_an_ad_hoc_run_reads_at_most_its_limit(store, config, clean, now, monkeypatch):
    """rule.test and rule.backtest are open to an outside assistant; they stay bounded."""
    monkeypatch.setattr(engine, "PAGE", 100)
    tenant, start = config.tenant_id, _boundary(now)
    times = [start + timedelta(seconds=i) for i in range(250)]
    batch.load(store, _trail(tenant, times, start, "a", op="DeleteTrail"))
    findings = run_rule(store, tenant, MATCH, start, start + timedelta(minutes=15))
    assert [f.event_count for f in findings] == [engine.ADHOC_LIMIT]


# -- RFC 0023: the format additions, run end to end -------------------------
def _calls(store, tenant, now, calls):
    """CloudTrail records from (event id, minutes ago, fields over a default call)."""
    mapping = ocsf.load_mapping("aws_cloudtrail")
    rows = []
    for uid, ago, extra in calls:
        record = {
            "eventID": uid,
            "eventTime": (now - timedelta(minutes=ago)).isoformat(),
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "sourceIPAddress": "203.0.113.20",
            "userIdentity": {"type": "IAMUser", "userName": "alice", "accessKeyId": "AKIATEST"},
        }
        record.update(extra)
        rows.append(mapping.map_record(record, tenant))
    batch.load(store, rows)


def _user(name):
    return {"userIdentity": {"type": "IAMUser", "userName": name, "accessKeyId": f"AKIA{name}"}}


def _rule(detection, **extra):
    return ruleset.from_dict(
        {
            "id": "TEST-0023",
            "title": "t",
            "logsource": {"product": "aws"},
            "entity": "actor.user.name",
            "detection": detection,
            **extra,
        }
    )


def _cited(store, tenant, rule, now):
    found = run_rule(store, tenant, rule, now - timedelta(hours=1), now + timedelta(minutes=1))
    return [f.event_uids for f in found]


def test_like_values_match_literally(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            ("path", 5, {"requestParameters": {"path": "C:\\Users\\Public\\x.exe"}}),
            ("nopath", 5, {"requestParameters": {"path": "C:/Users/Public/x.exe"}}),
            ("pct", 5, {"requestParameters": {"path": "report_100%.txt"}}),
            ("nopct", 5, {"requestParameters": {"path": "reportX100YY.txt"}}),
        ],
    )
    rule = _rule({"s": {"raw.requestParameters.path|contains": ["\\Users\\Public\\", "t_100%."]}})
    assert _cited(store, config.tenant_id, rule, now) == [["path", "pct"]]


def test_a_boolean_on_a_source_path_matches_with_or_without_quotes(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            ("on", 5, {"requestParameters": {"enabled": True}}),
            ("text", 5, {"requestParameters": {"enabled": "true"}}),
            ("off", 5, {"requestParameters": {"enabled": False}}),
        ],
    )
    for value in (True, "true"):
        rule = _rule({"s": {"raw.requestParameters.enabled": value}})
        assert _cited(store, config.tenant_id, rule, now) == [["on", "text"]]
    rule = _rule({"s": {"raw.requestParameters.enabled": False}})
    assert _cited(store, config.tenant_id, rule, now) == [["off"]]


def test_a_distinct_count_counts_values_inside_one_window(store, config, clean, now):
    login = {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}
    # Minutes before `base`, which is 10 minutes into one 15-minute bucket.
    start = _boundary(now)
    base = start + timedelta(minutes=10)
    calls = [
        (f"a-{u}-{i}", 9 - i / 10, {**login, **_user(u), "sourceIPAddress": "203.0.113.1"})
        for u in ("u1", "u2", "u3")
        for i in range(3)
    ]
    calls += [
        (f"b-{i}", 9 - i / 10, {**login, **_user("u1"), "sourceIPAddress": "203.0.113.2"})
        for i in range(10)
    ]
    # Three users, but the third comes 19 minutes after the first two.
    calls += [
        (f"c-{u}", ago, {**login, **_user(u), "sourceIPAddress": "203.0.113.3"})
        for u, ago in (("u1", 9), ("u2", 8.5), ("u3", -10))
    ]
    _calls(store, config.tenant_id, base, calls)
    rule = _rule(
        {
            "s": {"api.operation": "ConsoleLogin"},
            "group_by": ["src_endpoint.ip"],
            "count_distinct": "actor.user.name",
            "count": ">= 3",
            "timeframe": "15m",
        }
    )
    found = run_rule(store, config.tenant_id, rule, start, start + timedelta(minutes=15))
    assert [f.entity_key for f in found] == ["203.0.113.1"]
    assert sorted(found[0].event_uids) == ["a-u1-0", "a-u2-0", "a-u3-0"]
    assert found[0].evidence["distinct"] == "actor.user.name"


def test_a_sequence_fires_on_the_later_event_and_cites_both(store, config, clean, now):
    reset = {"eventName": "UpdateLoginProfile", "eventSource": "iam.amazonaws.com"}
    login = {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}
    _calls(
        store,
        config.tenant_id,
        now,
        [
            ("alice-reset", 30, {**reset, **_user("alice")}),
            ("alice-login", 10, {**login, **_user("alice")}),
            ("bob-login", 10, {**login, **_user("bob")}),
            ("carol-reset", 180, {**reset, **_user("carol")}),
            ("carol-login", 10, {**login, **_user("carol")}),
            ("dave-login", 20, {**login, **_user("dave")}),
            ("dave-reset", 10, {**reset, **_user("dave")}),
        ],
    )
    rule = _rule(
        {
            "reset": {"api.operation": "UpdateLoginProfile"},
            "login": {"api.operation": "ConsoleLogin"},
            "sequence": {
                "by": ["actor.user.name"],
                "first": "reset",
                "then": "login",
                "within": "1h",
            },
        }
    )
    assert _cited(store, config.tenant_id, rule, now) == [["alice-reset", "alice-login"]]


def test_a_sequence_pairs_up_when_its_first_event_is_delivered_last(
    conn, store, config, clean, now
):
    """The cycle that reads a late `first` evaluates the `then` it pairs with."""
    tenant, cycle = config.tenant_id, _boundary(now)
    rule = _rule(
        {
            "reset": {"api.operation": "UpdateLoginProfile"},
            "login": {"api.operation": "ConsoleLogin"},
            "sequence": {
                "by": ["actor.user.name"],
                "first": "reset",
                "then": "login",
                "within": "1h",
            },
            "timeframe": "1h",
        }
    )
    login = _trail(
        tenant,
        [cycle - timedelta(minutes=55)],
        cycle - timedelta(minutes=50),
        "login",
        op="ConsoleLogin",
        user="alice",
    )
    batch.load(store, login)
    run_all(conn, store, tenant, [rule], now=cycle)
    assert not _findings(conn, tenant, rule.id), "no reset has arrived yet"

    reset = _trail(
        tenant,
        [cycle - timedelta(minutes=70)],
        cycle + timedelta(minutes=30),
        "reset",
        op="UpdateLoginProfile",
        user="alice",
    )
    batch.load(store, reset)
    run_all(conn, store, tenant, [rule], now=cycle + timedelta(hours=1))
    assert [r["event_uids"] for r in _findings(conn, tenant, rule.id)] == [
        [reset[0]["event_uid"], login[0]["event_uid"]]
    ]


def test_fieldref_tells_a_key_made_for_someone_else(store, config, clean, now):
    create = {"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com"}
    _calls(
        store,
        config.tenant_id,
        now,
        [
            ("other", 5, {**create, "requestParameters": {"userName": "bob"}}),
            ("self", 5, {**create, "requestParameters": {"userName": "Alice"}}),
            ("implicit", 5, {**create}),
        ],
    )
    rule = _rule(
        {
            "s": {
                "api.operation": "CreateAccessKey",
                "raw.requestParameters.userName|exists": True,
            },
            "same": {"raw.requestParameters.userName|fieldref": "actor.user.name"},
            "condition": "s and not same",
        }
    )
    assert _cited(store, config.tenant_id, rule, now) == [["other"]]


def test_cidr_tells_internal_addresses_from_the_internet(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            (ip, 5, {"sourceIPAddress": ip, **_user(ip)})
            for ip in (
                "10.1.2.3",
                "172.20.0.1",
                "172.32.0.1",
                "fd12:3456::1",
                "2001:db8::1",
                "203.0.113.5",
            )
        ],
    )
    rule = _rule(
        {
            "s": {"src_endpoint.ip|exists": True},
            "internal": {"src_endpoint.ip|cidr": ["10.0.0.0/8", "172.16.0.0/12", "fc00::/7"]},
            "condition": "s and not internal",
        },
        entity="src_endpoint.ip",
    )
    found = run_rule(store, config.tenant_id, rule, now - timedelta(hours=1), now)
    assert sorted(f.entity_key for f in found) == ["172.32.0.1", "2001:db8::1", "203.0.113.5"]


def test_first_seen_fires_once_on_a_new_tuple_after_the_lookback_is_known(
    store, config, clean, now
):
    login = {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}
    tenant = config.tenant_id
    _calls(
        store,
        tenant,
        now,
        [
            ("known", 10, {**login, "sourceIPAddress": "198.51.100.1"}),
            ("new-1", 10, {**login, "sourceIPAddress": "203.0.113.9"}),
            ("new-2", 5, {**login, "sourceIPAddress": "203.0.113.9"}),
        ],
    )
    rule = _rule(
        {"s": {"api.operation": "ConsoleLogin", "status": "Success"}},
        baseline={"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "7d"},
    )
    assert _cited(store, tenant, rule, now) == [], "no history older than the lookback yet"
    day = 24 * 60
    _calls(
        store,
        tenant,
        now,
        [
            ("old", 8 * day, {}),
            ("seen", 2 * day, {**login, "sourceIPAddress": "198.51.100.1"}),
            (
                "failed",
                1 * day,
                {**login, "sourceIPAddress": "203.0.113.9", "errorCode": "Failed authentication"},
            ),
        ],
    )
    assert _cited(store, tenant, rule, now) == [["new-1"]]


def test_a_rule_that_fires_while_learning_fires_on_every_match_until_it_knows(
    store, config, clean, now
):
    """`while_learning: fire` keeps a rule as loud as it was before its baseline
    until the lookback is covered, then only a new tuple fires (DET-1)."""
    login = {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}
    tenant = config.tenant_id
    _calls(
        store,
        tenant,
        now,
        [
            ("known", 10, {**login, "sourceIPAddress": "198.51.100.1"}),
            ("new-1", 10, {**login, "sourceIPAddress": "203.0.113.9"}),
        ],
    )
    rule = _rule(
        {"s": {"api.operation": "ConsoleLogin", "status": "Success"}},
        baseline={
            "first_seen": ["actor.user.name", "src_endpoint.ip"],
            "lookback": "7d",
            "while_learning": "fire",
        },
    )
    learning = sorted(u for uids in _cited(store, tenant, rule, now) for u in uids)
    assert learning == ["known", "new-1"], "nothing is familiar yet, so every match fires"
    day = 24 * 60
    _calls(
        store,
        tenant,
        now,
        [("old", 8 * day, {}), ("seen", 2 * day, {**login, "sourceIPAddress": "198.51.100.1"})],
    )
    assert _cited(store, tenant, rule, now) == [["new-1"]]


def test_a_rule_that_learns_from_its_selection_waits_for_its_own_history(store, config, clean, now):
    """`learns_from: selection` counts the lookback from the rule's own first
    match: a product with months of other events has not learnt an event it
    only began to send (D157)."""
    login = {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}
    tenant, day = config.tenant_id, 24 * 60
    _calls(
        store,
        tenant,
        now,
        [
            ("old", 30 * day, {}),
            ("first", 3 * day, {**login, "sourceIPAddress": "198.51.100.1"}),
            ("new-1", 10, {**login, "sourceIPAddress": "203.0.113.9"}),
        ],
    )
    detection = {"s": {"api.operation": "ConsoleLogin"}}
    baseline = {"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "7d"}
    assert _cited(store, tenant, _rule(detection, baseline=baseline), now) == [["new-1"]]
    own = _rule(detection, baseline={**baseline, "learns_from": "selection"})
    assert _cited(store, tenant, own, now) == [], "its first login is three days old"
    _calls(store, tenant, now, [("older", 8 * day, {**login, "sourceIPAddress": "198.51.100.1"})])
    assert _cited(store, tenant, own, now) == [["new-1"]]


def test_a_new_stripe_source_does_not_fire_on_the_payouts_it_backfilled(
    conn, store, config, clean, now
):
    """A Stripe source's first poll reads months of activity log, and its first
    payout event the 60 days of payouts before it. None of those payouts is
    new; a later payout to another destination is (D157)."""
    rule = next(r for r in RULES if r.id == "stripe_payout_to_new_destination")
    mapping = ocsf.load_mapping("stripe")
    tenant = config.tenant_id

    def payout(uid, when, destination, ingested):
        created = int(when.timestamp())
        row = mapping.map_record(
            {
                "id": uid,
                "type": "payout.created",
                "created": created,
                "data": {"object": {"id": uid, "object": "payout", "destination": destination}},
            },
            tenant,
        )
        row["ingested_at"] = ingested.isoformat()
        return row

    log = mapping.map_record(
        {
            "id": "accact_old",
            "object": "v2.iam.activity_log",
            "type": "api_key_created",
            "created": (now - timedelta(days=150)).isoformat(),
            "context": "acct_1PfakeAccount01",
            "details": {"type": "api_key", "api_key": {"id": "mk_1", "type": "secret_key"}},
        },
        tenant,
    )
    loaded = now - timedelta(minutes=1)
    usual = [
        payout(f"po_{d}", now - timedelta(days=d), "ba_1PfakeUsualBank01", loaded)
        for d in range(61, 0, -1)
    ]
    batch.load(store, [log, *usual])
    run_all(conn, store, tenant, [rule], now=now)
    assert _findings(conn, tenant, rule.id) == [], "a backfilled payout is history"

    later = now + timedelta(minutes=4)
    batch.load(
        store,
        [
            payout("po_usual", now + timedelta(minutes=2), "ba_1PfakeUsualBank01", later),
            payout("po_new", now + timedelta(minutes=2), "card_1PfakeDebit00001", later),
        ],
    )
    run_all(conn, store, tenant, [rule], now=now + timedelta(minutes=5))
    assert [r["entity_key"] for r in _findings(conn, tenant, rule.id)] == ["po_new"]


def test_first_seen_is_learning_per_account(conn, store, config, clean, now):
    """A second AWS account connected yesterday is not new on every key it has,
    though the product has months of history from the first (D76, D79)."""
    login = {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "sourceIPAddress": "203.0.113.9",
    }
    tenant, day = config.tenant_id, 24 * 60
    _calls(
        store,
        tenant,
        now,
        [
            ("old", 60 * day, {"recipientAccountId": "111111111111"}),
            ("in-a", 10, {**login, "recipientAccountId": "111111111111"}),
            (
                "in-b",
                10,
                {**login, "recipientAccountId": "222222222222", "sourceIPAddress": "203.0.113.10"},
            ),
            # Familiar in the first account, new in this one.
            ("in-c", 10, {**login, "recipientAccountId": "333333333333"}),
        ],
    )
    for source, account, days in (
        ("aws_cloudtrail", "111111111111", 60),
        ("aws_cloudtrail:second", "222222222222", 1),
        ("aws_cloudtrail:third", "333333333333", 60),
    ):
        execute(
            conn,
            """INSERT INTO shoc.source_history
                   (tenant_id, source, products, first_event_at, account_uids)
               VALUES (%s, %s, %s, now() - %s * interval '1 day', %s)""",
            (tenant, source, ["AWS CloudTrail"], days, [account]),
        )
    rule = _rule(
        {"s": {"api.operation": "ConsoleLogin"}},
        baseline={"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "30d"},
    )
    run_all(conn, store, tenant, [rule], now=now, lookback_seconds=3600)
    assert [r["event_uids"] for r in _findings(conn, tenant, rule.id)] == [["in-a", "in-c"]]


def test_history_that_named_no_account_is_familiar_in_every_account(
    conn, store, config, clean, now
):
    """Events loaded before a source named its account are still its history,
    so a source that starts naming its org does not make everyone new (RFC 0025)."""
    login = {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "sourceIPAddress": "203.0.113.9",
    }
    tenant, day = config.tenant_id, 24 * 60
    _calls(
        store,
        tenant,
        now,
        [
            ("old", 60 * day, {}),
            ("before", 2 * day, login),
            ("named", 10, {**login, "recipientAccountId": "111111111111"}),
        ],
    )
    execute(
        conn,
        """INSERT INTO shoc.source_history
               (tenant_id, source, products, first_event_at, account_uids)
           VALUES (%s, 'aws_cloudtrail', %s, now() - interval '60 days', %s)""",
        (tenant, ["AWS CloudTrail"], ["111111111111"]),
    )
    rule = _rule(
        {"s": {"api.operation": "ConsoleLogin"}},
        baseline={"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "30d"},
    )
    run_all(conn, store, tenant, [rule], now=now, lookback_seconds=3600)
    assert _findings(conn, tenant, rule.id) == []


def test_entity_falls_back_when_the_first_field_is_empty(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            ("bucket", 5, {"requestParameters": {"bucketName": "payroll"}}),
            ("none", 5, {}),
        ],
    )
    rule = _rule(
        {"s": {"api.operation": "GetObject"}},
        entity=["raw.requestParameters.bucketName", "actor.user.name"],
    )
    found = run_rule(store, config.tenant_id, rule, now - timedelta(hours=1), now)
    assert sorted(f.entity_key for f in found) == ["alice", "payroll"]


def test_a_keyed_list_item_is_read_by_name(store, config, clean, now):
    from dataclasses import replace

    mapping = replace(
        ocsf.load_mapping("google_workspace"),
        keyed={
            "params": {
                "path": "events[*].parameters",
                "key": "name",
                "value": ["value", "boolValue"],
            }
        },
    )
    records = [
        {
            "id": {
                "uniqueQualifier": uid,
                "applicationName": "admin",
                "time": (now - timedelta(minutes=5)).isoformat(),
            },
            "actor": {"email": "admin@example.com"},
            "ipAddress": "198.51.100.9",
            "events": [
                {
                    "type": "APPLICATION_SETTINGS",
                    "name": "CHANGE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Allow users to install"},
                        {"name": "NEW_VALUE", "boolValue": value},
                    ],
                }
            ],
        }
        for uid, value in (("on", True), ("off", False))
    ]
    batch.load(store, [mapping.map_record(r, config.tenant_id) for r in records])
    rule = ruleset.from_dict(
        {
            "id": "TEST-KEYED",
            "title": "t",
            "logsource": {"product": "google"},
            "entity": "actor.user.name",
            "detection": {
                "s": {
                    "unmapped.params.SETTING_NAME|startswith": "allow users",
                    "unmapped.params.NEW_VALUE": True,
                }
            },
        }
    )
    assert _cited(store, config.tenant_id, rule, now) == [["on"]]


def test_a_source_path_with_a_hyphen_matches(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            (
                "public",
                5,
                {"eventName": "PutBucketAcl", "requestParameters": {"x-amz-acl": ["public-read"]}},
            ),
            (
                "private",
                5,
                {"eventName": "PutBucketAcl", "requestParameters": {"x-amz-acl": ["private"]}},
            ),
            (
                "sse-c",
                5,
                {
                    "requestParameters": {
                        "x-amz-server-side-encryption-customer-algorithm": "AES256"
                    }
                },
            ),
        ],
    )
    acl = "raw.requestParameters.x-amz-acl"
    rule = _rule({"s": {f"{acl}|contains": "public-read"}}, fields=[acl])
    assert _cited(store, config.tenant_id, rule, now) == [["public"]]
    sse = "raw.requestParameters.x-amz-server-side-encryption-customer-algorithm"
    assert _cited(store, config.tenant_id, _rule({"s": {f"{sse}|exists": True}}), now) == [
        ["sse-c"]
    ]


def test_contains_re_and_exists_read_a_json_list_or_object(store, config, clean, now):
    _calls(
        store,
        config.tenant_id,
        now,
        [
            (
                "list",
                5,
                {
                    "requestParameters": {
                        "groups": ["admins", "Domain Admins"],
                        "policy": {"Effect": "Allow"},
                    }
                },
            ),
            ("other", 5, {"requestParameters": {"groups": ["staff"]}}),
        ],
    )
    expect = {
        "raw.requestParameters.groups|contains": ("domain admins", [["list"]]),
        "raw.requestParameters.groups|re": ('"admins"', [["list"]]),
        "raw.requestParameters.policy|exists": (True, [["list"]]),
        "raw.requestParameters.policy|contains": ("allow", [["list"]]),
    }
    for field_spec, (value, cited) in expect.items():
        rule = _rule({"s": {field_spec: value}})
        assert _cited(store, config.tenant_id, rule, now) == cited, field_spec
    assert (
        _cited(
            store,
            config.tenant_id,
            _rule({"s": {"raw.requestParameters.groups|contains": "root"}}),
            now,
        )
        == []
    )
