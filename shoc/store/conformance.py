"""The `EventStore` conformance suite (STO-1), shipped with the package.

Every adapter, shoc's own and any registered under the `shoc.stores` entry
point, passes these checks unchanged. Each check needs nothing but a store, so
an adapter can be tried without the rest of shoc:

    from shoc.store.conformance import run
    failures = run(my_store)  # {} when it conforms

Each check deletes the store's tenant's events first: open the store for a
throwaway tenant. `tests/conformance/test_store.py` runs these on every
backend the environment reaches, and the rest of `tests/conformance` drives the
same stores through the detection engine and the crew. CI runs them on
Postgres only: a warehouse is checked when someone points the suite at one by
hand (d850a10).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import StoreError
from shoc.store.base import EventStore, RetentionPolicy

Check = Callable[[EventStore], None]
CHECKS: list[Check] = []


def check(fn: Check) -> Check:
    CHECKS.append(fn)
    return fn


def run(store: EventStore) -> dict[str, str]:
    """Run every check; the failures by check name."""
    failures: dict[str, str] = {}
    for fn in CHECKS:
        try:
            fn(store)
        except Exception as exc:
            failures[fn.__name__] = f"{type(exc).__name__}: {exc}"
    return failures


def _rows(tenant: str, n: int, now: datetime, tag: str = "conf") -> list[dict[str, Any]]:
    from shoc.ingest import ocsf
    from shoc.ingest.replay import expand

    mapping = ocsf.load_mapping("aws_cloudtrail")
    records = expand(
        [
            {
                "eventID": tag,
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": "203.0.113.10",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "deploy-ci",
                    "accessKeyId": "AKIATEST",
                },
                "_repeat": n,
            }
        ],
        "aws_cloudtrail",
        now,
    )
    return [row for r in records for row in mapping.map_records(r, tenant)]


def _load(store: EventStore, rows: list[dict[str, Any]]) -> int:
    from shoc.ingest import batch

    return batch.load(store, rows).rows


def _uids(store: EventStore, tenant: str | None = None) -> list[str]:
    result = store.query(
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id ORDER BY event_uid",
        {"tenant_id": tenant or store.tenant_id},
    )
    return [str(r["event_uid"]) for r in result.rows]


def _fresh(store: EventStore) -> datetime:
    store.reset()
    return datetime.now(UTC)


@check
def load_query_roundtrip(store: EventStore) -> None:
    now = _fresh(store)
    assert _load(store, _rows(store.tenant_id, 5, now)) == 5, "a load reports the rows it added"
    result = store.query(
        "SELECT event_uid, time, api_operation FROM ocsf_events "
        "WHERE tenant_id = :tenant_id AND time >= :start ORDER BY time",
        {"tenant_id": store.tenant_id, "start": now - timedelta(hours=1)},
    )
    assert len(result.rows) == 5
    assert {r["api_operation"] for r in result.rows} == {"ListBuckets"}


@check
def a_replayed_batch_adds_nothing_and_keeps_what_it_had(store: EventStore) -> None:
    now = _fresh(store)
    rows = _rows(store.tenant_id, 3, now)
    assert _load(store, rows) == 3
    before = _uids(store)
    assert _load(store, rows) == 0, "replaying a batch must not duplicate events"
    assert _uids(store) == before, "replaying a batch must keep the events it repeats"


@check
def a_batch_that_repeats_an_event_stores_it_once(store: EventStore) -> None:
    now = _fresh(store)
    rows = _rows(store.tenant_id, 2, now)
    assert _load(store, rows + rows[:1]) == 2
    assert len(_uids(store)) == 2


@check
def a_batch_for_another_tenant_is_refused(store: EventStore) -> None:
    now = _fresh(store)
    try:
        _load(store, _rows(store.tenant_id, 2, now) + _rows("someone-else", 1, now, tag="other"))
    except StoreError:
        assert _uids(store) == [], "a refused batch stored rows"
        return
    raise AssertionError("a store took rows stamped for another tenant")


@check
def a_query_limit_reports_truncation(store: EventStore) -> None:
    now = _fresh(store)
    _load(store, _rows(store.tenant_id, 10, now))
    result = store.query(
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id",
        {"tenant_id": store.tenant_id},
        limit=4,
    )
    assert len(result.rows) == 4 and result.truncated


@check
def a_missing_parameter_is_an_error(store: EventStore) -> None:
    try:
        store.query("SELECT 1 FROM ocsf_events WHERE tenant_id = :tenant_id", {})
    except StoreError as exc:
        assert "missing query parameter" in str(exc)
    else:
        raise AssertionError("a query with a missing parameter ran")


@check
def the_read_path_refuses_a_write(store: EventStore) -> None:
    try:
        store.query(
            "DELETE FROM ocsf_events WHERE tenant_id = :tenant_id", {"tenant_id": store.tenant_id}
        )
    except StoreError:
        return
    raise AssertionError("query() ran a DELETE")


@check
def retention_drops_old_events(store: EventStore) -> None:
    now = _fresh(store)
    _load(store, _rows(store.tenant_id, 2, now - timedelta(days=400), tag="old"))
    _load(store, _rows(store.tenant_id, 2, now))
    assert store.apply_retention(RetentionPolicy(days=90)) >= 1
    assert len(_uids(store)) == 2


@check
def health_reports_counts(store: EventStore) -> None:
    now = _fresh(store)
    _load(store, _rows(store.tenant_id, 3, now))
    health = store.health()
    assert health.ok and health.event_count >= 3, health.detail


def _probe(
    store: EventStore, now: datetime, selection: dict[str, Any], limit: int | None = None
) -> list[Any]:
    """The findings of a CloudTrail rule over the last hour, one per actor."""
    from shoc.detect import rules as ruleset
    from shoc.detect.engine import ADHOC_LIMIT, run_rule

    rule = ruleset.from_dict(
        {
            "id": "probe",
            "title": "Probe",
            "description": "d",
            "attack": ["T1078"],
            "entity": "actor.user.name",
            "logsource": {"product": "aws", "service": "cloudtrail"},
            "detection": {"selection": selection, "condition": "selection"},
        }
    )
    start, end = now - timedelta(hours=1), now + timedelta(minutes=1)
    return run_rule(
        store, store.tenant_id, rule, start, end, ADHOC_LIMIT if limit is None else limit
    )


@check
def a_regex_rule_runs_on_this_backend(store: EventStore) -> None:
    """No shipped rule uses `|re` yet, so the dialect's regex function needs proving."""
    now = _fresh(store)
    _load(store, _rows(store.tenant_id, 3, now))
    found = _probe(store, now, {"actor.user.name|re": "^deploy-[a-z]+$"})
    assert found and found[0].event_count == 3


@check
def like_wildcards_in_a_value_match_only_themselves(store: EventStore) -> None:
    """`\\`, `%`, `_` and `!` are matched as written, though each dialect escapes LIKE
    its own way and BigQuery has no ESCAPE clause."""
    now = _fresh(store)
    special = ["\\", "%", "_", "!"]
    names = [f"{c}a" for c in special] + [f"a{c}" for c in special] + ["aa", "ba"]
    rows = _rows(store.tenant_id, len(names), now)
    for row, name in zip(rows, names, strict=True):
        row["actor_user_name"] = name
    _load(store, rows)
    for modifier, expected in (
        ("contains", names[:8]),
        ("startswith", names[:4]),
        ("endswith", names[4:8]),
    ):
        found = _probe(store, now, {f"actor.user.name|{modifier}": special})
        assert sorted(f.entity_key for f in found) == sorted(expected), modifier


@check
def a_scan_pages_past_events_that_share_one_time(store: EventStore) -> None:
    """A cycle pages by (time, event_uid); more than a page at one instant is still read whole."""
    from shoc.detect.engine import PAGE

    now = _fresh(store)
    rows = _rows(store.tenant_id, PAGE + 5, now)
    for row in rows:
        row["time"] = rows[0]["time"]
    _load(store, rows)
    found = _probe(store, now, {"api.operation": "ListBuckets"}, limit=0)
    assert [f.event_count for f in found] == [PAGE + 5]


@check
def a_source_record_comes_back_as_an_object(store: EventStore) -> None:
    """`raw` reads back whole on every backend, and a key with a `-` in it is reachable."""
    from shoc.store import ocsf as layout

    now = _fresh(store)
    rows = _rows(store.tenant_id, 1, now)
    asked = {"bucketName": "conf-bucket", "x-amz-acl": "public-read"}
    rows[0]["raw"]["requestParameters"] = asked
    _load(store, rows)
    acl = layout.column_for("raw.requestParameters.x-amz-acl")
    (row,) = store.query(
        f"SELECT raw, {acl} AS acl FROM ocsf_events WHERE tenant_id = :tenant_id",
        {"tenant_id": store.tenant_id},
    ).rows
    assert row["acl"] == "public-read"
    assert isinstance(row["raw"], dict), type(row["raw"])
    assert row["raw"]["requestParameters"] == asked
    assert row["raw"]["userIdentity"]["userName"] == "deploy-ci"


@check
def a_source_specific_field_is_queryable(store: EventStore) -> None:
    """`raw.<path>` reaches a field no OCSF column holds (RFC 0009).

    Okta's `debugContext` is the case this exists for: nothing in the flattened
    layout carries a device-token hash, and a rule still has to match on one.
    """
    from shoc.ingest import ocsf

    now = _fresh(store)
    mapping = ocsf.load_mapping("okta")
    rows = [
        mapping.map_records(
            {
                "uuid": f"dbg-{i}",
                "published": (now - timedelta(minutes=i)).isoformat(),
                "eventType": "user.session.start",
                "actor": {"id": "u1", "alternateId": "alice@example.com", "type": "User"},
                "client": {"ipAddress": "203.0.113.7", "zone": zone},
                "debugContext": {"debugData": {"dtHash": dt, "riskScore": score}},
            },
            store.tenant_id,
        )[0]
        for i, (zone, dt, score) in enumerate(
            [("OffNetwork", "aaa", "90"), ("OffNetwork", "aaa", "10"), ("Trusted", "bbb", "n/a")]
        )
    ]
    _load(store, rows)
    result = store.query(
        "SELECT event_uid, JSON_EXTRACT_SCALAR(raw, '$.debugContext.debugData.dtHash') AS dthash "
        "FROM ocsf_events WHERE tenant_id = :tenant_id "
        "AND JSON_EXTRACT_SCALAR(unmapped, '$.client.zone') = :zone ORDER BY event_uid",
        {"tenant_id": store.tenant_id, "zone": "OffNetwork"},
    )
    assert [r["dthash"] for r in result.rows] == ["aaa", "aaa"]

    # The non-numeric third row must not break a numeric comparison.
    guarded = (
        "CAST(CASE WHEN REGEXP_LIKE(JSON_EXTRACT_SCALAR(raw, '$.debugContext.debugData.riskScore'), "
        "'^-?[0-9]+([.][0-9]+)?$') THEN JSON_EXTRACT_SCALAR(raw, "
        "'$.debugContext.debugData.riskScore') END AS DOUBLE)"
    )
    hot = store.query(
        f"SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id AND {guarded} >= :floor",
        {"tenant_id": store.tenant_id, "floor": 50},
    )
    assert len(hot.rows) == 1


@check
def ingestion_lag_is_measured_in_seconds(store: EventStore) -> None:
    """Canonical SQL for a time difference, which every dialect spells differently (OPS-1)."""
    now = _fresh(store)
    rows = _rows(store.tenant_id, 1, now - timedelta(minutes=10))
    rows[0]["ingested_at"] = (
        datetime.fromisoformat(str(rows[0]["time"])) + timedelta(seconds=90)
    ).isoformat()
    _load(store, rows)
    from shoc.agents.ops import LAG_SECONDS

    result = store.query(
        f"SELECT {LAG_SECONDS} AS lag FROM ocsf_events WHERE tenant_id = :tenant_id",
        {"tenant_id": store.tenant_id},
    )
    assert round(float(result.rows[0]["lag"])) == 90, result.rows
