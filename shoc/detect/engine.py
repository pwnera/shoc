"""Run rules, correlate the hits, write findings (DET-1, DET-3).

Correlation is deliberately simple and explainable. A match rule groups its hits
by entity inside a time bucket the size of the rule's timeframe. A threshold rule
fires for a group when a timeframe-long window that starts at one of its events
holds enough of them, or enough distinct values of its `count_distinct` field,
and the finding is filed under the bucket that window starts in. Buckets sit on fixed clock boundaries, so evaluating one again updates
the same finding instead of creating another.

A scheduled cycle reads by ingestion time. It asks which event-time buckets the
matches ingested since the rule's watermark fall in, and evaluates each of those
buckets whole, so a late event, a burst spread over several cycles and a backlog
after an outage come out the way one backfill over the same events would. A
bucket that fails two cycles in a row is left out, named in `rule_state` and
handed to the Manager, so one bad bucket never stops the rule.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.cases import engine as case_engine
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.detect import rules as ruleset
from shoc.detect.compiler import CompiledRule, compile_rule, evidence_sql, page_sql
from shoc.errors import StoreError
from shoc.store import ocsf as layout
from shoc.store.base import EventStore

MAX_EVIDENCE = 20
PAGE = 1000
# Past this many candidate groups in one bucket, a cycle evaluates the ones with
# the most events and says how many it left out. A spray from more addresses
# than this still raises findings.
MAX_GROUPS = 10_000
# Past this many buckets in one cycle, the newest are evaluated and the rest named.
MAX_BUCKETS = 10_000
# rule.test, rule.backtest and the Detection Engineer read at most this many rows
# per scan and groups per rule; only a scheduled cycle or a lookback reads all.
ADHOC_LIMIT = 200
# `ingested_at` is stamped when an event is mapped and the event is visible once
# its batch commits, so a cycle reads again this far behind its watermark, and
# further back to the oldest stamp of a load that committed after the watermark
# (`shoc.store_loads`). An event read twice only refreshes its finding.
SETTLE = timedelta(minutes=10)
# The most ingestion time one rule reads in one cycle. After an outage the
# watermark walks forward by this much per cycle until it reaches now.
CATCH_UP = timedelta(hours=6)


@dataclass
class Finding:
    finding_uid: str
    tenant_id: str
    rule_id: str
    title: str
    severity: str
    confidence: float
    entity_key: str
    window_start: datetime
    window_end: datetime
    first_seen: datetime
    last_seen: datetime
    event_count: int
    event_uids: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    entities: list[str] = field(default_factory=list)
    status: str = "new"


def _bucket(ts: datetime, seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=UTC)


def _uid(tenant_id: str, rule_id: str, entity: str, window_start: datetime) -> str:
    blob = f"{tenant_id}|{rule_id}|{entity}|{window_start.isoformat()}"
    return "F-" + hashlib.sha256(blob.encode()).hexdigest()[:24]


# The columns worth correlating on, and the prefix each gets in an entity key.
ENTITY_COLUMNS = {
    "actor_user_name": "user",
    "actor_session_uid": "key",
    "src_endpoint_ip": "ip",
    "resource_uid": "resource",
    "cloud_account_uid": "account",
    "device_hostname": "host",
    # The id the source gives the machine: the EDR's device id (CrowdStrike aid,
    # Defender machineId, SentinelOne agent UUID), an instance id in AWS.
    "device_uid": "device",
}

# A file's hash is an entity of the finding but not a place in the graph or the
# inventory: powershell.exe's hash ran on every laptop (RSP-2).
HASH_COLUMNS = {
    "process_hash_sha256": "process_hash",
    "file_hash_sha256": "file_hash",
}


def entities_of(row: dict[str, Any]) -> list[str]:
    """Typed entity keys for one event row: user:alice, key:AKIA…, ip:203.0.113.5."""
    out = []
    for column, prefix in (ENTITY_COLUMNS | HASH_COLUMNS).items():
        value = row.get(column)
        if value not in (None, "", "-"):
            out.append(f"{prefix}:{value}")
    # A session key (ASIA…) was issued to a role; CloudTrail and GuardDuty name
    # the role as the user, and only the role's sessions can be revoked.
    if row.get("actor_user_type") == "AssumedRole" and row.get("actor_user_name"):
        out.append(f"role:{row['actor_user_name']}")
    # A finding's remote peer (GuardDuty's C2 address on an outbound call) is
    # what it is about. Telemetry's destinations are every CDN a host talks to,
    # so only findings make it an entity.
    if row.get("class_uid") == 2004 and row.get("dst_endpoint_ip") not in (None, ""):
        out.append(f"ip:{row['dst_endpoint_ip']}")
    return sorted(dict.fromkeys(out))


def _entity_value(row: dict[str, Any], rule: ruleset.Rule) -> str:
    """The first of the rule's entity fields, then its group fields, that has a value."""
    for f in (*rule.entity, *rule.detection.group_by):
        col = layout.alias_for(f)
        if col and row.get(col) not in (None, ""):
            return str(row[col])
    return "-"


def _scan(
    store: EventStore, sql: str, params: dict[str, Any], limit: int = 0
) -> Iterator[dict[str, Any]]:
    """Every row of a scan, or its first `limit`, read one keyset page at a time."""
    after: dict[str, Any] = {}
    left = limit or -1
    while True:
        size = min(PAGE, left) if left > 0 else PAGE
        rows = store.query(page_sql(sql, bool(after), size), {**params, **after}, size).rows
        yield from rows
        left -= len(rows)
        if len(rows) < size or left == 0:
            return
        after = {"after_time": rows[-1]["time"], "after_uid": rows[-1]["event_uid"]}


def run_rule(
    store: EventStore,
    tenant_id: str,
    rule: ruleset.Rule,
    window_start: datetime,
    window_end: datetime,
    limit: int = ADHOC_LIMIT,
    notes: list[str] | None = None,
    learning: dict[str, datetime] | None = None,
) -> list[Finding]:
    """Evaluate `rule` over the events whose time is in [window_start, window_end).

    A threshold window may start anywhere in that range and runs one timeframe
    from its first event, so it also reads the timeframe after `window_end`.
    `limit` caps the rows of each scan and the groups; 0 reads everything, and
    then the groups past `MAX_GROUPS` that were left out are written to `notes`.
    `learning` is `accounts_learning` for a first-seen rule.
    """
    compiled = compile_rule(rule, learning)
    params: dict[str, Any] = dict(compiled.params)
    params.update({"tenant_id": tenant_id, "window_start": window_start, "window_end": window_end})
    if rule.is_aggregate:
        params["window_end"] = window_end + timedelta(seconds=rule.timeframe_seconds)
        return _thresholds(
            store, tenant_id, rule, compiled, params, window_start, window_end, limit, notes
        )
    return _matches(store, tenant_id, rule, compiled, params, limit)


def _thresholds(
    store: EventStore,
    tenant_id: str,
    rule: ruleset.Rule,
    compiled: CompiledRule,
    params: dict[str, Any],
    window_start: datetime,
    window_end: datetime,
    limit: int,
    notes: list[str] | None,
) -> list[Finding]:
    seconds = rule.timeframe_seconds
    span = timedelta(seconds=seconds)
    need = compiled.count_value + (compiled.count_op == ">")
    groups = store.query(compiled.agg_sql, params, limit or MAX_GROUPS)
    if groups.truncated and not limit and notes is not None:
        notes.append(
            f"{window_start:%Y-%m-%d %H:%M}: more than {MAX_GROUPS} groups reached the "
            f"threshold; only the {MAX_GROUPS} with the most events were evaluated"
        )
    findings: list[Finding] = []
    for g in groups.rows:
        values = [g[c] for c in compiled.group_columns]
        gparams = dict(params)
        gparams.update({f"g_{i}": v for i, v in enumerate(values) if v is not None})
        rows = list(_scan(store, evidence_sql(compiled, values), gparams, limit))
        times = [r["time"] for r in rows]
        # What a window counts: each event, or each distinct value of `count_distinct`.
        key = compiled.distinct_column
        counted = [r[key] for r in rows] if key else list(range(len(rows)))
        # bucket -> (first row of its first window, end of its last window, last window's start)
        fired: dict[datetime, tuple[int, int, datetime]] = {}
        inside: Counter[Any] = Counter()  # counted values of rows[i:end]
        distinct = end = 0
        for i, t in enumerate(times):
            while end < len(times) and times[end] < t + span:
                value = counted[end]
                if value is not None:
                    distinct += inside[value] == 0
                    inside[value] += 1
                end += 1
            if window_start <= t < window_end and distinct >= need:
                bucket = _bucket(t, seconds)
                fired[bucket] = (fired[bucket][0] if bucket in fired else i, end, t)
            value = counted[i]
            if value is not None:
                inside[value] -= 1
                distinct -= inside[value] == 0
        entity = "|".join(str(g[c]) for c in compiled.group_columns)
        group_entities = {
            f"{ENTITY_COLUMNS[c]}:{g[c]}"
            for c in compiled.group_columns
            if c in ENTITY_COLUMNS and g[c] not in (None, "")
        }
        for bucket, (first, last, last_start) in fired.items():
            # One event per counted value first, so the citations show the spread.
            cited_by: dict[Any, dict[str, Any]] = {}
            for value, r in zip(counted[first:last], rows[first:last], strict=True):
                cited_by.setdefault(value, r)
            cited = list(cited_by.values())[:MAX_EVIDENCE]
            findings.append(
                _finding(
                    rule,
                    tenant_id,
                    entity,
                    bucket,
                    last_start + span,
                    times[first],
                    times[last - 1],
                    last - first,
                    [str(r["event_uid"]) for r in cited],
                    {
                        "kind": "aggregate",
                        "group": {c: str(g[c]) for c in compiled.group_columns},
                        "threshold": f"{compiled.count_op} {compiled.count_value}",
                        **(
                            {"distinct": rule.detection.count_distinct}
                            if compiled.distinct_column
                            else {}
                        ),
                    },
                    sorted({e for r in cited for e in entities_of(r)} | group_entities),
                )
            )
    return findings


def _matches(
    store: EventStore,
    tenant_id: str,
    rule: ruleset.Rule,
    compiled: CompiledRule,
    params: dict[str, Any],
    limit: int,
) -> list[Finding]:
    seconds = rule.timeframe_seconds
    # (entity, bucket) -> [its first rows up to the evidence cap, hit count, last time]
    buckets: dict[tuple[str, datetime], list[Any]] = {}
    for row in _scan(store, compiled.select_sql, params, limit):
        key = (_entity_value(row, rule), _bucket(row["time"], seconds))
        seen = buckets.setdefault(key, [[], 0, row["time"]])
        if len(seen[0]) < MAX_EVIDENCE:
            seen[0].append(row)
        seen[1] += 1
        seen[2] = row["time"]
    findings: list[Finding] = []
    for (entity, start), (rows, count, last) in buckets.items():
        sample = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in rows[0].items()
            if k not in ("event_uid",)
        }
        findings.append(
            _finding(
                rule,
                tenant_id,
                entity,
                start,
                start + timedelta(seconds=seconds),
                rows[0]["time"],
                last,
                count,
                # A sequence cites the earlier event before the one that fired.
                list(
                    dict.fromkeys(
                        str(u) for r in rows for u in (r.get("sequence_first"), r["event_uid"]) if u
                    )
                )[:MAX_EVIDENCE],
                {"kind": "match", "sample": sample},
                sorted({e for r in rows for e in entities_of(r)}),
            )
        )
    return findings


def _finding(
    rule: ruleset.Rule,
    tenant_id: str,
    entity: str,
    window_start: datetime,
    window_end: datetime,
    first_seen: datetime,
    last_seen: datetime,
    count: int,
    event_uids: list[str],
    evidence: dict[str, Any],
    entities: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_uid=_uid(tenant_id, rule.id, entity, window_start),
        tenant_id=tenant_id,
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        entity_key=entity,
        window_start=window_start,
        window_end=window_end,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=count,
        event_uids=event_uids,
        attack=list(rule.attack),
        evidence=evidence,
        entities=list(entities or []),
    )


def upsert(conn: Any, finding: Finding) -> bool:
    """Insert or refresh a finding. Returns True when it is new."""
    row = fetch_one(
        conn,
        f"""INSERT INTO shoc.findings
             (finding_uid, tenant_id, rule_id, title, severity, confidence, status,
              entity_key, window_start, window_end, first_seen, last_seen,
              event_count, event_uids, attack, evidence, entities)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, rule_id, entity_key, window_start) DO UPDATE SET
             first_seen = LEAST(shoc.findings.first_seen, EXCLUDED.first_seen),
             last_seen = GREATEST(shoc.findings.last_seen, EXCLUDED.last_seen),
             window_end = GREATEST(shoc.findings.window_end, EXCLUDED.window_end),
             -- Every evaluation counts its whole bucket, so the larger count is
             -- the one that has seen more of it.
             event_count = GREATEST(shoc.findings.event_count, EXCLUDED.event_count),
             -- What was cited stays cited; new events fill what is left of the cap.
             event_uids = ARRAY(
               SELECT u FROM unnest(shoc.findings.event_uids || EXCLUDED.event_uids)
                 WITH ORDINALITY AS t(u, n)
               GROUP BY u ORDER BY min(n) LIMIT {MAX_EVIDENCE}),
             -- Intake's and Sentinel's marks are read again only when a newer
             -- event arrives: re-reading the same bucket is not news (D43).
             evidence = CASE WHEN EXCLUDED.last_seen > shoc.findings.last_seen
                             THEN EXCLUDED.evidence
                             ELSE EXCLUDED.evidence || jsonb_strip_nulls(jsonb_build_object(
                                 'intake', shoc.findings.evidence -> 'intake',
                                 'sentinel', shoc.findings.evidence -> 'sentinel')) END,
             entities = ARRAY(
               SELECT DISTINCT e FROM unnest(shoc.findings.entities || EXCLUDED.entities) AS e
               ORDER BY e),
             updated_at = now()
           RETURNING (xmax = 0) AS inserted""",
        (
            finding.finding_uid,
            finding.tenant_id,
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.confidence,
            finding.status,
            finding.entity_key,
            finding.window_start,
            finding.window_end,
            finding.first_seen,
            finding.last_seen,
            finding.event_count,
            finding.event_uids,
            finding.attack,
            json.dumps(finding.evidence, default=str),
            finding.entities,
        ),
    )
    return bool(row and row["inserted"])


def _window(
    watermark: datetime | None,
    now: datetime,
    first: timedelta,
    late: Sequence[tuple[datetime, datetime]] = (),
) -> tuple[datetime, datetime]:
    """The ingestion range a cycle reads: from `SETTLE` before the watermark, or
    `first` back when there is none, and at most `CATCH_UP` of it. A load in
    `late` (committed, oldest stamp) that committed after the watermark pulls
    the start back to its oldest stamp, however slow it was (DET-3)."""
    start = watermark - SETTLE if watermark else now - first
    end = min(now, start + CATCH_UP)
    if watermark:
        start = min([start, *(stamp for committed, stamp in late if committed > watermark)])
    return start, end


def _since_watermark(
    store: EventStore,
    tenant_id: str,
    rule: ruleset.Rule,
    start: datetime,
    end: datetime,
    skip: bool,
    notes: list[str],
    learning: dict[str, datetime] | None = None,
) -> list[Finding]:
    """Evaluate, one at a time, the buckets that matches ingested in [start, end) fall in.

    A bucket that fails raises, so the watermark stays and the next cycle tries
    again. With `skip`, set when the rule's last cycle failed as well, the bucket
    is left out and named in `notes`, and the rest of the range goes on.
    """
    seconds = rule.timeframe_seconds
    span = timedelta(seconds=seconds)
    compiled = compile_rule(rule, learning)
    params: dict[str, Any] = dict(compiled.params)
    params.update({"tenant_id": tenant_id, "ingested_from": start, "ingested_to": end})
    listed = store.query(compiled.buckets_sql, params, MAX_BUCKETS)
    buckets = {datetime.fromtimestamp(int(r["bucket"]) * seconds, tz=UTC) for r in listed.rows}
    if listed.truncated:
        notes.append(
            f"more than {MAX_BUCKETS} buckets arrived in one cycle; those before "
            f"{min(buckets):%Y-%m-%d %H:%M} were not evaluated"
        )
    if rule.is_aggregate:
        # A new event also counts toward windows that began up to one timeframe before it.
        buckets |= {b - span for b in buckets}
    found: list[Finding] = []
    for bucket in sorted(buckets):
        try:
            found += run_rule(store, tenant_id, rule, bucket, bucket + span, 0, notes, learning)
        except Exception as exc:
            if not skip:
                raise
            notes.append(f"{bucket:%Y-%m-%d %H:%M} not evaluated: {exc}")
    return found


def _ran(
    conn: Any, tenant_id: str, rule_id: str, mark: datetime | None, fires: int, notes: list[str]
) -> None:
    """Record a finished cycle. What it left out stays in `last_error` until the
    next clean cycle and reaches the Manager's weekly digest."""
    note = "; ".join(notes)[:2000] or None
    execute(
        conn,
        """INSERT INTO shoc.rule_state (tenant_id, rule_id, last_run_at, watermark, fires, last_error)
           VALUES (%s,%s,now(),%s,%s,%s)
           ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
             last_run_at = now(),
             watermark = COALESCE(EXCLUDED.watermark, shoc.rule_state.watermark),
             fires = shoc.rule_state.fires + EXCLUDED.fires, last_error = EXCLUDED.last_error""",
        (tenant_id, rule_id, mark, fires, note),
    )
    if note:
        from shoc.agents import manager

        manager.tell(conn, tenant_id, "detect", "digest", f"{rule_id}: {note}", group_key=rule_id)


def _last_load(conn: Any, tenant_id: str) -> datetime | None:
    row = fetch_one(
        conn,
        "SELECT max(loaded_at) AS loaded_at FROM shoc.store_loads WHERE tenant_id = %s",
        (tenant_id,),
    )
    return row["loaded_at"] if row else None


def _late_loads(conn: Any, tenant_id: str) -> list[tuple[datetime, datetime]]:
    """(committed, oldest stamp) of each recorded load that took longer than
    `SETTLE` from mapping to commit."""
    return [
        (r["loaded_at"], r["stamped_from"])
        for r in fetch_all(
            conn,
            """SELECT loaded_at, stamped_from FROM shoc.store_loads
               WHERE tenant_id = %s AND stamped_from < loaded_at - %s""",
            (tenant_id, SETTLE),
        )
    ]


def _idle(conn: Any, tenant_id: str, rule_id: str, now: datetime) -> None:
    """Nothing was loaded since the range began, so the rule has read it all:
    the watermark moves to now without a query. A store that has never
    stamped a load is read as usual (D71)."""
    execute(
        conn,
        """UPDATE shoc.rule_state SET watermark = %s, last_run_at = now()
           WHERE tenant_id = %s AND rule_id = %s""",
        (now, tenant_id, rule_id),
    )


def _failed(
    conn: Any, tenant_id: str, rule_id: str, error: str, attempted: datetime | None
) -> None:
    """Record a failed cycle. A rule with no watermark yet keeps the start it
    attempted, so the cycle that recovers reads from there."""
    execute(
        conn,
        """INSERT INTO shoc.rule_state (tenant_id, rule_id, last_run_at, watermark, last_error)
           VALUES (%s,%s,now(),%s,%s)
           ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
             last_run_at = now(), last_error = EXCLUDED.last_error,
             watermark = COALESCE(shoc.rule_state.watermark, EXCLUDED.watermark)""",
        (tenant_id, rule_id, attempted, error[:2000]),
    )


# The indicator matcher keeps its watermark in `rule_state` under this id (DET-4).
INDICATORS = "ioc_match"


def match_indicators(
    conn: Any,
    store: EventStore,
    tenant_id: str,
    lookback_seconds: int | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Match events against known indicators and write the findings (DET-4).

    Without a lookback it reads what was ingested since its watermark, the way
    a rule does, so a late event or an outage is matched too. A lookback matches
    by event time and leaves the watermark alone.
    """
    from shoc.detect import intel

    now = now or datetime.now(UTC)
    if lookback_seconds:
        since = now - timedelta(seconds=lookback_seconds)
        return intel.findings_from_hits(
            conn, tenant_id, intel.match_window(conn, store, tenant_id, since, now)
        )
    row = fetch_one(
        conn,
        "SELECT watermark FROM shoc.rule_state WHERE tenant_id = %s AND rule_id = %s",
        (tenant_id, INDICATORS),
    )
    start, end = _window(
        row["watermark"] if row else None, now, timedelta(minutes=30), _late_loads(conn, tenant_id)
    )
    last = _last_load(conn, tenant_id)
    if row and row["watermark"] and last and last < start:
        _idle(conn, tenant_id, INDICATORS, now)
        return []
    try:
        hits = intel.match_window(conn, store, tenant_id, start, end, column="ingested_at")
        found = intel.findings_from_hits(conn, tenant_id, hits)
    except Exception as exc:
        _failed(conn, tenant_id, INDICATORS, f"{type(exc).__name__}: {exc}", start)
        raise
    _ran(conn, tenant_id, INDICATORS, end, len(found), [])
    return found


def accounts_learning(rule: ruleset.Rule, history: list[dict[str, Any]]) -> dict[str, datetime]:
    """When each account's own history first covers a first-seen rule's lookback.

    From `shoc.source_history`, per account its sources speak for, the way hunt
    readiness is (D79): a second AWS account connected today is learning even
    though the product has months of history from the first. An account two
    sources share counts from the earlier one.
    """
    products = set(
        layout.products_for(rule.logsource.get("product", ""), rule.logsource.get("service", ""))
    )
    starts: dict[str, datetime] = {}
    for row in history:
        if products and not products & set(row["products"] or []):
            continue
        for account in row["account_uids"] or []:
            starts[account] = min(starts.get(account, row["start"]), row["start"])
    lookback = timedelta(seconds=ruleset.parse_timeframe(rule.lookback))
    return {account: start + lookback for account, start in starts.items()}


@dataclass
class DetectStats:
    rules_run: int = 0
    findings_new: int = 0
    findings_updated: int = 0
    errors: dict[str, str] = field(default_factory=dict)


def run_all(
    conn: Any,
    store: EventStore,
    tenant_id: str,
    rules: list[ruleset.Rule] | None = None,
    *,
    now: datetime | None = None,
    lookback_seconds: int | None = None,
    config: Any = None,
) -> DetectStats:
    """One detection cycle: every enabled rule over what was ingested since its watermark.

    An explicit lookback is an instruction instead: every rule evaluates the
    events whose time falls in that many seconds before now, and the watermarks
    stay where they are, so the next scheduled cycle still reads everything
    ingested since the last one.
    """
    rules = rules if rules is not None else ruleset.load(config, conn, tenant_id)
    now = now or datetime.now(UTC)
    stats = DetectStats()
    states = {
        r["rule_id"]: r
        for r in fetch_all(
            conn,
            "SELECT rule_id, watermark, last_error FROM shoc.rule_state WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    last = None if lookback_seconds else _last_load(conn, tenant_id)
    late = [] if lookback_seconds else _late_loads(conn, tenant_id)
    history = fetch_all(
        conn,
        """SELECT products, account_uids, coalesce(first_event_at, first_loaded_at) AS start
           FROM shoc.source_history WHERE tenant_id = %s""",
        (tenant_id,),
    )
    for rule in rules:
        learning = accounts_learning(rule, history) if rule.first_seen else None
        state = states.get(rule.id) or {}
        span = timedelta(seconds=rule.timeframe_seconds)
        start, end = _window(state.get("watermark"), now, span, late)
        if state.get("watermark") and last and last < start:
            _idle(conn, tenant_id, rule.id, now)
            stats.rules_run += 1
            continue
        notes: list[str] = []
        try:
            if lookback_seconds:
                since = now - timedelta(seconds=lookback_seconds)
                found = run_rule(store, tenant_id, rule, since, now, 0, notes, learning)
            else:
                skip = bool(state.get("last_error"))
                found = _since_watermark(store, tenant_id, rule, start, end, skip, notes, learning)
            new = 0
            for finding in found:
                if upsert(conn, finding):
                    new += 1
                    case_engine.publish(
                        conn,
                        tenant_id,
                        "finding.new",
                        finding.finding_uid,
                        {
                            "rule_id": finding.rule_id,
                            "severity": finding.severity,
                            "entity": finding.entity_key,
                            "events": finding.event_count,
                        },
                    )
                else:
                    stats.findings_updated += 1
            stats.findings_new += new
            if notes:
                stats.errors[rule.id] = "; ".join(notes)
            _ran(conn, tenant_id, rule.id, None if lookback_seconds else end, new, notes)
        except Exception as exc:
            # A store that is down, or whose table `shoc migrate` has not made
            # yet, is not this rule's fault: marking it would mark every rule.
            health = store.health()
            if not health.ok:
                raise StoreError(
                    f"event store unreachable, detection stopped: {health.detail}"
                ) from exc
            stats.errors[rule.id] = f"{type(exc).__name__}: {exc}"
            _failed(conn, tenant_id, rule.id, str(exc), None if lookback_seconds else start)
        stats.rules_run += 1
    return stats
