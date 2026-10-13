"""Event capabilities: typed search over the OCSF store, and ingest (API-1)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.capabilities.registry import Caller, Context, Result, capability
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json
from shoc.store import ocsf as layout
from shoc.store.base import QueryResult
from shoc.store.sql import max_params


@dataclass
class EventFilter:
    """Which events to look at. Every filter is optional and combined with AND."""

    since: str = f("-24h", doc="ISO-8601 timestamp or a relative window like -24h")
    until: str = f("", doc="ISO-8601 timestamp; defaults to now")
    actor: str = f("", doc="Exact actor.user.name")
    src_ip: str = f("", doc="Exact src_endpoint.ip")
    api_operation: str = f("", doc="Exact api.operation, e.g. ListBuckets")
    product: str = f("", doc="metadata.product.name, e.g. 'AWS CloudTrail'")
    class_uid: int | None = f(None, doc="OCSF class_uid, e.g. 6003")
    status: str = f("", doc="Success or Failure")
    contains: str = f("", doc="Substring matched against the message and the operation")
    q: str = f(
        "",
        doc=(
            "One-box search. A bare word is matched against the message, the operation, the "
            "actor, the source IP and the resource; "
            "`field=value`, `field!=value`, `field~substring`, `field!~substring` and "
            "`field>=n` (also >, <, <=) narrow it. A field is an OCSF path "
            "(actor.user.name), a column name, or a source path (raw.debugContext.debugData"
            ".dtHash). Quote a value that contains spaces"
        ),
    )


@dataclass
class EventQuery(EventFilter):
    """Search OCSF events and get cited rows back."""

    event_uids: list[str] = f(
        doc="Fetch these exact events (used to resolve citations)", factory=list
    )
    include_raw: bool = f(
        False, doc="Return every column, including the original record in `raw` and `unmapped`"
    )
    limit: int = f(100, doc="Maximum rows, capped at 1000")


@dataclass
class EventPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    truncated: bool = False
    sql: str = ""


def parse_since(value: str, default_hours: int = 24) -> datetime:
    """A relative window (`-24h`) or an ISO-8601 time, always in UTC.

    A time typed without an offset (`2026-10-01T00:00`) is read as UTC, as the
    warehouses read it, rather than in the database server's zone.
    """
    from shoc.detect.rules import parse_timeframe
    from shoc.errors import ConfigError, ValidationError

    text = (value or "").strip()
    now = datetime.now(UTC)
    if not text:
        return now - timedelta(hours=default_hours)
    # A bad window (-1y), one too wide for a date (-99999999999d) and a year-1
    # time pushed past the calendar by its offset are the caller's mistake: 400.
    try:
        if text.startswith("-"):
            return now - timedelta(seconds=parse_timeframe(text[1:]))
        when = datetime.fromisoformat(text)
        return (when if when.tzinfo else when.replace(tzinfo=UTC)).astimezone(UTC)
    except (ConfigError, OverflowError, ValueError) as exc:
        raise ValidationError(
            f"'{text}' is neither an ISO-8601 time nor a window like -24h"
        ) from exc


_SELECT = [
    "event_uid",
    "time",
    "class_name",
    "activity_name",
    "severity_id",
    "status",
    "actor_user_name",
    "actor_session_uid",
    "src_endpoint_ip",
    "api_operation",
    "api_service_name",
    "cloud_account_uid",
    "cloud_region",
    "resource_uid",
    "metadata_product",
    "message",
]


# `field op value`, then anything left over as a bare word. The field name is
# resolved against the OCSF layout, so a typo is rejected rather than ignored,
# and every value travels as a bound parameter.
_TERM = re.compile(
    r"(?P<field>[A-Za-z_][A-Za-z0-9_.@$-]*)\s*(?P<op>!=|>=|<=|!~|[=~<>])\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
    r"|(?P<word>\"[^\"]*\"|'[^']*'|\S+)"
)

_OPS = {
    "=": "=",
    "!=": "<>",
    ">": ">",
    ">=": ">=",
    "<": "<",
    "<=": "<=",
    "~": "LIKE",
    "!~": "NOT LIKE",
}

_BUCKETS = ("minute", "hour", "day")

# What a bare word searches. Someone typing `alice` or `203.0.113.7` means "find
# this anywhere it identifies something", not "find it in the message text".
_FREE_TEXT = ("message", "api_operation", "actor_user_name", "src_endpoint_ip", "resource_uid")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def resolve(field_name: str) -> str:
    """The SQL expression for a field a caller named, or a ValidationError."""
    from shoc.errors import ValidationError

    column = layout.column_for(field_name)
    if column is None:
        raise ValidationError(
            f"unknown field '{field_name}'. Use an OCSF path (actor.user.name), a column "
            "name (actor_user_name), or a source path (raw.debugContext.debugData.dtHash)."
        )
    return column


def _contains(value: str) -> str:
    """A LIKE pattern for `value` anywhere, its own `%`, `_` and `!` escaped.

    Every LIKE here ends `ESCAPE '!'`, as a rule's does (D80): a backslash is
    the default escape on Postgres and Databricks, and a Windows path is full
    of them. `store.sql` rewrites the escapes for BigQuery.
    """
    from shoc.detect.compiler import _literal

    return f"%{_literal(value)}%"


def parse_terms(text: str, params: dict[str, Any]) -> list[str]:
    """Compile a one-box query into SQL predicates, binding every value."""
    where: list[str] = []
    for i, m in enumerate(_TERM.finditer(text or "")):
        key = f"q{i}"
        if m.group("word") is not None:
            params[key] = _contains(_unquote(m.group("word")))
            matches = " OR ".join(
                f"LOWER({column}) LIKE :{key} ESCAPE '!'" for column in _FREE_TEXT
            )
            where.append(f"({matches})")
            continue
        op, value = m.group("op"), _unquote(m.group("value"))
        column = resolve(m.group("field"))
        numeric = column in layout.INT_COLUMNS
        if op in ("~", "!~"):
            params[key] = _contains(value)
            where.append(f"LOWER({column}) {_OPS[op]} :{key} ESCAPE '!'")
        elif numeric or op not in ("=", "!="):
            params[key] = int(value) if numeric and value.lstrip("-").isdigit() else value
            where.append(f"{column} {_OPS[op]} :{key}")
        else:
            params[key] = value.lower()
            where.append(f"LOWER({column}) {_OPS[op]} :{key}")
    return where


def build_where(inp: EventFilter, tenant_id: str) -> tuple[list[str], dict[str, Any]]:
    """The WHERE clause shared by the row query and the aggregate."""
    where = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": tenant_id}
    params["window_start"] = parse_since(inp.since)
    params["window_end"] = (
        parse_since(inp.until) if inp.until else datetime.now(UTC) + timedelta(minutes=1)
    )
    where.append("time >= :window_start AND time < :window_end")
    for value, column in (
        (inp.actor, "actor_user_name"),
        (inp.src_ip, "src_endpoint_ip"),
        (inp.api_operation, "api_operation"),
        (inp.product, "metadata_product"),
        (inp.status, "status"),
    ):
        if value:
            key = f"f_{column}"
            params[key] = value.lower()
            where.append(f"LOWER({column}) = :{key}")
    if inp.class_uid is not None:
        params["class_uid"] = inp.class_uid
        where.append("class_uid = :class_uid")
    if inp.contains:
        params["needle"] = _contains(inp.contains)
        where.append(
            "(LOWER(message) LIKE :needle ESCAPE '!' "
            "OR LOWER(api_operation) LIKE :needle ESCAPE '!')"
        )
    where += parse_terms(inp.q, params)
    return where, params


def build_query(inp: EventQuery, tenant_id: str) -> tuple[str, dict[str, Any], int]:
    limit = max(1, min(int(inp.limit), 1000))
    if inp.event_uids:
        where = ["tenant_id = :tenant_id"]
        params: dict[str, Any] = {"tenant_id": tenant_id}
        placeholders = []
        for i, uid in enumerate(inp.event_uids[:limit]):
            params[f"u{i}"] = uid
            placeholders.append(f":u{i}")
        where.append(f"event_uid IN ({', '.join(placeholders)})")
    else:
        where, params = build_where(inp, tenant_id)
    columns = layout.COLUMN_NAMES if inp.include_raw else _SELECT
    sql = (
        f"SELECT {', '.join(columns)} FROM {layout.EVENTS_TABLE} "
        f"WHERE {' AND '.join(where)} ORDER BY time DESC LIMIT {limit}"
    )
    return sql, params, limit


def by_uid(store: Any, tenant_id: str, uids: list[str], include_raw: bool = False) -> QueryResult:
    """These events, one row each, newest first.

    An alert updated in place keeps its event_uid on every row, so each uid is
    read with room for four rows and keeps its newest. An alert updated more
    often than that can still fill a read, so the uids it pushed out are read
    again on their own: one uid's updates never cost another cited event.
    `truncated` means a cited event is still missing. The uids go in groups one
    statement can bind, since Databricks refuses a 257th value (D250).
    """
    wanted = list(dict.fromkeys(str(u) for u in uids if u))
    size = max(1, min(max_params(getattr(store, "dialect", "")) - 1, 250))
    out = QueryResult()
    seen: dict[str, dict[str, Any]] = {}
    for start in range(0, len(wanted), size):
        pending = wanted[start : start + size]
        while pending:
            sql, params, limit = build_query(
                EventQuery(event_uids=pending, limit=len(pending) * 4, include_raw=include_raw),
                tenant_id,
            )
            result = store.query(sql, params, limit)
            out.sql = out.sql or result.sql
            for row in result.rows:
                seen.setdefault(str(row["event_uid"]), row)
            missing = [u for u in pending if u not in seen]
            if not (result.truncated and missing) or len(missing) == len(pending):
                out.truncated = out.truncated or bool(result.truncated and missing)
                break
            pending = missing
    out.rows = sorted(seen.values(), key=lambda r: r["time"], reverse=True)
    return out


@capability(
    name="events.query",
    summary="Search OCSF events by filter or one-box query, and get cited rows back",
    input=EventQuery,
    output=EventPage,
    scope="events:read",
    tags=("events", "read"),
)
def query(ctx: Context, inp: EventQuery) -> Result:
    if inp.event_uids:
        limit = max(1, min(int(inp.limit), 1000))
        wanted = list(dict.fromkeys(inp.event_uids))[:limit]
        result = by_uid(ctx.store, ctx.tenant_id, wanted, inp.include_raw)
    else:
        sql, params, limit = build_query(inp, ctx.tenant_id)
        result = ctx.store.query(sql, params, limit)
    rows = [to_json(r) for r in result.rows]
    page = EventPage(rows=rows, count=len(rows), truncated=result.truncated, sql=result.sql)
    window = "the requested events" if inp.event_uids else f"since {inp.since or '-24h'}"
    return Result(
        data=page,
        summary=f"{len(rows)} event(s) matched {window}.",
        citations=[str(r["event_uid"]) for r in rows],
    )


@dataclass
class SummarizeInput(EventFilter):
    """Count matching events per group: a histogram over time, or a field's top values."""

    by: str = f(
        "time",
        doc="Group by `time` for a histogram, or by any field — actor.user.name, "
        "metadata_product, raw.<source path>",
    )
    interval: str = f(
        "",
        doc="Bucket width when grouping by time: minute, hour or day. Defaults to fit the window",
    )
    limit: int = f(50, doc="Maximum groups, capped at 500")


@dataclass
class Group:
    key: str = ""
    count: int = 0


@dataclass
class Summary:
    by: str = ""
    interval: str = ""
    rows: list[Group] = field(default_factory=list)
    total: int = 0
    sql: str = ""


def bucket_for(inp: SummarizeInput) -> str:
    """The requested bucket width, or one that gives a readable number of bars."""
    if inp.interval in _BUCKETS:
        return inp.interval
    until = parse_since(inp.until) if inp.until else datetime.now(UTC)
    hours = (until - parse_since(inp.since)).total_seconds() / 3600
    return "minute" if hours <= 3 else "hour" if hours <= 96 else "day"


def build_summary(inp: SummarizeInput, tenant_id: str) -> tuple[str, dict[str, Any], int, str]:
    limit = max(1, min(int(inp.limit), 500))
    where, params = build_where(inp, tenant_id)
    bucket = bucket_for(inp) if inp.by == "time" else ""
    expr = f"DATE_TRUNC('{bucket}', time)" if bucket else resolve(inp.by)
    order = "group_key" if bucket else "n DESC"
    sql = (
        f"SELECT {expr} AS group_key, COUNT(*) AS n FROM {layout.EVENTS_TABLE} "
        f"WHERE {' AND '.join(where)} GROUP BY {expr} ORDER BY {order} LIMIT {limit}"
    )
    return sql, params, limit, bucket


@capability(
    name="events.summarize",
    summary="Count matching events per group: a histogram over time, or a field's top values",
    input=SummarizeInput,
    output=Summary,
    scope="events:read",
    tags=("events", "read"),
)
def summarize(ctx: Context, inp: SummarizeInput) -> Result:
    sql, params, limit, bucket = build_summary(inp, tenant_id=ctx.tenant_id)
    result = ctx.store.query(sql, params, limit)
    rows = [
        Group(key="" if r["group_key"] is None else str(to_json(r["group_key"])), count=int(r["n"]))
        for r in result.rows
    ]
    total = sum(row.count for row in rows)
    return Result(
        data=Summary(by=inp.by, interval=bucket, rows=rows, total=total, sql=result.sql),
        summary=f"{total} event(s) in {len(rows)} group(s) by {bucket or inp.by}.",
    )


@dataclass
class IngestInput:
    """Push raw source records in; they are mapped to OCSF and stored."""

    source: str = f(doc="Connector/mapping name, e.g. aws_cloudtrail, okta, github")
    records: list[dict[str, Any]] = f(
        doc="Raw source records, exactly as the API returns them", factory=list
    )
    spool: bool = f(
        False,
        doc="Keep the records in Postgres for the worker to load with the next detection "
        "cycle, as GitHub's push is kept on a warehouse. Only GitHub's signed webhook may "
        "set it",
    )


@dataclass
class IngestResult:
    source: str = ""
    received: int = 0
    loaded: int = 0
    duration_ms: int = 0
    spooled: int = 0


@capability(
    name="events.ingest",
    summary="Map raw source records to OCSF and load them",
    input=IngestInput,
    output=IngestResult,
    scope="events:write",
    # Loading is a write, and agents read through SHOC_READONLY_DSN (D22).
    principals=("human", "service"),
    audit=True,
    tags=("events", "ingest"),
)
def ingest(ctx: Context, inp: IngestInput) -> Result:
    from shoc.errors import ValidationError
    from shoc.ingest import batch as batchwriter
    from shoc.ingest import ocsf as mapper

    cap = getattr(ctx.config, "max_ingest_records", 50_000)
    if len(inp.records) > cap:
        raise ValidationError(
            f"{len(inp.records)} records in one call; the limit is {cap}. "
            "Send several batches, or raise SHOC_MAX_INGEST_RECORDS."
        )
    from shoc.ingest.connectors.base import connector_of

    if inp.spool:
        # Kept records load as GitHub's own push, its history and its health:
        # only the webhook keeps them, never a token that holds events:write.
        if not _pushed(ctx) or connector_of(inp.source) != "github":
            from shoc.errors import Denied

            raise Denied("only GitHub's signed webhook keeps records for the cycle")
        return _spool(ctx, inp)

    mapping = mapper.for_tenant(ctx.db, ctx.tenant_id, connector_of(inp.source))
    rows = [row for r in inp.records for row in mapping.map_records(r, ctx.tenant_id)]
    stats = batchwriter.load(ctx.store, rows)
    if stats.rows:
        # Rows all stored before wake nothing: stamped as a load, a redelivery
        # woke every rule over their products for no new event (D71).
        batchwriter.loaded(ctx.db, ctx.tenant_id, rows)
    if rows and _pushed(ctx):
        # A vendor's own push is the source's history; records loaded by
        # hand (a replay, a test) are not (RFC 0022).
        from shoc.ingest.connectors.base import history

        history(ctx.db, ctx.tenant_id, inp.source, rows)
    return Result(
        data=IngestResult(
            source=inp.source,
            received=len(inp.records),
            loaded=stats.rows,
            duration_ms=stats.duration_ms,
        ),
        summary=f"Loaded {stats.rows} of {len(inp.records)} {inp.source} record(s).",
        citations=[r["event_uid"] for r in rows[:20]],
    )


# Who loads a vendor's push: GitHub's webhook as it arrives, or the worker
# loading what the webhook kept. Its own push is the source's history (RFC 0022).
GITHUB_WEBHOOK = Caller(kind="service", id="github-webhook", scopes=("events:write",))
# Kept deliveries read per pass; a GitHub delivery is one record.
SPOOL_BATCH = 500
# A kept delivery that failed this many loads is tried once a day after, and
# shows on its source's health until it loads or the retention prunes it.
SPOOL_TRIES = 5
# How that source error starts, so a flush clears only its own.
SPOOL_ERROR = "pushed deliveries not loaded"


def _pushed(ctx: Context) -> bool:
    """Whether GitHub's webhook, or the worker loading what it kept, is calling.

    The object itself, not its id: a token can be given any name.
    """
    return ctx.caller is GITHUB_WEBHOOK


def _spool(ctx: Context, inp: IngestInput) -> Result:
    """Keep a push in Postgres for the next cycle's load (ING-2, STO-3).

    On a warehouse each delivery was a load of its own and woke detection a
    minute later, so the warehouse never idled, and a load that failed lost
    the event: GitHub does not redeliver on its own.
    """
    import json

    from shoc.db.pool import execute

    if inp.records:
        execute(
            ctx.db,
            "INSERT INTO shoc.push_spool (tenant_id, source, records) VALUES (%s, %s, %s)",
            (ctx.tenant_id, inp.source, json.dumps(inp.records, default=str)),
        )
    n = len(inp.records)
    return Result(
        data=IngestResult(source=inp.source, received=n, spooled=n),
        summary=f"Kept {n} {inp.source} record(s) to load with the next detection cycle.",
    )


def flush_spool(ctx: Context) -> tuple[int, int]:
    """Load what `_spool` kept, oldest first: the rows loaded and the deliveries that failed.

    The worker calls it as the cycle's detection run starts, which then reads
    what it loaded. One flush per tenant at a time: two detection runs loading
    the same delivery store its events twice on a warehouse that enforces no
    key. A kept delivery goes once its load succeeded; one that failed is tried
    again the next cycle, alone.
    """
    from shoc.db.pool import execute, fetch_all, fetch_one

    lock = "hashtext('shoc.push_spool'), hashtext(%s)"
    got = fetch_one(ctx.db, f"SELECT pg_try_advisory_lock({lock}) AS got", (ctx.tenant_id,))
    if not (got and got["got"]):
        return 0, 0  # another detection run of this tenant is loading them
    push = Context(tenant_id=ctx.tenant_id, caller=GITHUB_WEBHOOK, config=ctx.config, _db=ctx.db)
    loaded = failed = 0
    try:
        sources = fetch_all(
            ctx.db,
            """SELECT source FROM shoc.push_spool WHERE tenant_id = %s
               UNION SELECT source FROM shoc.connector_state
               WHERE tenant_id = %s AND last_error LIKE %s""",
            (ctx.tenant_id, ctx.tenant_id, f"{SPOOL_ERROR}%"),
        )
        for row in sources:
            n, bad = _flush_source(ctx, push, row["source"])
            loaded, failed = loaded + n, failed + bad
            _report_parked(ctx, row["source"])
    finally:
        push.close()
        execute(ctx.db, f"SELECT pg_advisory_unlock({lock})", (ctx.tenant_id,))
    return loaded, failed


def _flush_source(ctx: Context, push: Context, source: str) -> tuple[int, int]:
    """One source's kept deliveries: new ones load together, as many as the
    ingest limit takes; one that failed before loads alone, after them, so a
    bad delivery holds no other back."""
    from shoc.db.pool import fetch_all

    most = max(1, int(getattr(ctx.config, "max_ingest_records", 50_000)))
    loaded = failed = after = 0
    alive = False  # something of this source loaded in this flush

    def attempt(rows: list[dict[str, Any]]) -> bool:
        """Load these; False when a failure points at the store, not a delivery."""
        nonlocal loaded, failed, alive
        try:
            loaded += _load_kept(ctx, push, source, rows)
        except Exception as exc:
            if len(rows) > 1:
                return all(attempt([row]) for row in rows)
            _failed(ctx, rows[0], exc)
            failed += 1
            # Nothing loaded yet: the store is likely down, and trying the rest
            # one by one would cost a statement each for nothing.
            return alive
        alive = True
        return True

    while rows := fetch_all(
        ctx.db,
        """SELECT spool_id, records, attempts FROM shoc.push_spool
           WHERE tenant_id = %s AND source = %s AND spool_id > %s
             AND (attempts < %s OR tried_at < now() - interval '1 day')
           ORDER BY spool_id LIMIT %s""",
        (ctx.tenant_id, source, after, SPOOL_TRIES, SPOOL_BATCH),
    ):
        after = rows[-1]["spool_id"]
        groups: list[list[dict[str, Any]]] = []
        size = most
        for row in rows:
            if row["attempts"]:
                continue
            if size + len(row["records"]) > most:
                groups.append([])
                size = 0
            groups[-1].append(row)
            size += len(row["records"])
        groups += [[row] for row in rows if row["attempts"]]
        if not all(attempt(group) for group in groups):
            break
    return loaded, failed


def _load_kept(ctx: Context, push: Context, source: str, rows: list[dict[str, Any]]) -> int:
    from shoc.capabilities.registry import call
    from shoc.db.pool import execute
    from shoc.ingest.connectors.base import mark_push

    records = [record for row in rows for record in row["records"]]
    result = call("events.ingest", push, {"source": source, "records": records})
    execute(
        ctx.db,
        "DELETE FROM shoc.push_spool WHERE tenant_id = %s AND spool_id = ANY(%s)",
        (ctx.tenant_id, [row["spool_id"] for row in rows]),
    )
    mark_push(ctx.db, ctx.tenant_id, source, result.data.loaded)
    return result.data.loaded


def _failed(ctx: Context, row: dict[str, Any], exc: Exception) -> None:
    from shoc.db.pool import execute

    execute(
        ctx.db,
        """UPDATE shoc.push_spool
           SET attempts = attempts + 1, tried_at = now(), last_error = %s
           WHERE tenant_id = %s AND spool_id = %s""",
        (f"{type(exc).__name__}: {exc}"[:500], ctx.tenant_id, row["spool_id"]),
    )


def _report_parked(ctx: Context, source: str) -> None:
    """Put deliveries that keep failing on the source's error, which Ops raises
    as source.failing; clear it once none are left. A poll's own error stays."""
    from shoc.db.pool import execute, fetch_one

    row = fetch_one(
        ctx.db,
        """SELECT count(*) AS n, (array_agg(last_error ORDER BY tried_at DESC))[1] AS error
           FROM shoc.push_spool
           WHERE tenant_id = %s AND source = %s AND attempts >= %s""",
        (ctx.tenant_id, source, SPOOL_TRIES),
    )
    ours = "last_error LIKE %s"
    if row and row["n"]:
        error = (
            f"{SPOOL_ERROR}: {row['n']} kept delivery(ies) failed {SPOOL_TRIES} loads "
            f"and are tried daily; last: {row['error']}"
        )
        params: tuple[Any, ...] = (error, ctx.tenant_id, source, f"{SPOOL_ERROR}%")
        ours = f"(last_error IS NULL OR {ours})"
    else:
        params = (None, ctx.tenant_id, source, f"{SPOOL_ERROR}%")
    execute(
        ctx.db,
        f"""UPDATE shoc.connector_state SET last_error = %s
            WHERE tenant_id = %s AND source = %s AND {ours}""",
        params,
    )


@dataclass
class RetainInput:
    days: int = f(
        0,
        doc="Keep this many days of events, at least the configured retention (0 = the "
        "configured retention). Postgres drops whole months older than that; a warehouse "
        "deletes the older rows",
    )


@dataclass
class Retained:
    dropped: int = 0
    unit: str = ""


def retention_days(ctx: Context) -> int:
    """The retention this tenant keeps: what `config.apply` set (D94), else SHOC_RETENTION_DAYS."""
    from shoc.db.pool import fetch_one

    row = fetch_one(
        ctx.db,
        "SELECT payload FROM shoc.schedules WHERE schedule_id = %s AND tenant_id = %s",
        (f"{ctx.tenant_id}:retention", ctx.tenant_id),
    )
    days = (row or {}).get("payload", {}).get("days")
    return int(days if days is not None else getattr(ctx.config, "retention_days", 90))


@capability(
    name="events.retain",
    summary="Delete the events older than the retention window, never fewer days than configured",
    input=RetainInput,
    output=Retained,
    scope="events:retain",
    # Dropping a partition needs the writer's credential, which agents never hold (D22).
    principals=("human", "service"),
    audit=True,
    tags=("events", "write"),
)
def retain(ctx: Context, inp: RetainInput) -> Result:
    from shoc.errors import ValidationError
    from shoc.store.base import RetentionPolicy

    # What is deleted cannot come back: keeping less than the configured
    # retention is a change to it, made through config.apply, which a person
    # confirms (D94), never one call that an assistant can be steered into.
    kept = retention_days(ctx)
    days = inp.days or kept
    if days < kept:
        raise ValidationError(
            f"events.retain keeps at least the configured {kept} day(s); "
            "lower retention_days through config.apply first"
        )
    dropped = ctx.store.apply_retention(RetentionPolicy(days=max(1, days)))
    # Postgres drops monthly partitions; a warehouse deletes rows (STO-6).
    unit = "partition(s)" if ctx.store.dialect == "postgres" else "row(s)"
    return Result(
        data=Retained(dropped=dropped, unit=unit),
        summary=f"retention: removed {dropped} {unit} older than {days} day(s)",
    )
