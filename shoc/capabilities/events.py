"""Event capabilities: typed search over the OCSF store, and ingest (API-1)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json
from shoc.store import ocsf as layout


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
    text = (value or "").strip()
    now = datetime.now(UTC)
    if not text:
        return now - timedelta(hours=default_hours)
    if text.startswith("-"):
        from shoc.detect.rules import parse_timeframe

        return now - timedelta(seconds=parse_timeframe(text[1:]))
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


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


def parse_terms(text: str, params: dict[str, Any]) -> list[str]:
    """Compile a one-box query into SQL predicates, binding every value."""
    where: list[str] = []
    for i, m in enumerate(_TERM.finditer(text or "")):
        key = f"q{i}"
        if m.group("word") is not None:
            params[key] = f"%{_unquote(m.group('word')).lower()}%"
            matches = " OR ".join(f"LOWER({column}) LIKE :{key}" for column in _FREE_TEXT)
            where.append(f"({matches})")
            continue
        op, value = m.group("op"), _unquote(m.group("value"))
        column = resolve(m.group("field"))
        numeric = column in layout.INT_COLUMNS
        if op in ("~", "!~"):
            params[key] = f"%{value.lower()}%"
            where.append(f"LOWER({column}) {_OPS[op]} :{key}")
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
        params["needle"] = f"%{inp.contains.lower()}%"
        where.append("(LOWER(message) LIKE :needle OR LOWER(api_operation) LIKE :needle)")
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


@capability(
    name="events.query",
    summary="Search OCSF events by filter or one-box query, and get cited rows back",
    input=EventQuery,
    output=EventPage,
    scope="events:read",
    tags=("events", "read"),
)
def query(ctx: Context, inp: EventQuery) -> Result:
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


@dataclass
class IngestResult:
    source: str = ""
    received: int = 0
    loaded: int = 0
    duration_ms: int = 0


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

    mapping = mapper.for_tenant(ctx.db, ctx.tenant_id, connector_of(inp.source))
    rows = [mapping.map_record(r, ctx.tenant_id) for r in inp.records]
    stats = batchwriter.load(ctx.store, rows)
    if rows:
        batchwriter.loaded(ctx.db, ctx.tenant_id, rows)
        if ctx.caller.id.endswith("-webhook"):
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


@dataclass
class RetainInput:
    days: int = f(90, doc="Keep this many days of events; older whole months are dropped")


@dataclass
class Retained:
    dropped: int = 0


@capability(
    name="events.retain",
    summary="Drop the event partitions older than the retention window",
    input=RetainInput,
    output=Retained,
    scope="events:retain",
    # Dropping a partition needs the writer's credential, which agents never hold (D22).
    principals=("human", "service"),
    audit=True,
    tags=("events", "write"),
)
def retain(ctx: Context, inp: RetainInput) -> Result:
    from shoc.store.base import RetentionPolicy

    dropped = ctx.store.apply_retention(RetentionPolicy(days=max(1, inp.days)))
    return Result(
        data=Retained(dropped=dropped),
        summary=f"retention: dropped {dropped} partition(s) older than {inp.days} day(s)",
    )
