"""The case's timeline and its history: the Investigator's first reads (AGT-13, RFC 0012).

An investigation starts in the source that alerted and extends outward on two
pivots, a resolved identity and an indicator. `timeline.build` is the first
step and `timeline.extend` the second; both return events oldest first, because
a timeline read backwards is a list. `case.history` is what earlier cases on the
same entities concluded, for the Investigator and the Challenger.

All three are reads over the event store and the case tables, in canonical SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from shoc.capabilities.events import _SELECT
from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import fetch_all
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json
from shoc.store import ocsf as layout

# How far either side of the case's own events a timeline reaches by default.
MARGIN_HOURS = 1
MAX_ROWS = 500
# The entity kinds a timeline pivots on, and the column each lives in. An
# account id is left out: every event in the account carries it, so it links
# everything to everything.
PIVOTS = {
    "user": "actor_user_name",
    "key": "actor_session_uid",
    "ip": "src_endpoint_ip",
    "resource": "resource_uid",
    "host": "device_hostname",
}


@dataclass
class Timeline:
    case_uid: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    # True when more events matched than `limit`: the timeline then stops at
    # the `limit` oldest, and the caller should narrow the window.
    truncated: bool = False
    limit: int = 0
    window_start: str = ""
    window_end: str = ""
    products: list[str] = field(default_factory=list)


def _cited(ctx: Context, case_uid: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The case's cited events and its typed entities."""
    from shoc.agents.dossier import _events, findings
    from shoc.cases import engine

    case = engine.require(ctx.db, ctx.tenant_id, case_uid)
    uids = [u for row in findings(ctx.db, ctx.tenant_id, case) for u in row["event_uids"] or []]
    entities = [
        str(r["entity"])
        for r in fetch_all(
            ctx.db,
            "SELECT entity FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
            (ctx.tenant_id, case_uid),
        )
    ]
    return _events(ctx.store, ctx.tenant_id, uids), entities


def _read(
    ctx: Context,
    case_uid: str,
    where: list[str],
    params: dict[str, Any],
    start: Any,
    end: Any,
    limit: int,
    cited: set[str],
    products: list[str],
) -> Result:
    limit = max(1, min(int(limit), MAX_ROWS))
    params = {**params, "tenant_id": ctx.tenant_id, "start": start, "end": end}
    sql = (
        f"SELECT {', '.join(_SELECT)} FROM {layout.EVENTS_TABLE} "
        f"WHERE tenant_id = :tenant_id AND time >= :start AND time <= :end AND {' AND '.join(where)} "
        "ORDER BY time ASC"
    )
    result = ctx.store.query(sql, params, limit)
    rows = [{**to_json(r), "cited": str(r["event_uid"]) in cited} for r in result.rows]
    data = Timeline(
        case_uid=case_uid,
        events=rows,
        count=len(rows),
        truncated=result.truncated,
        limit=limit,
        window_start=start.isoformat(),
        window_end=end.isoformat(),
        products=products,
    )
    return Result(
        data=data,
        summary=(
            f"{len(rows)} event(s) from {start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"
            + (f" in {', '.join(products)}" if products else "")
            + (
                f", cut at the {limit} oldest; narrow the window to see the rest"
                if result.truncated
                else ""
            )
            + "."
        ),
        citations=[str(r["event_uid"]) for r in rows],
    )


def _match(entities: list[str], params: dict[str, Any]) -> list[str]:
    """`column IN (...)` per pivot kind, ORed, every value bound."""
    terms: list[str] = []
    for kind, column in PIVOTS.items():
        values = [e.split(":", 1)[1] for e in entities if e.startswith(f"{kind}:")]
        if not values:
            continue
        names = []
        for value in values[:50]:
            key = f"p{len(params)}"
            params[key] = value
            names.append(f":{key}")
        terms.append(f"{column} IN ({', '.join(names)})")
    return terms


@dataclass
class BuildInput:
    case_uid: str = f(doc="The case")
    margin_hours: int = f(MARGIN_HOURS, doc="How far either side of the case's events to read")
    limit: int = f(200, doc="Maximum events, capped at 500")


@capability(
    name="timeline.build",
    summary="The case's timeline in the source that alerted: its entities' events, oldest first",
    input=BuildInput,
    output=Timeline,
    scope="cases:read",
    tags=("cases", "read"),
)
def build(ctx: Context, inp: BuildInput) -> Result:
    events, entities = _cited(ctx, inp.case_uid)
    if not events:
        return Result(
            data=Timeline(case_uid=inp.case_uid),
            summary=f"{inp.case_uid} cites no event the store still holds.",
        )
    margin = timedelta(hours=max(0, min(int(inp.margin_hours), 72)))
    times = [r["time"] for r in events]
    products = sorted({str(r["metadata_product"]) for r in events if r.get("metadata_product")})
    params: dict[str, Any] = {}
    pivots = _match(entities, params)
    cited = {str(r["event_uid"]) for r in events}
    where = []
    if products:
        names = []
        for product in products:
            params[f"m{len(params)}"] = product
            names.append(f":m{len(params) - 1}")
        where.append(f"metadata_product IN ({', '.join(names)})")
    # The cited events always belong; so does whatever shares an entity with them.
    for uid in sorted(cited):
        params[f"u{len(params)}"] = uid
    marks = [f":{k}" for k in params if k.startswith("u")]
    where.append("(" + " OR ".join([*pivots, f"event_uid IN ({', '.join(marks)})"]) + ")")
    return _read(
        ctx,
        inp.case_uid,
        where,
        params,
        min(times) - margin,
        max(times) + margin,
        inp.limit,
        cited,
        products,
    )


@dataclass
class ExtendInput:
    case_uid: str = f(doc="The case")
    value: str = f(
        doc="An identity or an indicator: user:…, key:…, ip:…, resource:…, host:…, or a bare "
        "value matched against all of them"
    )
    hours: int = f(24, doc="How far either side of the case's events to read")
    limit: int = f(200, doc="Maximum events, capped at 500")


@capability(
    name="timeline.extend",
    summary="Extend a case's timeline on one identity or indicator, in every source",
    input=ExtendInput,
    output=Timeline,
    scope="cases:read",
    tags=("cases", "read"),
)
def extend(ctx: Context, inp: ExtendInput) -> Result:
    from shoc.errors import ValidationError

    value = inp.value.strip()
    if not value:
        raise ValidationError("value is required: an identity or an indicator")
    events, _entities = _cited(ctx, inp.case_uid)
    if not events:
        return Result(
            data=Timeline(case_uid=inp.case_uid),
            summary=f"{inp.case_uid} cites no event the store still holds.",
        )
    margin = timedelta(hours=max(1, min(int(inp.hours), 24 * 30)))
    times = [r["time"] for r in events]
    kind, _, bare = value.partition(":")
    params: dict[str, Any] = {"v": bare if kind in PIVOTS and bare else value}
    columns = [PIVOTS[kind]] if kind in PIVOTS and bare else list(PIVOTS.values())
    where = ["(" + " OR ".join(f"{c} = :v" for c in columns) + ")"]
    cited = {str(r["event_uid"]) for r in events}
    return _read(
        ctx,
        inp.case_uid,
        where,
        params,
        min(times) - margin,
        max(times) + margin,
        inp.limit,
        cited,
        [],
    )


@dataclass
class HistoryInput:
    case_uid: str = f(doc="The case whose entities to look back on")
    limit: int = f(20, doc="Maximum cases")


@dataclass
class History:
    case_uid: str = ""
    cases: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="case.history",
    summary="Earlier cases on the same entities, and how each one ended",
    input=HistoryInput,
    output=History,
    scope="cases:read",
    tags=("cases", "read"),
)
def history(ctx: Context, inp: HistoryInput) -> Result:
    from shoc.cases import engine

    engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    rows = fetch_all(
        ctx.db,
        """SELECT c.case_uid, c.title, c.severity, c.state, c.verdict, c.closed_by,
                  c.disposition_reason, c.opened_at, c.closed_at,
                  array_agg(DISTINCT e.entity ORDER BY e.entity) AS shared
           FROM shoc.case_entities mine
           JOIN shoc.case_entities e
             ON e.tenant_id = mine.tenant_id AND e.entity = mine.entity
            AND e.case_uid <> mine.case_uid
           JOIN shoc.cases c ON c.tenant_id = e.tenant_id AND c.case_uid = e.case_uid
           WHERE mine.tenant_id = %s AND mine.case_uid = %s
             AND mine.entity NOT LIKE 'account:%%'
           GROUP BY c.case_uid, c.title, c.severity, c.state, c.verdict, c.closed_by,
                    c.disposition_reason, c.opened_at, c.closed_at
           ORDER BY c.opened_at DESC LIMIT %s""",
        (ctx.tenant_id, inp.case_uid, max(1, min(int(inp.limit), 100))),
    )
    ended: dict[str, int] = {}
    for row in rows:
        ended[str(row["verdict"])] = ended.get(str(row["verdict"]), 0) + 1
    return Result(
        data=History(case_uid=inp.case_uid, cases=[to_json(r) for r in rows], count=len(rows)),
        summary=(
            f"{len(rows)} earlier case(s) share an entity with {inp.case_uid}"
            + (": " + ", ".join(f"{n} {v}" for v, n in sorted(ended.items())) if rows else "")
            + ". What the crew concluded is a reading; a person's close is a decision."
        ),
        citations=[str(r["case_uid"]) for r in rows],
    )
