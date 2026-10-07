"""Posture: what the company has, what is exposed, what nothing is watching.

The Surveyor's capabilities (AGT-3, RFC 0006 §3). Every answer is derived from
ingested events and the snapshots connectors take (D49), and carries the caveat
that says what it cannot see, so no other agent reads silence as absence.

Nothing in this module writes outside `shoc.exposures` and
`shoc.posture_snapshots`, and nothing in it uses a model: inventory and exposure
are joins, and the one answer that must be identical every time it is asked has
no business varying. The Surveyor's model reads the result afterwards (D47).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.agents import surveyor
from shoc.capabilities.registry import Context, Result, capability
from shoc.errors import Denied
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class PostureInput:
    days: int = f(surveyor.WINDOW_DAYS, doc="How far back to read events")
    refresh: bool = f(
        False,
        doc="Re-read the events and keep the new survey (needs posture:write). "
        "False answers from the last survey",
    )


@dataclass
class PostureOut:
    window_days: int = 0
    taken_at: Any = None
    counts: dict[str, int] = field(default_factory=dict)
    exposed: list[dict[str, Any]] = field(default_factory=list)
    privileged: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    unwatched: dict[str, Any] = field(default_factory=dict)
    caveat: str = ""
    truncated: bool = False
    limit: int = 0
    # What the Surveyor's model made of the last scheduled survey, when one ran.
    reading: str = ""


@capability(
    name="posture.get",
    summary="What this company has, what is exposed, and what nothing is watching",
    input=PostureInput,
    output=PostureOut,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def get(ctx: Context, inp: PostureInput) -> Result:
    # A read by default (AGT-10): keeping a survey is a write, asked for by name.
    if inp.refresh and not ctx.caller.allows("posture:write"):
        raise Denied("posture.get: refresh keeps a new survey and needs scope 'posture:write'")
    if inp.refresh:
        posture = surveyor.survey(ctx.db, ctx.store, ctx.tenant_id, max(1, inp.days), ctx.config)
        data = PostureOut(**posture.to_json())
        citations = posture.citations
    else:
        snapshot = surveyor.latest(ctx.db, ctx.tenant_id)
        if snapshot is None:
            # Never surveyed: answer from the events, and keep nothing.
            posture = surveyor.survey(
                ctx.db, ctx.store, ctx.tenant_id, max(1, inp.days), ctx.config, keep=False
            )
            data, citations = PostureOut(**posture.to_json()), posture.citations
        else:
            gaps = snapshot.get("gaps") or {}
            data = PostureOut(
                window_days=int(snapshot["window_days"]),
                taken_at=snapshot["taken_at"],
                counts=snapshot.get("counts") or {},
                unwatched=gaps.get("unwatched") or {},
                caveat=str(snapshot.get("caveat") or surveyor.CAVEAT),
                truncated=bool(gaps.get("truncated")),
                limit=int(gaps.get("limit") or 0),
                reading=str(gaps.get("reading") or ""),
            )
            citations = []

    counts = data.counts
    blind = (data.unwatched or {}).get("products_with_no_rule") or []
    return Result(
        data=data,
        summary=(
            f"{counts.get('total', 0)} entity(ies) seen in {data.window_days} day(s): "
            f"{counts.get('exposed', 0)} used from outside our own ranges, "
            f"{counts.get('privileged', 0)} with administrative operations, "
            f"{counts.get('stale', 0)} stale."
            + (f" {len(blind)} product(s) arrive with no rule looking at them." if blind else "")
            + (
                f" The window held more than {data.limit} events; this covers the newest "
                f"{data.limit}."
                if data.truncated
                else ""
            )
            + f" {data.caveat}"
        ),
        citations=citations[:100],
    )


@dataclass
class ExposureInput:
    entity: str = f(doc="An entity like user:alice, key:AKIA… or just the value")


@dataclass
class ExposureOut:
    entity: str = ""
    known: bool = False
    answer: str = ""
    kind: str = ""
    exposed: bool = False
    privileged: bool = False
    stale: bool = False
    events: int = 0
    sources: list[str] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    caveat: str = ""
    # False when the latest survey did not see it; the flags are then today's.
    present: bool = False


@capability(
    name="posture.exposure",
    summary="Is this identity, key or host privileged, exposed or stale?",
    input=ExposureInput,
    output=ExposureOut,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def exposure(ctx: Context, inp: ExposureInput) -> Result:
    row = surveyor.exposure_of(ctx.db, ctx.tenant_id, inp.entity.strip())
    data = ExposureOut(
        entity=str(row.get("entity") or inp.entity),
        known=bool(row.get("known")),
        answer=str(row.get("answer") or ""),
        kind=str(row.get("kind") or ""),
        exposed=bool(row.get("exposed")),
        privileged=bool(row.get("privileged")),
        stale=bool(row.get("stale")),
        events=int(row.get("events") or 0),
        sources=[str(s) for s in (row.get("sources") or [])],
        countries=[str(c) for c in (row.get("countries") or [])],
        operations=[str(o) for o in (row.get("operations") or [])],
        caveat=str(row.get("caveat") or surveyor.CAVEAT),
        present=bool(row.get("present")),
    )
    return Result(
        data=data,
        summary=data.answer,
        citations=[str(u) for u in (row.get("event_uids") or [])][:20],
    )


@dataclass
class SurfaceInput:
    kind: str = f("", doc="Limit to one entity kind: user, key, ip, resource or account")
    exposed_only: bool = f(True, doc="Only what has been used from outside our own ranges")
    limit: int = f(100, doc="How many rows to return")


@dataclass
class SurfaceOut:
    entities: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    caveat: str = ""


@capability(
    name="surface.list",
    summary="The attack surface as the events describe it",
    input=SurfaceInput,
    output=SurfaceOut,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def surface(ctx: Context, inp: SurfaceInput) -> Result:
    rows = surveyor.surface(
        ctx.db, ctx.tenant_id, inp.kind, inp.exposed_only, max(1, min(inp.limit, 500))
    )
    return Result(
        data=SurfaceOut(
            entities=[to_json(r) for r in rows], count=len(rows), caveat=surveyor.CAVEAT
        ),
        summary=(
            f"{len(rows)} entity(ies)"
            + (f" of kind {inp.kind}" if inp.kind else "")
            + (" reachable from outside our own ranges" if inp.exposed_only else "")
            + ". "
            + surveyor.CAVEAT
        ),
        citations=[str(u) for r in rows for u in (r.get("event_uids") or [])][:100],
    )


@dataclass
class IdentifyInput:
    target: str = f(doc="An address, host or identity, typed (ip:…, user:…) or bare")
    days: int = f(30, doc="How far back to look at behaviour")


@dataclass
class AssetIdentity:
    target: str = ""
    is_ours: bool = False
    what_it_is: str = "unknown"
    source: str = "unknown"
    principals: int = -1
    statements: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="asset.identify",
    summary="What an address, host or identity is to this company: declared, listed or observed",
    input=IdentifyInput,
    output=AssetIdentity,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def identify(ctx: Context, inp: IdentifyInput) -> Result:
    answer = surveyor.identify(
        ctx.db, ctx.store, ctx.tenant_id, inp.target, ctx.config, max(1, min(inp.days, 90))
    )
    citations = answer.pop("citations")
    data = AssetIdentity(**answer)
    return Result(
        data=data,
        summary=(
            f"{data.target}: {data.what_it_is} ({data.source})"
            + (", ours" if data.is_ours else "")
            + (f"; {data.principals} principal(s) acted from it" if data.principals >= 0 else "")
            + "."
            + (
                ""
                if data.statements
                else " Nobody declared it, no source lists it and no event shows it: unknown."
            )
        ),
        citations=citations,
    )


@dataclass
class ResolveInput:
    identity: str = f(doc="A user or a key, typed (user:…, key:…) or bare")


@dataclass
class ResolvedIdentity:
    identity: str = ""
    nodes: list[str] = field(default_factory=list)
    linked: list[dict[str, Any]] = field(default_factory=list)
    listed: list[dict[str, Any]] = field(default_factory=list)
    registry: list[dict[str, Any]] = field(default_factory=list)
    declared: list[dict[str, Any]] = field(default_factory=list)
    unbridged: bool = True
    # The identity-provider login it signs in as: one entry is the login an
    # identity action acts on for it, two or more answer nothing (RFC 0027).
    logins: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="identity.resolve",
    summary="The same actor under its other names: its keys, its users, what sources list for it",
    input=ResolveInput,
    output=ResolvedIdentity,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def resolve(ctx: Context, inp: ResolveInput) -> Result:
    answer = surveyor.resolve(ctx.db, ctx.tenant_id, inp.identity.strip())
    data = ResolvedIdentity(**{k: to_json(v) for k, v in answer.items()})
    names = [str(r["entity"]) for r in data.linked]
    if not inp.identity.strip().startswith("key:"):
        data.logins = surveyor.logins(ctx.store, ctx.tenant_id, inp.identity)["logins"]
        data.unbridged = data.unbridged and len(data.logins) != 1
    said = [f"is linked to {', '.join(names[:5])}"] if names else []
    if len(data.logins) == 1:
        said.append(f"signs in as {data.logins[0]['login']} ({data.logins[0]['via']})")
    elif data.logins:
        said.append(
            f"signs in as {' or '.join(li['login'] for li in data.logins[:5])}: no single login"
        )
    return Result(
        data=data,
        summary=(
            f"{data.identity} {'; '.join(said)}"
            if said
            else f"Nothing links {data.identity} to another name in events"
        )
        + (
            f"; listed by {', '.join(sorted({str(r['source']) for r in data.listed}))}"
            if data.listed
            else ""
        )
        + (
            ". Unbridged: treat any other name as a different actor until something links them."
            if data.unbridged
            else "."
        ),
        citations=[*data.nodes, *names, *(u for li in data.logins for u in li["event_uids"])],
    )


@dataclass
class SnapshotInput:
    source: str = f("", doc="One source, or empty for all")
    kind: str = f("", doc="user or network; empty for all")
    limit: int = f(200, doc="Maximum rows, capped at 1000")


@dataclass
class SnapshotPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    truncated: bool = False


@capability(
    name="snapshot.list",
    summary="What each source's own API says exists, whether or not it ever acted (D49)",
    input=SnapshotInput,
    output=SnapshotPage,
    scope="posture:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("posture", "read"),
)
def snapshots(ctx: Context, inp: SnapshotInput) -> Result:
    from shoc.db.pool import fetch_all

    limit = max(1, min(int(inp.limit), 1000))
    rows = fetch_all(
        ctx.db,
        """SELECT source, entity, kind, attributes, last_active, taken_at FROM shoc.snapshots
           WHERE tenant_id = %s AND (%s = '' OR source = %s) AND (%s = '' OR kind = %s)
           ORDER BY source, kind, entity LIMIT %s""",
        (ctx.tenant_id, inp.source, inp.source, inp.kind, inp.kind, limit + 1),
    )
    sources = sorted({str(r["source"]) for r in rows})
    return Result(
        data=SnapshotPage(
            rows=[to_json(r) for r in rows[:limit]],
            count=min(len(rows), limit),
            truncated=len(rows) > limit,
        ),
        summary=(
            f"{min(len(rows), limit)} listed asset(s) from {', '.join(sources)}"
            + (f", cut at {limit}" if len(rows) > limit else "")
            + "."
            if rows
            else "No snapshot has been taken: no configured source lists what exists, so only "
            "what acted is known."
        ),
        citations=[f"snapshot:{r['source']}:{r['entity']}" for r in rows[:limit]][:100],
    )
