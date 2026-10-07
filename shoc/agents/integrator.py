"""The Integrator: one source at a time, until it has produced a finding (AGT-13, D50, D74).

Every step of a source's onboarding is checkable, and is plain code:

- `sample` reads one page from a configured source and maps it, writing
  nothing, so a wrong credential or a changed vendor shape shows up before any
  detection depends on it;
- `coverage` says which rules the source can carry, from the fields its events
  actually fill;
- `proof` finds the finding one of its events became. That, and only that,
  makes a source onboarded.

`work` is the daily turn, built from those three and the permission tables in
`shoc.ingest.connectors.base`.

One step needs judgement: when a vendor moves a field, matching the new path to
the column it used to fill. `repair` asks a model for that, once per change of
shape, and `check_patch` accepts the answer only if the same recent events fill
more with it and nothing fills less.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.agents import ops
from shoc.db.pool import Conn, execute, fetch_all
from shoc.jsonschema import field as f

SAMPLE_LIMIT = 20
# Recent events a mapping patch is measured against, and how many of them the
# model is shown.
REPAIR_EVENTS = 100
REPAIR_SHOWN = 5
# Columns a patch may never set: they identify the row or hold the evidence.
FIXED = frozenset(
    {
        "tenant_id",
        "event_uid",
        "raw",
        "unmapped",
        "observables",
        "ingested_at",
        "metadata_product",
        "metadata_version",
    }
)
# Columns shown from each sampled row. The whole row is too much to quote, and
# these are the ones a reader checks a mapping against.
SHOWN = (
    "event_uid",
    "time",
    "class_name",
    "activity_name",
    "actor_user_name",
    "src_endpoint_ip",
    "api_operation",
    "resource_type",
    "resource_uid",
    "status",
)


def mapping_of(conn: Conn, tenant_id: str, source: str) -> str:
    """The mapping a source's events are read with, honouring its `mapping` setting."""
    from shoc.ingest.connectors.base import connector_of

    row = fetch_all(
        conn,
        "SELECT settings FROM shoc.connector_config WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    settings = dict(row[0]["settings"] or {}) if row else {}
    return str(settings.get("mapping") or connector_of(source))


def product_of(conn: Conn, tenant_id: str, source: str) -> str:
    """The `metadata_product` a source's events carry."""
    return ops.product_of(mapping_of(conn, tenant_id, source))


def _leaves(node: Any, prefix: str = "") -> set[str]:
    if isinstance(node, dict):
        out: set[str] = set()
        for key, value in node.items():
            out |= _leaves(value, f"{prefix}{key}.")
        return out
    if isinstance(node, list):
        return set().union(*(_leaves(v, prefix) for v in node)) if node else set()
    return {prefix.rstrip(".")} if prefix else set()


def sample(conn: Conn, tenant_id: str, source: str, master_key: str, limit: int = 10) -> dict:
    """One page from the source, mapped and returned. Nothing is stored."""
    from shoc.errors import NotFound
    from shoc.ingest import connectors, ocsf
    from shoc.ingest.connectors.base import PERMISSION_HINTS, connector_of, explain, read_config

    settings, secret, _enabled = read_config(conn, tenant_id, source, master_key)
    if not settings and not secret:
        raise NotFound(f"{source} is not configured; the operator adds it with source.configure")
    if connectors.pushed(source, secret):
        return {
            "source": source,
            "ok": False,
            "error": f"{source} pushes its events to /ingest/{source}, so there is no page to pull",
        }
    limit = max(1, min(limit, SAMPLE_LIMIT))
    try:
        page = connectors.get(source).fetch(settings, secret, {}, limit)
        mapping = ocsf.for_tenant(
            conn, tenant_id, str(settings.get("mapping") or connector_of(source))
        )
        rows = [mapping.map_record(r, tenant_id) for r in page.records[:limit]]
    except Exception as exc:
        return {
            "source": source,
            "ok": False,
            "error": explain(source, exc),
            "needs": PERMISSION_HINTS.get(connector_of(source), ""),
        }
    unmapped = sorted(set().union(*(_leaves(r["unmapped"]) for r in rows)) if rows else set())
    return {
        "source": source,
        "ok": True,
        "fetched": len(rows),
        "error": page.error,
        "unmapped_fields": unmapped[:100],
        "rows": [{k: r.get(k) for k in SHOWN} for r in rows],
    }


def coverage(conn: Conn, store: Any, tenant_id: str, product: str) -> tuple[list[str], list[str]]:
    """(rules this product can carry, rules it cannot and why), from its own events."""
    from shoc.detect import rules as ruleset
    from shoc.store import ocsf as layout

    mine = [
        r.id
        for r in ruleset.load(None, conn, tenant_id)
        if product
        in layout.products_for(r.logsource.get("product", ""), r.logsource.get("service", ""))
    ]
    quality = next(
        (q for q in ops.source_quality(conn, store, tenant_id) if q.product == product), None
    )
    if quality is None or not quality.events:
        return [], [f"{r}: no events from {product} in 30 days" for r in mine]
    blind: dict[str, str] = {}
    for col, ids in quality.readers.items():
        if quality.fields.get(col, 0.0) < ops.FIDELITY_FLOOR:
            for rule_id in ids:
                blind.setdefault(rule_id, col)
    return (
        [r for r in mine if r not in blind],
        [f"{r}: {blind[r]} is empty in most {product} events" for r in mine if r in blind],
    )


def unfed(
    conn: Conn, tenant_id: str, source: str, supports: list[str], cannot: list[str]
) -> tuple[list[str], list[str]]:
    """`coverage`, less the rules the source's own settings keep from firing,
    each with what to change: CloudTrail read through LookupEvents never sees
    the S3 data events a rule asks for (ING-1)."""
    from shoc.detect import rules as ruleset
    from shoc.ingest import connectors
    from shoc.ingest.connectors.base import connector_of

    name = connector_of(source)
    check = (
        getattr(connectors._module(name), "cannot_carry", None)
        if (name in connectors.available())
        else None
    )
    if check is None:
        return supports, cannot
    row = fetch_all(
        conn,
        "SELECT settings FROM shoc.connector_config WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    settings = dict(row[0]["settings"] or {}) if row else {}
    mine = set(supports) | {c.split(":", 1)[0] for c in cannot}
    why = {
        r.id: said
        for r in ruleset.load(None, conn, tenant_id)
        if r.id in mine and (said := check(settings, r))
    }
    return (
        [r for r in supports if r not in why],
        [c for c in cannot if c.split(":", 1)[0] not in why]
        + [f"{r}: {said}" for r, said in sorted(why.items())],
    )


def proof(conn: Conn, store: Any, tenant_id: str, product: str) -> str:
    """A finding at least one of this product's events became, or ''."""
    from shoc.store import ocsf as layout

    findings = fetch_all(
        conn,
        """SELECT finding_uid, event_uids FROM shoc.findings
           WHERE tenant_id = %s AND last_seen > now() - interval '30 days'
           ORDER BY last_seen DESC LIMIT 200""",
        (tenant_id,),
    )
    owner = {str(u): str(f["finding_uid"]) for f in findings for u in (f["event_uids"] or [])[:5]}
    uids = list(owner)[:500]
    if not uids:
        return ""
    params: dict[str, Any] = {f"u{i}": u for i, u in enumerate(uids)}
    params.update(tenant_id=tenant_id, product=product)
    rows = store.query(
        f"SELECT event_uid FROM {layout.EVENTS_TABLE} "
        "WHERE tenant_id = :tenant_id AND metadata_product = :product "
        f"AND event_uid IN ({', '.join(f':u{i}' for i in range(len(uids)))})",
        params,
        1,
    ).rows
    return owner.get(str(rows[0]["event_uid"]), "") if rows else ""


def _recent(store: Any, tenant_id: str, product: str) -> list[dict[str, Any]]:
    """The vendor records behind this product's newest events, as they arrived."""
    from shoc.store import ocsf as layout

    rows = store.query(
        f"""SELECT raw FROM {layout.EVENTS_TABLE}
            WHERE tenant_id = :tenant_id AND metadata_product = :product
            ORDER BY time DESC""",
        {"tenant_id": tenant_id, "product": product},
        REPAIR_EVENTS,
    ).rows
    raws = [json.loads(r["raw"]) if isinstance(r["raw"], str) else r["raw"] for r in rows]
    return [r for r in raws if isinstance(r, dict) and r]


def _fill(mapping: Any, records: list[dict[str, Any]], tenant_id: str) -> dict[str, float]:
    """Per mapped column, the share of `records` it comes out non-empty for."""
    rows = [mapping.map_record(r, tenant_id) for r in records]
    return {
        col: sum(r.get(col) not in (None, "") for r in rows) / len(rows) for col in mapping.fields
    }


def check_patch(
    conn: Conn,
    store: Any,
    tenant_id: str,
    source: str,
    fields: dict[str, Any],
) -> dict[str, list[float]]:
    """{column: [fill before, fill after]} for a patch that passes, or ValidationError.

    It passes when the tenant's recent events of this source fill no column less
    and at least one more. `fields` can move paths and transforms; it cannot set
    a constant, name a column outside the layout, or touch the ones in FIXED.
    """
    from shoc.errors import ValidationError
    from shoc.ingest import ocsf
    from shoc.store import ocsf as layout

    current = ocsf.for_tenant(conn, tenant_id, source)
    for col, spec in fields.items():
        if col not in layout.COLUMN_NAMES or col in FIXED or col in current.constants:
            raise ValidationError(f"{col} is not a column a mapping patch may set")
        spec = {"path": spec} if isinstance(spec, str) else spec
        if not isinstance(spec, dict) or not spec.keys() <= {"path", "paths", "transform"}:
            raise ValidationError(f"{col}: a spec is a path, or path/paths and a transform")
        if spec.get("transform") and spec["transform"] not in ocsf.TRANSFORMS:
            raise ValidationError(f"{col}: unknown transform {spec['transform']}")
    records = _recent(store, tenant_id, ops.product_of(source))
    if not records:
        raise ValidationError(f"{source} has no recent events to check a patch against")
    patched = replace(current, fields={**current.fields, **fields})
    before = _fill(current, records, tenant_id)
    after = _fill(patched, records, tenant_id)
    fill = {c: [round(before.get(c, 0.0), 3), round(after[c], 3)] for c in after}
    if any(a < b for b, a in fill.values()) or not any(a > b for b, a in fill.values()):
        raise ValidationError(f"the patch does not fill more of {source}'s events: {fill}")
    return fill


def write_patch(
    conn: Conn,
    tenant_id: str,
    source: str,
    fields: dict[str, Any],
    reason: str,
    fill: dict[str, list[float]],
    who: str,
) -> None:
    """Merge `fields` into the tenant's override for `source`."""
    execute(
        conn,
        """INSERT INTO shoc.mapping_overrides (tenant_id, source, fields, reason, fill, written_by)
           VALUES (%s, %s, %s, %s, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               fields = shoc.mapping_overrides.fields || EXCLUDED.fields,
               reason = EXCLUDED.reason, fill = EXCLUDED.fill,
               written_by = EXCLUDED.written_by, updated_at = now()""",
        (tenant_id, source, json.dumps(fields), reason[:2000], json.dumps(fill), who),
    )


@dataclass
class FieldPath:
    """Where one OCSF column is now found in the vendor's record."""

    column: str = f("", doc="The OCSF column, one of the mapping's `fields:` keys")
    paths: list[str] = f(doc="Dotted paths into the vendor record, first match wins", factory=list)
    transform: str = f("", doc="Keep the transform the column already had, or empty")


@dataclass
class MappingPatch:
    """The field paths to move so the columns fill again."""

    fields: list[FieldPath] = f(doc="Only columns that should read a new path", factory=list)
    reason: str = f("", doc="Which vendor field replaced which, in one sentence")


REPAIR_PROMPT = """You maintain the OCSF mapping for one log source in a small
company's SOC. The vendor changed the shape of its records: some mapped columns
now come out empty, and fields the mapping does not read have appeared.

Match each empty column to the vendor field that now carries the same value, if
one does. Change paths only. Leave a column out when no field carries its value;
a guess that fills a column with the wrong value is worse than an empty one.
Every patch is replayed over the tenant's recent events and kept only if nothing
fills less and something fills more."""


def repair(
    conn: Conn,
    store: Any,
    tenant_id: str,
    cfg: Any,
    source: str,
    client: Any = None,
) -> str:
    """Ask a model to move the paths a vendor change broke. One sentence, or ''."""
    import hashlib

    from shoc.agents import manager, safety
    from shoc.agents.llm import NoLLM, complete_typed, from_config
    from shoc.db import audit
    from shoc.errors import ValidationError
    from shoc.ingest import ocsf

    name = mapping_of(conn, tenant_id, source)
    records = _recent(store, tenant_id, ops.product_of(name))
    if not records:
        return ""
    current = ocsf.for_tenant(conn, tenant_id, name)
    # Only columns a rule reads: one that is empty by design (an error field on
    # a source that rarely fails) is not broken, and a model asked to fill it
    # would find something wrong to fill it with.
    readers = next(
        (
            q.readers
            for q in ops.source_quality(conn, store, tenant_id)
            if q.product == ops.product_of(name)
        ),
        {},
    )
    fill = _fill(current, records, tenant_id)
    empty = sorted(
        c for c in readers if c in current.fields and fill.get(c, 0.0) < ops.FIDELITY_FLOOR
    )
    rows = [current.map_record(r, tenant_id) for r in records]
    unread = sorted(set().union(*(_leaves(r["unmapped"]) for r in rows)))
    if not empty or not unread:
        return ""
    shape = hashlib.sha256(json.dumps([empty, unread]).encode()).hexdigest()[:32]
    tried = fetch_all(
        conn,
        "SELECT 1 FROM shoc.source_onboarding "
        "WHERE tenant_id = %s AND source = %s AND repair_tried = %s",
        (tenant_id, source, shape),
    )
    if tried:
        return ""
    client = client if client is not None else from_config(cfg, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return ""
    if ops.provider_failing(conn, tenant_id):
        return ""
    prompt = "\n".join(
        [
            f"Source: {name}.",
            # A tenant's override paths were themselves read from vendor records.
            "Current field specs:",
            safety.quote("field_specs", current.fields),
            f"Columns now empty in most events: {', '.join(empty)}.",
            # Field names come from the vendor's records, so they are data too.
            safety.quote("vendor_fields_not_read", unread[:200]),
            safety.quote("vendor_records", records[:REPAIR_SHOWN]),
        ]
    )
    try:
        answer, usage = complete_typed(
            client,
            safety.system_prompt(REPAIR_PROMPT),
            prompt,
            MappingPatch,
            cfg.llm_max_tokens,
        )
    except Exception as exc:
        # The next daily turn asks again; a failed job would ask five times.
        ops.record_failure(
            conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
        )
        return ""
    ops.charge(conn, tenant_id, usage)
    _save(conn, tenant_id, source, repair_tried=shape)
    patch = {
        p.column: {
            "paths": [str(x) for x in p.paths],
            **({"transform": p.transform} if p.transform else {}),
        }
        for p in answer.fields
        if p.column in empty and p.paths
    }
    if not patch:
        return ""
    try:
        checked = check_patch(conn, store, tenant_id, name, patch)
    except ValidationError as exc:
        return f"{source}: the mapping patch was not kept, {exc}"
    write_patch(conn, tenant_id, name, patch, answer.reason, checked, "agent:Integrator")
    audit.append(
        conn,
        tenant_id,
        "agent",
        "Integrator",
        "mapping.write",
        audit.hash_payload(patch),
        audit.hash_payload(checked),
    )
    moved = ", ".join(f"{c} {b:.0%}→{a:.0%}" for c, (b, a) in checked.items() if a != b)
    manager.tell(
        conn,
        tenant_id,
        "integrator",
        "digest",
        f"{source} changed shape; its mapping now reads new paths ({moved}). {answer.reason}"[:800],
        group_key=f"mapping:{source}",
    )
    return f"{source}: {moved}"


def _save(conn: Conn, tenant_id: str, source: str, **values: Any) -> None:
    cols = ["tenant_id", "source", *values]
    vals = [tenant_id, source] + [
        json.dumps(v) if isinstance(v, list) else v for v in values.values()
    ]
    execute(
        conn,
        f"""INSERT INTO shoc.source_onboarding ({", ".join(cols)}, updated_at)
            VALUES ({", ".join(["%s"] * len(cols))}, now())
            ON CONFLICT (tenant_id, source) DO UPDATE SET
            {", ".join(f"{c} = EXCLUDED.{c}" for c in values)}, updated_at = now()""",
        vals,
    )


def _prove_connected(conn: Conn, store: Any, tenant_id: str) -> dict[str, str]:
    """Mark every configured source a finding has already proved. No model needed."""
    proved = {}
    for row in fetch_all(
        conn,
        "SELECT source FROM shoc.connector_config "
        "WHERE tenant_id = %s AND source NOT IN ('slack', 'llm')",
        (tenant_id,),
    ):
        source = str(row["source"])
        finding = proof(conn, store, tenant_id, product_of(conn, tenant_id, source))
        if finding:
            proved[source] = finding
            execute(
                conn,
                """INSERT INTO shoc.source_onboarding
                       (tenant_id, source, step, proof_finding, onboarded_at)
                   VALUES (%s, %s, 'done', %s, now())
                   ON CONFLICT (tenant_id, source) DO UPDATE SET
                       step = 'done', dark = false, proof_finding = EXCLUDED.proof_finding,
                       onboarded_at = coalesce(shoc.source_onboarding.onboarded_at, now()),
                       updated_at = now()""",
                (tenant_id, source, finding),
            )
    return proved


def work(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any = None,
    source: str = "",
    client: Any = None,
) -> dict[str, Any]:
    """The daily turn, or one source's when `source` is set."""
    from shoc.config import Config
    from shoc.errors import NotFound
    from shoc.ingest import connectors
    from shoc.ingest.connectors.base import (
        PERMISSION_HINTS,
        PUSH_WHERE,
        WHERE,
        connector_of,
        read_config,
    )
    from shoc.store import ocsf as layout

    cfg = config or Config.load()
    proved = _prove_connected(conn, store, tenant_id)
    if not fetch_all(
        conn,
        """SELECT 1 FROM shoc.connector_config WHERE tenant_id = %s
           UNION ALL
           SELECT 1 FROM shoc.notices WHERE tenant_id = %s AND group_key = 'onboarding'
             AND created_at > now() - interval '7 days'
           LIMIT 1""",
        (tenant_id, tenant_id),
    ):
        # A new install with nothing connected sees nothing. Once a week is
        # enough; the weekly is where it is read.
        from shoc.agents import manager

        manager.tell(
            conn,
            tenant_id,
            "integrator",
            "digest",
            "No log source is connected, so shoc sees nothing. `shoc source list` says "
            "what each connector needs; identity (okta, entra, google_workspace) comes first.",
            group_key="onboarding",
        )

    configured = fetch_all(
        conn,
        """SELECT c.source, coalesce(s.events_seen, 0) AS events_seen
           FROM shoc.connector_config c
           LEFT JOIN shoc.connector_state s ON s.tenant_id = c.tenant_id AND s.source = c.source
           WHERE c.tenant_id = %s AND c.source NOT IN ('slack', 'llm') ORDER BY c.source""",
        (tenant_id,),
    )
    was = {
        str(r["source"]): str(r["step"])
        for r in fetch_all(
            conn,
            "SELECT source, step FROM shoc.source_onboarding WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    worked = 0
    asked: list[str] = []
    repaired: list[str] = []
    for row in configured:
        name = str(row["source"])
        if source and name != source:
            continue
        # A proved source is where a vendor change hurts: its rules go quiet.
        if said := repair(conn, store, tenant_id, cfg, name, client):
            repaired.append(said)
        if name in proved:
            continue
        worked += 1
        secret = read_config(conn, tenant_id, name, cfg.master_key)[1]
        pushing = connectors.accepts_push(name) and row["events_seen"]
        if pushing or connectors.pushed(name, secret):
            # The vendor is pushing, or set up to before its first push lands;
            # a pull credential is not missing, it is unused.
            got: dict[str, Any] = {"ok": True, "unmapped_fields": []}
        else:
            try:
                got = sample(conn, tenant_id, name, cfg.master_key)
            except NotFound:
                got = {"ok": False, "error": "It has no settings and no secret yet."}
        supports, cannot = unfed(
            conn,
            tenant_id,
            name,
            *coverage(conn, store, tenant_id, product_of(conn, tenant_id, name)),
        )
        if got["ok"]:
            _save(
                conn,
                tenant_id,
                name,
                step="prove",
                dark=False,
                scopes=[],
                click_path="",
                unmapped_fields=got["unmapped_fields"],
                supports=supports,
                cannot_support=cannot,
            )
            continue
        kind = connector_of(name)
        hint = PERMISSION_HINTS.get(kind, "")
        where = " ".join(w for w in (WHERE.get(kind, ""), PUSH_WHERE.get(kind, "")) if w)
        _save(
            conn,
            tenant_id,
            name,
            step="credentials",
            dark=False,
            scopes=[hint] if hint else [],
            click_path=where[:1000],
            supports=supports,
            cannot_support=cannot,
        )
        asked.append(name)
        if was.get(name) != "credentials":
            # Once per wait, not once a day: the weekly carries it to the operator.
            from shoc.agents import manager

            manager.tell(
                conn,
                tenant_id,
                "integrator",
                "digest",
                f"{name} waits on a credential: {got['error']} Grant {hint}. {where}"[:800],
                group_key=f"onboarding:{name}",
            )

    # A source removed while this turn worked it keeps no row: one left at
    # "credentials" would wait on the operator for a source that is gone.
    gone = {
        str(r["source"])
        for r in fetch_all(
            conn,
            """DELETE FROM shoc.source_onboarding o
               WHERE o.tenant_id = %s AND NOT o.dark AND NOT EXISTS (
                 SELECT 1 FROM shoc.connector_config c
                 WHERE c.tenant_id = o.tenant_id AND c.source = o.source)
               RETURNING o.source""",
            (tenant_id,),
        )
    }
    asked = [name for name in asked if name not in gone]

    # Dark: a connector nobody configured whose product already shows up in
    # events, through a file, a replay or another source's forwarding.
    since = datetime.now(UTC) - timedelta(days=30)
    seen = {
        str(r["product"])
        for r in store.query(
            f"""SELECT DISTINCT metadata_product AS product FROM {layout.EVENTS_TABLE}
                WHERE tenant_id = :tenant_id AND time > :since""",
            {"tenant_id": tenant_id, "since": since},
            200,
        ).rows
    }
    wired = {connector_of(str(r["source"])) for r in configured}
    dark = [
        name
        for name in connectors.available()
        if name not in wired and name != "file" and ops.product_of(name) in seen
    ]
    if not source:
        for name in dark:
            _save(conn, tenant_id, name, dark=True)

    if asked:
        from shoc.cases import engine

        engine.publish(
            conn, tenant_id, "source.needs_credentials", ",".join(asked), {"sources": asked}
        )
    return {
        "worked": worked,
        "onboarded": sorted(proved),
        "dark": dark,
        "waiting": asked,
        "repaired": repaired,
    }
