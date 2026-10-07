"""Source (connector) capabilities (ING-1, OPS-1)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import execute, fetch_all
from shoc.errors import ConfigError, NotFound, UpstreamError
from shoc.ingest import connectors
from shoc.ingest import ocsf as mapper
from shoc.ingest.connectors.base import FIELDS, PERMISSION_HINTS, PUSH_WHERE, WHERE
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class Empty:
    pass


@dataclass
class SourceList:
    configured: list[dict[str, Any]] = field(default_factory=list)
    available: list[str] = field(default_factory=list)
    push_only: list[str] = field(default_factory=list)
    also_push: list[str] = field(default_factory=list)
    mappings: list[str] = field(default_factory=list)
    needs: dict[str, dict[str, Any]] = f(
        doc="Per connector: the permission to grant and the settings and secret keys to give",
        factory=dict,
    )
    onboarding: list[dict[str, Any]] = f(
        doc="The Integrator's progress per source: step, scopes, click path, rules it can carry",
        factory=list,
    )


@capability(
    name="source.list",
    summary="List configured log sources, the connectors available and what each one needs",
    input=Empty,
    output=SourceList,
    scope="sources:read",
    tags=("sources", "read"),
)
def list_sources(ctx: Context, inp: Empty) -> Result:
    rows = fetch_all(
        ctx.db,
        """SELECT c.source, c.enabled, c.settings, c.interval_seconds,
                  c.secret,
                  s.last_run_at, s.last_ok_at, s.last_error,
                  -- A source configured and not yet synced has no state row.
                  COALESCE(s.events_seen, 0) AS events_seen,
                  -- The accounts its events named: what a response credential's
                  -- `accounts` setting lists (RFC 0025).
                  COALESCE(h.account_uids, '{}') AS accounts
           FROM shoc.connector_config c
           LEFT JOIN shoc.connector_state s
             ON s.tenant_id = c.tenant_id AND s.source = c.source
           LEFT JOIN shoc.source_history h
             ON h.tenant_id = c.tenant_id AND h.source = c.source
           WHERE c.tenant_id = %s AND c.source NOT IN ('slack', 'llm') ORDER BY c.source""",
        (ctx.tenant_id,),
    )
    from shoc.db.secrets import open_secret

    # Whether a poll credential is stored, never the credential. A push key
    # alone is not one: the source pushes and has nothing to poll with.
    for r in rows:
        blob = r.pop("secret")
        r["has_secret"] = bool(blob) and bool(
            set(
                open_secret(
                    ctx.config.master_key, blob, ctx.tenant_id, "connector_config", r["source"]
                )
            )
            - {"push_key"}
        )
    # Where shoc can act on what each source sees: the response credentials
    # that cover it, and its accounts none claims (RFC 0025).
    from shoc.cases import credentials

    covered = credentials.coverage(ctx.db, ctx.tenant_id)
    for r in rows:
        r["response"] = [
            {k: c[k] for k in ("provider", "credentials", "missing")}
            for c in covered
            if c["source"] == r["source"]
        ]
    onboarding = fetch_all(
        ctx.db,
        """SELECT source, step, dark, scopes, click_path, unmapped_fields, supports,
                  cannot_support, proof_finding, onboarded_at, updated_at
           FROM shoc.source_onboarding WHERE tenant_id = %s ORDER BY source""",
        (ctx.tenant_id,),
    )
    waiting = [r["source"] for r in onboarding if r["step"] == "credentials"]
    return Result(
        data=SourceList(
            configured=[to_json(r) for r in rows],
            available=connectors.available(),
            push_only=connectors.push_sources(),
            also_push=connectors.also_push(),
            mappings=mapper.available_sources(),
            needs={
                name: {
                    "permission": PERMISSION_HINTS.get(name, ""),
                    "where": WHERE.get(name, ""),
                    "push_where": PUSH_WHERE.get(name, ""),
                    "settings": list(settings),
                    "secret": list(secret),
                }
                for name, (settings, secret) in FIELDS.items()
            },
            onboarding=[to_json(r) for r in onboarding],
        ),
        summary=(
            f"{len(rows)} source(s) configured; {len(connectors.available())} pull connector(s) "
            f"and {len(connectors.push_sources())} push source(s) available."
            + (f" Waiting on a credential: {', '.join(waiting)}." if waiting else "")
        ),
        citations=[r["proof_finding"] for r in onboarding if r["proof_finding"]],
    )


@dataclass
class SourceConfig:
    """Configure a connector. The secret is encrypted with the master key."""

    source: str = f(
        doc="Connector name, e.g. cloudflare, or connector:label for another account "
        "of the same vendor, e.g. cloudflare:acme"
    )
    settings: dict[str, Any] = f(doc="Non-secret settings, e.g. {'org_url': '…'}", factory=dict)
    secret: dict[str, Any] = f(doc="Credentials, e.g. {'api_token': '…'}", factory=dict)
    interval_seconds: int = f(300, doc="How often the worker polls this source")
    enabled: bool = f(True, doc="Whether the worker should poll it at all")
    verify: bool = f(True, doc="Try the credential once before saving it")


@dataclass
class SourceState:
    source: str = ""
    enabled: bool = True
    interval_seconds: int = 300
    verified: bool | None = None
    verify_error: str | None = None


@capability(
    name="source.configure",
    summary="Add or update a log source and its credentials",
    input=SourceConfig,
    output=SourceState,
    scope="sources:write",
    principals=("human",),
    audit=True,
    tags=("sources", "write"),
)
def configure_source(ctx: Context, inp: SourceConfig) -> Result:
    from shoc.db.jobs import enqueue, upsert_schedule
    from shoc.db.secrets import seal

    known = connectors.available() + connectors.push_sources()
    if connectors.connector_of(inp.source) not in known:
        raise ConfigError(f"unknown source '{inp.source}' (have: {', '.join(sorted(known))})")
    if not re.fullmatch(r"[a-z0-9_]+(:[a-z0-9_-]{1,40})?", inp.source):
        raise ConfigError(
            f"'{inp.source}': a second account is connector:label, the label in "
            "lowercase letters, digits, '_' and '-'"
        )
    blob = (
        seal(ctx.config.master_key, inp.secret, ctx.tenant_id, "connector_config", inp.source)
        if inp.secret
        else None
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config
               (tenant_id, source, enabled, settings, secret, interval_seconds)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               enabled = EXCLUDED.enabled,
               settings = EXCLUDED.settings,
               secret = COALESCE(EXCLUDED.secret, shoc.connector_config.secret),
               interval_seconds = EXCLUDED.interval_seconds""",
        (
            ctx.tenant_id,
            inp.source,
            inp.enabled,
            json.dumps(inp.settings),
            blob,
            inp.interval_seconds,
        ),
    )
    # The Integrator takes a new or changed source from here (D50).
    enqueue(
        ctx.db,
        ctx.tenant_id,
        "source.onboard",
        {"source": inp.source},
        idempotency_key=f"onboard:{inp.source}:{int(time.time() // 3600)}",
    )
    # A source that can push and arrived without credentials is being set up as a
    # push source; there is nothing to poll it with.
    if inp.source in connectors.push_sources() or (
        connectors.accepts_push(inp.source) and not inp.secret
    ):
        return Result(
            data=SourceState(
                source=inp.source, enabled=inp.enabled, interval_seconds=inp.interval_seconds
            ),
            summary=(
                f"Push source {inp.source} configured. Call source.push_key to get its signing "
                f"key, then POST records to /ingest/{inp.source}."
            ),
        )
    # A poll that loads wakes a warehouse, and detection only looks once a
    # cycle, so on one a source polls no more often than the cycle (D71).
    every = inp.interval_seconds
    if getattr(ctx.config, "backend", "postgres") != "postgres":
        every = max(every, ctx.config.cycle_seconds)
    upsert_schedule(
        ctx.db,
        f"{ctx.tenant_id}:sync:{inp.source}",
        ctx.tenant_id,
        "source.sync",
        every,
        {"source": inp.source},
        enabled=inp.enabled,
    )
    if not inp.enabled:
        return Result(
            data=SourceState(
                source=inp.source, enabled=False, interval_seconds=inp.interval_seconds
            ),
            summary=f"Source {inp.source} saved and disabled; the worker does not poll it.",
        )
    verified, why = _verify(ctx, inp)
    _remember_own(ctx, inp)
    return Result(
        data=SourceState(
            source=inp.source,
            enabled=inp.enabled,
            interval_seconds=inp.interval_seconds,
            verified=verified,
            verify_error=why,
        ),
        summary=(
            f"Source {inp.source} configured, polling every {inp.interval_seconds}s."
            + (f" The credential works. {why}" if verified and why else "")
            + (f" It is saved, but the credential did not work: {why}" if verified is False else "")
        ),
    )


def _verify(ctx: Context, inp: SourceConfig) -> tuple[bool | None, str | None]:
    """Try the credential once, now, rather than leaving it to the next cycle.

    A wrong token used to be accepted with "configured", and only announced
    itself on a later sync, in a log nobody was reading. The source is still
    saved either way: refusing would mean you cannot write down a credential
    before the permission it needs has been granted.
    """
    if not inp.verify or not inp.secret:
        return None, None
    from shoc.ingest.connectors.base import run

    stats = run(
        ctx.db,
        ctx.store,
        ctx.tenant_id,
        inp.source,
        inp.settings,
        inp.secret,
        limit=1,
        max_pages=1,
        # A one-record page leaves a page token or a moved window behind; the
        # scheduled sync starts from the stored cursor, so this probe keeps out.
        persist=False,
    )
    if stats.error:
        return False, stats.error
    return True, f"{stats.fetched} record(s) read on the first page."


def _has_own(ctx: Context, source: str) -> bool:
    from shoc.db.pool import fetch_one

    return bool(
        fetch_one(
            ctx.db,
            """SELECT 1 FROM shoc.own_identities
           WHERE tenant_id = %s AND kind = 'credential' AND source = %s""",
            (ctx.tenant_id, source),
        )
    )


def _remember_own(ctx: Context, inp: SourceConfig) -> None:
    """Write down the non-secret id of the credential shoc was just given (RFC 0021).

    Without it, every token shoc fetches for itself reads in the vendor's log
    as an unknown client acting on the company's data.
    """
    import contextlib
    import importlib

    from shoc.cases import own

    if not inp.secret:
        return
    module = importlib.import_module(
        f"shoc.ingest.connectors.{connectors.connector_of(inp.source)}"
    )
    found = getattr(module, "credentials", None)
    if found is None:
        return
    with contextlib.suppress(Exception):  # a vendor that does not answer costs only this
        for value, scope in found(inp.settings, inp.secret):
            own.register(
                ctx.db,
                ctx.tenant_id,
                "credential",
                value,
                source=inp.source,
                scope=scope,
                note=f"the credential {inp.source} is read with",
                by=f"{ctx.caller.kind}:{ctx.caller.id}",
            )


@dataclass
class RemoveInput:
    source: str = f(doc="The connected source to remove")


@dataclass
class RemoveResult:
    source: str = ""


@capability(
    name="source.remove",
    summary="Disconnect a log source; the events it already delivered stay",
    input=RemoveInput,
    output=RemoveResult,
    scope="sources:write",
    principals=("human",),
    audit=True,
    tags=("sources", "write"),
)
def remove_source(ctx: Context, inp: RemoveInput) -> Result:
    """What shoc keeps to reach the source goes: its settings and sealed
    credential (a push key included), its cursor, its sync schedule, its
    onboarding and the jobs still queued for it. Its events stay and age out
    with retention. Connecting it again starts from the backfill window, and
    what that reads again loads once."""
    source, tenant = inp.source, ctx.tenant_id
    gone = execute(
        ctx.db,
        "DELETE FROM shoc.connector_config WHERE tenant_id = %s AND source = %s",
        (tenant, source),
    )
    if not gone:
        raise NotFound(f"source '{source}' is not connected")
    for sql, params in (
        ("DELETE FROM shoc.connector_state WHERE tenant_id = %s AND source = %s", (tenant, source)),
        (
            "DELETE FROM shoc.source_onboarding WHERE tenant_id = %s AND source = %s",
            (tenant, source),
        ),
        (
            "DELETE FROM shoc.schedules WHERE tenant_id = %s AND schedule_id = %s",
            (tenant, f"{tenant}:sync:{source}"),
        ),
        (
            """DELETE FROM shoc.jobs WHERE tenant_id = %s AND state = 'pending'
              AND kind IN ('source.sync', 'source.onboard') AND payload->>'source' = %s""",
            (tenant, source),
        ),
    ):
        execute(ctx.db, sql, params)
    return Result(
        data=RemoveResult(source=source),
        summary=f"Source {source} removed. The events it delivered stay.",
    )


@dataclass
class PushKeyInput:
    source: str = f(doc="The push source: github")
    rotate: bool = f(False, doc="Replace the existing key; the old one stops working")


@dataclass
class PushKeyResult:
    source: str = ""
    push_key: str = ""
    signature_header: str = ""
    timestamp_header: str = ""


@capability(
    name="source.push_key",
    summary="Create or rotate the signing key a push source must use",
    input=PushKeyInput,
    output=PushKeyResult,
    scope="sources:write",
    principals=("human",),
    audit=True,
    tags=("sources", "write", "security"),
)
def push_key(ctx: Context, inp: PushKeyInput) -> Result:
    from shoc.api.ingest import GITHUB_SIGNATURE_HEADER, new_key
    from shoc.db.pool import fetch_one
    from shoc.db.secrets import open_secret, seal

    if not connectors.accepts_push(inp.source):
        raise ConfigError(f"{inp.source} is polled; only a source its vendor pushes has a key")
    row = fetch_one(
        ctx.db,
        "SELECT settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source=%s",
        (ctx.tenant_id, inp.source),
    )
    where = (ctx.tenant_id, "connector_config", inp.source)
    secret = open_secret(ctx.config.master_key, row["secret"], *where) if row else {}
    settings = dict(row["settings"]) if row else {}
    # The key is shown when it is made and never again: asking without
    # `rotate` for a source that has one says so and returns no key.
    if secret.get("push_key") and not inp.rotate:
        return Result(
            data=PushKeyResult(
                source=inp.source,
                signature_header=GITHUB_SIGNATURE_HEADER,
            ),
            summary=(
                f"{inp.source} already has a push key, and it is not shown again. "
                "Rotate it to get a new one; the old one stops working."
            ),
        )
    secret["push_key"] = new_key()
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s,%s,true,%s,%s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET secret = EXCLUDED.secret""",
        (
            ctx.tenant_id,
            inp.source,
            json.dumps(settings),
            seal(ctx.config.master_key, secret, *where),
        ),
    )
    return Result(
        data=PushKeyResult(
            source=inp.source,
            push_key=secret["push_key"],
            signature_header=GITHUB_SIGNATURE_HEADER,
        ),
        summary=(
            f"Push key for {inp.source} "
            + ("rotated" if inp.rotate else "ready")
            + f". Give it to {inp.source} as the webhook secret; it is shown once."
        ),
    )


@dataclass
class SyncInput:
    source: str = f(doc="Which source to pull now")
    limit: int = f(1000, doc="Records per page")
    max_pages: int = f(20, doc="Safety cap on pages per run")


@dataclass
class SyncResult:
    source: str = ""
    fetched: int = 0
    loaded: int = 0
    pages: int = 0
    error: str | None = None
    detail: str | None = None
    # What the source's own API says exists, read at most daily (D49).
    snapshot_assets: int = 0
    snapshot_error: str = ""


@capability(
    name="source.sync",
    summary="Pull new events from a source now",
    input=SyncInput,
    output=SyncResult,
    scope="sources:sync",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("sources", "ingest"),
)
def sync_source(ctx: Context, inp: SyncInput) -> Result:
    from shoc.ingest.connectors.base import (
        explain,
        read_config,
        run,
        snapshot_due,
        take_snapshot,
    )
    from shoc.store import open_store

    settings, secret, enabled = read_config(
        ctx.db, ctx.tenant_id, inp.source, ctx.config.master_key
    )
    if not settings and not secret:
        raise ConfigError(f"source '{inp.source}' is not configured; call source.configure first")
    if connectors.pushed(inp.source, secret):
        # A pull would fail on the credential a pushed source never needed, and
        # Ops would queue it again after every push. A failure an earlier pull
        # left goes too: nothing polls this source (ING-2).
        execute(
            ctx.db,
            "UPDATE shoc.connector_state SET last_error = NULL "
            "WHERE tenant_id = %s AND source = %s",
            (ctx.tenant_id, inp.source),
        )
        return Result(
            data=SyncResult(source=inp.source),
            summary=f"{inp.source} pushes its events to /ingest/{inp.source}; nothing was pulled.",
        )
    if not enabled:
        # A job queued before the source was disabled finds nothing to do.
        return Result(
            data=SyncResult(source=inp.source),
            summary=f"{inp.source} is disabled; nothing was pulled.",
        )
    if secret and not _has_own(ctx, inp.source):
        # A source configured before shoc recorded its own credentials learns
        # them on its next pull (RFC 0021).
        _remember_own(ctx, SourceConfig(source=inp.source, settings=settings, secret=secret))
    # Loading is a write. The worker is an agent principal, and agents read
    # through SHOC_READONLY_DSN (D22), which cannot create partitions or insert,
    # so the pull loads through the writer role.
    store = open_store(ctx.config, ctx.tenant_id) if ctx.reads_only else ctx.store
    try:
        stats = run(
            ctx.db,
            store,
            ctx.tenant_id,
            inp.source,
            settings,
            secret,
            limit=inp.limit,
            max_pages=inp.max_pages,
        )
    finally:
        if store is not ctx.store:
            store.close()
    if stats.loaded:
        from shoc.cases import engine

        # Detection reads it now, once for every source of the cycle (RFC 0034).
        engine.publish(ctx.db, ctx.tenant_id, "events.loaded", inp.source, {"loaded": stats.loaded})
    if stats.error:
        # `run` has already written the failure to connector_state, so health
        # knows. Raising is what makes the shell exit non-zero and REST answer
        # 502: a pull that fetched nothing because it was refused is not a
        # successful call with a field set.
        raise UpstreamError(
            f"{inp.source}: fetched {stats.fetched}, loaded {stats.loaded} — {stats.error}"
        )
    assets, snap_error = 0, ""
    if snapshot_due(ctx.db, ctx.tenant_id, inp.source):
        # The log was read; a snapshot that fails is said, and retried next pull.
        try:
            assets = take_snapshot(ctx.db, ctx.tenant_id, inp.source, settings, secret)
        except Exception as exc:
            snap_error = explain(inp.source, exc)
    return Result(
        data=SyncResult(
            source=stats.source,
            fetched=stats.fetched,
            loaded=stats.loaded,
            pages=stats.pages,
            error=stats.error,
            detail=stats.detail,
            snapshot_assets=assets,
            snapshot_error=snap_error,
        ),
        summary=f"{inp.source}: fetched {stats.fetched}, loaded {stats.loaded}."
        + (f" Snapshot: {assets} asset(s)." if assets else "")
        + (f" Snapshot failed: {snap_error}" if snap_error else ""),
    )


@dataclass
class SampleInput:
    source: str = f(doc="A configured source")
    limit: int = f(10, doc="Records to read, at most 20")


@dataclass
class SampleResult:
    source: str = ""
    ok: bool = False
    fetched: int = 0
    error: str = ""
    needs: str = f("", doc="The permission a rejected credential most likely lacks")
    unmapped_fields: list[str] = f(
        doc="Fields the mapping did not read. They are kept, under unmapped.<path>",
        factory=list,
    )
    rows: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="source.sample",
    summary="Read one page from a source and map it, storing nothing",
    input=SampleInput,
    output=SampleResult,
    scope="sources:sample",
    # It calls the vendor's API, so an external agent does not get it.
    principals=("human", "agent", "service"),
    tags=("sources", "read"),
)
def sample_source(ctx: Context, inp: SampleInput) -> Result:
    from shoc.agents import integrator

    out = integrator.sample(ctx.db, ctx.tenant_id, inp.source, ctx.config.master_key, inp.limit)
    return Result(
        data=SampleResult(**out),
        summary=(
            f"{inp.source}: read {out['fetched']} record(s), "
            f"{len(out['unmapped_fields'])} field(s) left unmapped."
            + (f" Failed: {out['error']}" if out["error"] else "")
            if out["ok"]
            else f"{inp.source}: {out['error']}"
        ),
    )


@dataclass
class MappingTestInput:
    source: str = f(doc="A source, e.g. okta")


@dataclass
class MappingTestResult:
    source: str = ""
    product: str = ""
    supports: list[str] = f(doc="Rules its events can carry", factory=list)
    cannot_support: list[str] = f(doc="Rules they cannot, and why", factory=list)
    proof_finding: str = f("", doc="A finding one of its events became, if any")


@capability(
    name="mapping.test",
    summary="Say which rules a source can carry, from the fields its events fill",
    input=MappingTestInput,
    output=MappingTestResult,
    scope="sources:read",
    tags=("sources", "read"),
)
def mapping_test(ctx: Context, inp: MappingTestInput) -> Result:
    from shoc.agents import integrator

    product = integrator.product_of(ctx.db, ctx.tenant_id, inp.source)
    supports, cannot = integrator.coverage(ctx.db, ctx.store, ctx.tenant_id, product)
    proof = integrator.proof(ctx.db, ctx.store, ctx.tenant_id, product)
    return Result(
        data=MappingTestResult(
            source=inp.source,
            product=product,
            supports=supports,
            cannot_support=cannot,
            proof_finding=proof,
        ),
        summary=(
            f"{inp.source}: carries {len(supports)} rule(s), cannot carry {len(cannot)}; "
            + (f"proved by {proof}." if proof else "no finding has come from it yet.")
        ),
        citations=[proof] if proof else [],
    )


@dataclass
class MappingWriteInput:
    source: str = f(doc="The mapping, named after its connector, e.g. okta")
    fields: dict[str, Any] = f(
        doc="Column to a path, or to {paths, transform}, merged over the shipped "
        "fields. Empty removes this tenant's override",
        factory=dict,
    )
    reason: str = f("", doc="Which vendor field replaced which")


@dataclass
class MappingWriteResult:
    source: str = ""
    fill: dict[str, Any] = f(
        doc="Per column, the share of recent events filled before and after", factory=dict
    )
    removed: bool = False


@capability(
    name="mapping.write",
    summary="Move a source's field paths for this tenant, kept only if its events fill more",
    input=MappingWriteInput,
    output=MappingWriteResult,
    scope="sources:write",
    principals=("human",),
    audit=True,
    tags=("sources", "write"),
)
def mapping_write(ctx: Context, inp: MappingWriteInput) -> Result:
    from shoc.agents import integrator

    mapper.load_mapping(inp.source)  # a name with no shipped mapping is refused here
    if not inp.fields:
        execute(
            ctx.db,
            "DELETE FROM shoc.mapping_overrides WHERE tenant_id = %s AND source = %s",
            (ctx.tenant_id, inp.source),
        )
        return Result(
            data=MappingWriteResult(source=inp.source, removed=True),
            summary=f"{inp.source} reads the shipped mapping again.",
        )
    fill = integrator.check_patch(ctx.db, ctx.store, ctx.tenant_id, inp.source, inp.fields)
    integrator.write_patch(
        ctx.db,
        ctx.tenant_id,
        inp.source,
        inp.fields,
        inp.reason,
        fill,
        f"{ctx.caller.kind}:{ctx.caller.id}",
    )
    return Result(
        data=MappingWriteResult(source=inp.source, fill=fill),
        summary=f"{inp.source} now reads {', '.join(inp.fields)} from new paths.",
    )


@dataclass
class OnboardInput:
    source: str = f("", doc="One source, or empty for all of them")


@dataclass
class OnboardReport:
    worked: int = 0
    onboarded: list[str] = field(default_factory=list)
    dark: list[str] = field(default_factory=list)
    waiting: list[str] = f(doc="Sources waiting on the operator for a credential", factory=list)
    repaired: list[str] = f(doc="Mappings moved to a vendor's new field paths", factory=list)


@capability(
    name="source.onboard",
    summary="The Integrator works each source until it has produced a finding",
    input=OnboardInput,
    output=OnboardReport,
    scope="sources:onboard",
    principals=("human", "service", "agent"),
    audit=True,
    tags=("sources", "write"),
)
def onboard(ctx: Context, inp: OnboardInput) -> Result:
    from shoc.agents import integrator

    report = OnboardReport(
        **integrator.work(ctx.db, ctx.store, ctx.tenant_id, ctx.config, source=inp.source)
    )
    return Result(
        data=report,
        summary=(
            f"Integrator: {len(report.onboarded)} source(s) proved"
            + (f", {len(report.dark)} dark" if report.dark else "")
            + (
                f", waiting on credentials for {', '.join(report.waiting)}"
                if report.waiting
                else ""
            )
            + (f"; remapped {'; '.join(report.repaired)}" if report.repaired else "")
            + "."
        ),
    )
