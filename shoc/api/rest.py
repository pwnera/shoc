"""REST + OpenAPI, generated from the registry (API-1).

Every capability gets `POST /v1/<area>/<name>` with its input schema as the body
and the standard envelope as the response.

The hand-written routes exist for clients that cannot send that request:
Prometheus (`/metrics`, a GET), an SSE reader (`/v1/stream`), Slack and GitHub,
which sign their own bodies and send no bearer token, and MCP. Each one
authenticates its client and then invokes a capability, so the registry checks
it. Outside a capability they only read what authentication needs (Slack's
signing secret, GitHub's push key) and record that a push arrived
(`connector_state`, as a poll does).

The /auth/* routes (`shoc.api.signin`, RFC 0028) are the exception: signing
a person in sets a cookie and follows redirects before there is a caller, so
no capability can do it. They sign people in and out and nothing else.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Mount, Route

from shoc import __version__
from shoc.api import signin
from shoc.api.auth import SINGLE_USER, authenticate
from shoc.capabilities.registry import Caller, Capability, Context, all_capabilities, get
from shoc.config import Config
from shoc.errors import Denied, ShocError, ValidationError

log = logging.getLogger("shoc.serve")

# How often `serve` checks that some worker is still ticking the schedule.
SCHEDULER_CHECK_SECONDS = 300.0
# How often an open event stream asks again who is reading it.
STREAM_RECHECK_SECONDS = 30.0


def watch_scheduler(cfg: Config, stop: threading.Event, every: float) -> None:
    """Page when no worker ticks the schedule (OPS-1).

    A stalled scheduler cannot report itself, since `ops.check` is one of its
    schedules, so `serve` checks from outside it. This covers every worker down
    or crashlooping as well as a leader stuck in a job.
    """
    from shoc.agents import manager
    from shoc.db import jobs, pool

    while not stop.wait(every):
        try:
            conn = pool.connect(cfg)
            pool.set_tenant(conn, pool.ALL_TENANTS)
            for tenant in jobs.tenants(conn, cfg.tenant_id):
                pool.set_tenant(conn, tenant)
                manager.scheduler(conn, tenant, cfg)
        except Exception as exc:
            log.warning("could not check the scheduler: %s", exc)
            pool.close()
    pool.close()


def _too_large(limit: int) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "code": "payload_too_large",
                "message": f"request body exceeds {limit} bytes; send it in batches",
            }
        },
        413,
    )


def _over_limit(request: Request, limit: int) -> bool:
    declared = request.headers.get("content-length")
    return bool(declared and declared.isdigit() and int(declared) > limit)


def _error(exc: ShocError | Exception) -> JSONResponse:
    if isinstance(exc, ShocError):
        return JSONResponse({"error": exc.to_json()}, exc.status)
    return JSONResponse({"error": {"code": "internal_error", "message": str(exc)}}, 500)


def _context(request: Request, config: Config) -> Context:
    caller, tenant = authenticate(request.headers, config.tenant_id, config, request.method)
    return Context(tenant_id=tenant, caller=caller, config=config)


def _handler(cap: Capability, config: Config):
    async def handle(request: Request) -> JSONResponse:
        try:
            if _over_limit(request, config.max_request_bytes):
                return _too_large(config.max_request_bytes)
            body: Any = {}
            if await request.body():
                body = await request.json()
            if not isinstance(body, dict):
                raise ValidationError("request body must be a JSON object")
            # Off the event loop, the token lookup included: case.investigate runs
            # the crew for minutes, and one blocking call would stall every other request.
            result = await asyncio.to_thread(lambda: cap.invoke(_context(request, config), body))
            return JSONResponse(result.to_json())
        except ShocError as exc:
            return _error(exc)
        except json.JSONDecodeError as exc:
            return JSONResponse(
                {"error": {"code": "validation_error", "message": f"bad JSON: {exc}"}}, 400
            )
        except Exception as exc:
            return _error(exc)

    return handle


async def _slack(request: Request, cfg: Config, kind: str) -> JSONResponse:
    """Verify the request really came from Slack, then let the registry decide (API-3)."""
    try:
        raw = await request.body()
        return await asyncio.to_thread(_slack_sync, raw, request.headers, cfg, kind)
    except ShocError as exc:
        return _error(exc)
    except Exception as exc:
        return _error(exc)


def _slack_sync(raw: bytes, headers: Any, cfg: Config, kind: str) -> JSONResponse:
    from shoc.api import slack

    tenant = headers.get("x-shoc-tenant") or cfg.tenant_id
    ctx = Context(tenant_id=tenant, caller=Caller(kind="external_agent", id="slack"), config=cfg)
    app = slack.load_app(ctx.db, tenant, cfg.master_key)
    slack.verify(
        app.signing_secret,
        headers.get(slack.TIMESTAMP_HEADER, ""),
        raw,
        headers.get(slack.SIGNATURE_HEADER, ""),
    )
    payload = slack.parse_payload(raw, headers.get("content-type", ""))
    if payload.get("type") == "url_verification":
        return JSONResponse({"challenge": payload.get("challenge", "")})
    if kind == "command":
        return JSONResponse(slack.handle_command(ctx, app, payload))
    return JSONResponse(slack.handle_interaction(ctx, app, payload))


# What an operation answers besides 200, every one in the same envelope.
ERRORS = {
    "400": "The input is invalid, or a gate refused a merge (gate_refused)",
    "401": "No credential, or an unknown, expired or revoked token or session",
    "403": "A scope, principal, tenant or autonomy check failed",
    "404": "What it names does not exist",
    "409": "What it would create exists already",
    "500": "shoc is misconfigured or failed",
}
ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "error": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "reasons": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "gate_refused: every reason the failed step gave",
                },
                "stage": {"type": "string", "description": "gate_refused: the step that failed"},
            },
            "required": ["code", "message"],
        }
    },
    "required": ["error"],
}


def openapi_document() -> dict[str, Any]:
    error = {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    paths: dict[str, Any] = {}
    for cap in all_capabilities():
        paths[cap.rest_path] = {
            "post": {
                "operationId": cap.mcp_name,
                "summary": cap.summary,
                "tags": [cap.area],
                "x-shoc-scope": cap.scope,
                "x-shoc-autonomy": cap.autonomy,
                "x-shoc-principals": list(cap.principals),
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": cap.input_schema()}},
                },
                "responses": {
                    "200": {
                        "description": "Result envelope: data, summary, citations",
                        "content": {"application/json": {"schema": cap.output_schema()}},
                    },
                    **{s: {"description": d, "content": error} for s, d in ERRORS.items()},
                },
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "shoc",
            "version": __version__,
            "description": "Headless, AI-first SOC. Every route is generated from the capability registry.",
        },
        "paths": paths,
        "components": {
            "schemas": {"Error": ERROR_SCHEMA},
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"},
                "session": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "shoc_session",
                    "description": "A signed-in browser's session (RFC 0028). The cookie is "
                    "__Host-shoc_session when SHOC_PUBLIC_URL is https",
                },
            },
        },
        "security": [{"bearer": []}, {"session": []}],
    }


def build_app(config: Config | None = None) -> Starlette:
    cfg = config or Config.load()
    routes = [
        Route(cap.rest_path, _handler(cap, cfg), methods=["POST"]) for cap in all_capabilities()
    ]

    async def openapi(_: Request) -> JSONResponse:
        return JSONResponse(openapi_document())

    async def healthz(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    async def index(request: Request) -> JSONResponse:
        """What this is, for whoever just opened it in a browser.

        shoc is headless: there is no UI here and there is not meant to be one.
        This answers the question the 404 was leaving unanswered.
        """
        base = str(request.base_url).rstrip("/")
        return JSONResponse(
            {
                "name": "shoc",
                "version": __version__,
                "description": (
                    "A headless, AI-first SOC. There is no web UI: every capability is "
                    "reachable over REST, MCP, the CLI and Slack. If you are looking for "
                    "screens, use the CLI or point an MCP client at /mcp."
                ),
                "capabilities": len(all_capabilities()),
                "endpoints": {
                    "openapi": f"{base}/v1/openapi.json",
                    "capabilities": f"{base}/v1/capability/list",
                    "mcp": f"{base}/mcp",
                    "health": f"{base}/healthz",
                    "metrics": f"{base}/metrics",
                    "ingest": f"{base}/ingest/{{source}}",
                    "stream": f"{base}/v1/stream",
                },
                "calling_it": {
                    "shape": "POST /v1/<area>/<name> with a JSON body",
                    "example": f'curl -X POST {base}/v1/finding/list -d \'{{"since": "-24h"}}\'',
                    "auth": (
                        "Bearer token once one is issued (token.create or SHOC_TOKENS), or "
                        "a person's session cookie from signing in at /auth/* (browser "
                        "clients); before the first token or account, single-user mode, "
                        "which answers requests addressed to localhost only."
                    ),
                    "answers": "Every response is {data, summary, citations}.",
                },
                "docs": "https://github.com/pwnera/shoc/tree/main/docs",
            }
        )

    async def metrics(request: Request) -> PlainTextResponse | JSONResponse:
        """`metrics.export` as Prometheus scrapes it: a GET, answered in text."""
        cap = get("metrics.export")
        try:
            result = await asyncio.to_thread(lambda: cap.invoke(_context(request, cfg), {}))
        except ShocError as exc:
            return _error(exc)
        except Exception as exc:
            return _error(exc)
        return PlainTextResponse(result.data.text, media_type="text/plain; version=0.0.4")

    async def ingest(request: Request) -> JSONResponse:
        """Vendor push ingest (ING-2): POST /ingest/<source>, as the vendor sends it.

        Only GitHub's organisation webhook today: its signature stands in for
        the bearer token GitHub cannot send, as Slack's does, and the tenant is
        named in the URL (`?tenant=`). Every other source is polled, and records
        loaded by hand go through `events.ingest`.
        """
        from shoc.api.ingest import (
            GITHUB_SIGNATURE_HEADER,
            first_delivery,
            forget_delivery,
            verify_github,
        )
        from shoc.capabilities.registry import get
        from shoc.ingest.connectors import github
        from shoc.ingest.connectors.base import connector_of, mark_push

        cap = get("events.ingest")
        try:
            if _over_limit(request, cfg.max_request_bytes):
                return _too_large(cfg.max_request_bytes)
            source = request.path_params["source"]
            raw = await request.body()
            hub = request.headers.get(GITHUB_SIGNATURE_HEADER)
            if connector_of(source) != "github" or hub is None:
                raise Denied(
                    f"shoc takes no push for '{source}' but GitHub's signed webhook; "
                    "the source is polled"
                )
            ctx = Context(
                tenant_id=request.query_params.get("tenant") or cfg.tenant_id,
                caller=Caller(kind="service", id="github-webhook", scopes=("events:write",)),
                config=cfg,
            )

            def run() -> Any:
                verify_github(ctx.db, ctx.tenant_id, cfg.master_key, raw, hub, source)
                records = github.from_webhook(request.headers, raw)
                delivery = request.headers.get("x-github-delivery", "")
                if records and not first_delivery(
                    ctx.db, ctx.tenant_id, source, delivery, cfg.retention_days
                ):
                    records = []  # a replay: it loaded the first time
                try:
                    result = cap.invoke(ctx, {"source": source, "records": records})
                except Exception:
                    forget_delivery(ctx.db, ctx.tenant_id, source, delivery)
                    raise
                mark_push(ctx.db, ctx.tenant_id, source, result.data.loaded)
                return result

            result = await asyncio.to_thread(run)
            return JSONResponse(result.to_json())
        except ShocError as exc:
            return _error(exc)
        except Exception as exc:
            return _error(exc)

    async def stream(request: Request) -> StreamingResponse | JSONResponse:
        """Server-sent events (API-2). Resume with ?since=<seq> or Last-Event-ID."""
        tail = get("stream.tail")
        try:
            first = _context(request, cfg)  # refuses shoc:all before the stream opens
            caller, tenant = first.caller, first.tenant_id
            tail.check(caller)
            since = request.headers.get("last-event-id") or request.query_params.get("since")
            if since and not (since.isascii() and since.isdigit()):
                raise ValidationError("since must be a sequence number")
        except ShocError as exc:
            return _error(exc)
        types = [t for t in request.query_params.get("types", "").split(",") if t]

        def poll(seq: int) -> list[dict[str, Any]]:
            # A fresh context per poll, like any other capability call: the
            # connection it takes is pinned to the caller's tenant in `Context.db`.
            ctx = Context(tenant_id=tenant, caller=caller, config=cfg)
            return tail.invoke(ctx, {"since_seq": seq, "types": types, "limit": 100}).data.events

        def recheck() -> None:
            # A revoked token, an ended session or a lowered role ends the stream (RFC 0028).
            nonlocal caller
            ctx = _context(request, cfg)
            if ctx.tenant_id != tenant:
                raise Denied("the caller's tenant changed")
            tail.check(ctx.caller)
            caller = ctx.caller

        async def events():
            seq = int(since or 0)
            checked = time.monotonic()
            while True:
                if await request.is_disconnected():
                    return
                if time.monotonic() - checked >= STREAM_RECHECK_SECONDS:
                    try:
                        await asyncio.to_thread(recheck)
                    except ShocError:
                        yield "event: signed_out\ndata: {}\n\n"
                        return
                    checked = time.monotonic()
                rows = await asyncio.to_thread(poll, seq)
                for row in rows:
                    seq = row["seq"]
                    payload = json.dumps(row, default=str)
                    yield f"id: {seq}\nevent: {row['type']}\ndata: {payload}\n\n"
                if not rows:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(2)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    async def slack_command(request: Request) -> JSONResponse:
        return await _slack(request, cfg, "command")

    async def slack_interaction(request: Request) -> JSONResponse:
        return await _slack(request, cfg, "interaction")

    # The MCP server for remote clients. A desktop client uses `shoc mcp` over
    # stdio; this is the same registry behind the same checks. Its session
    # manager runs for the app's lifetime, from the lifespan below.
    from shoc.api.mcp import EXTERNAL_AGENT, session_manager

    manager = session_manager(cfg)

    async def mcp_asgi(scope: Any, receive: Any, send: Any) -> None:
        # Same bearer token and tenant rule as every REST route. The MCP handlers
        # read who is calling from the scope (see `mcp.build_server`).
        try:
            caller, tenant = await asyncio.to_thread(
                authenticate, Headers(scope=scope), cfg.tenant_id, cfg, scope.get("method", "POST")
            )
        except ShocError as exc:
            await _error(exc)(scope, receive, send)
            return
        # Single-user mode is for the person at the keyboard. A model that
        # reaches /mcp without a token stays an external agent.
        scope["shoc.caller"] = EXTERNAL_AGENT if caller is SINGLE_USER else caller
        scope["shoc.tenant"] = tenant
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        stop = threading.Event()
        threading.Thread(
            target=watch_scheduler, args=(cfg, stop, SCHEDULER_CHECK_SECONDS), daemon=True
        ).start()
        try:
            async with manager.run():
                yield
        finally:
            stop.set()

    routes += [
        Route("/", index, methods=["GET"]),
        Mount("/mcp", app=mcp_asgi),
        Route("/slack/commands", slack_command, methods=["POST"]),
        Route("/slack/interactions", slack_interaction, methods=["POST"]),
        Route("/v1/stream", stream, methods=["GET"]),
        Route("/v1/openapi.json", openapi, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/metrics", metrics, methods=["GET"]),
        Route("/ingest/{source}", ingest, methods=["POST"]),
    ]
    routes += signin.routes(cfg)
    return Starlette(routes=routes, lifespan=lifespan)
