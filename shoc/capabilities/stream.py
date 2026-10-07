"""Event stream capabilities (API-2).

Every state change is an event: a finding, a case, an openspace message, a source
going quiet. Clients subscribe instead of polling — over SSE for a live view, or
as a signed webhook for a service. `stream.tail` is the same feed as a plain
call, so a script can catch up after a restart with a sequence number.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import Conn, execute, fetch_all
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json

SIGNATURE_HEADER = "X-Shoc-Signature"
TIMESTAMP_HEADER = "X-Shoc-Timestamp"


@dataclass
class TailInput:
    since_seq: int = f(0, doc="Return events after this sequence number")
    types: list[str] = f(doc="Only these event types, e.g. ['case.opened']", factory=list)
    limit: int = f(100, doc="Maximum events, capped at 500")


@dataclass
class EventPage:
    events: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    last_seq: int = 0
    latest_seq: int = 0


def read_events(
    conn: Conn, tenant_id: str, since_seq: int = 0, types: list[str] | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s", "seq > %(since_seq)s"]
    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "since_seq": since_seq,
        "limit": max(1, min(limit, 500)),
    }
    if types:
        where.append("type = ANY(%(types)s)")
        params["types"] = list(types)
    return fetch_all(
        conn,
        f"SELECT seq, type, subject, payload, created_at FROM shoc.stream_events "
        f"WHERE {' AND '.join(where)} ORDER BY seq LIMIT %(limit)s",
        params,
    )


@capability(
    name="stream.tail",
    summary="Read events since a sequence number: findings, cases, openspace messages, health",
    input=TailInput,
    output=EventPage,
    scope="stream:read",
    tags=("stream", "read"),
)
def tail(ctx: Context, inp: TailInput) -> Result:
    from shoc.db.pool import fetch_one

    rows = read_events(ctx.db, ctx.tenant_id, inp.since_seq, inp.types, inp.limit)
    last = rows[-1]["seq"] if rows else inp.since_seq
    # `latest_seq` is where the stream is right now, so a client that only wants
    # what happens next can start there instead of replaying the history.
    head = fetch_one(
        ctx.db,
        "SELECT coalesce(max(seq), 0) AS seq FROM shoc.stream_events WHERE tenant_id = %s",
        (ctx.tenant_id,),
    )
    latest = int((head or {}).get("seq") or 0)
    return Result(
        data=EventPage(
            events=[to_json(r) for r in rows],
            count=len(rows),
            last_seq=last,
            latest_seq=latest,
        ),
        summary=f"{len(rows)} event(s); resume from seq {last} of {latest}.",
        citations=[r["subject"] for r in rows if r["subject"]],
    )


@dataclass
class WebhookInput:
    url: str = f(doc="Where to POST events")
    types: list[str] = f(doc="Event types to send; empty means all", factory=list)
    enabled: bool = f(True, doc="Whether to deliver to it")


@dataclass
class WebhookResult:
    webhook_id: str = ""
    url: str = ""
    secret: str = ""
    types: list[str] = field(default_factory=list)


@capability(
    name="stream.subscribe",
    summary="Register a signed webhook for events",
    input=WebhookInput,
    output=WebhookResult,
    scope="stream:write",
    principals=("human",),
    audit=True,
    tags=("stream", "write"),
)
def subscribe(ctx: Context, inp: WebhookInput) -> Result:
    from shoc.db.secrets import seal

    if not inp.url.startswith(("http://", "https://")):
        from shoc.errors import ValidationError

        raise ValidationError("a webhook url must be http or https")
    webhook_id = "WH-" + hashlib.sha256(f"{ctx.tenant_id}|{inp.url}".encode()).hexdigest()[:16]
    secret = secrets.token_urlsafe(32)
    # A new subscriber starts at the head of the stream. Subscribing the same
    # url again replaces its secret, the one returned here, and keeps its place.
    execute(
        ctx.db,
        """INSERT INTO shoc.webhooks (webhook_id, tenant_id, url, secret, types, enabled, last_seq)
           VALUES (%s,%s,%s,%s,%s,%s,
                   (SELECT coalesce(max(seq), 0) FROM shoc.stream_events WHERE tenant_id = %s))
           ON CONFLICT (webhook_id) DO UPDATE SET
               secret = EXCLUDED.secret, types = EXCLUDED.types, enabled = EXCLUDED.enabled""",
        (
            webhook_id,
            ctx.tenant_id,
            inp.url,
            seal(ctx.config.master_key, {"secret": secret}, ctx.tenant_id, "webhooks", webhook_id),
            list(inp.types),
            inp.enabled,
            ctx.tenant_id,
        ),
    )
    return Result(
        data=WebhookResult(
            webhook_id=webhook_id, url=inp.url, secret=secret, types=list(inp.types)
        ),
        summary=(
            f"Webhook {webhook_id} registered. Verify each delivery with the "
            f"{SIGNATURE_HEADER} header; the secret is shown once."
        ),
    )


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over `timestamp.body`, the same shape Stripe and GitHub use."""
    payload = timestamp.encode() + b"." + body
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def deliver(conn: Conn, tenant_id: str, master_key: str, limit: int = 50) -> int:
    """Send each enabled webhook the events after its cursor. Called by the worker.

    The cursor moves only when the subscriber answers 2xx, so a failed batch is
    sent again on the next run: delivery is at least once.
    """
    import httpx

    from shoc.db.audit import chain_head
    from shoc.db.secrets import open_secret

    hooks = fetch_all(
        conn,
        "SELECT webhook_id, url, secret, types, last_seq FROM shoc.webhooks "
        "WHERE tenant_id=%s AND enabled",
        (tenant_id,),
    )
    if not hooks:
        return 0
    head = chain_head(conn, tenant_id)
    sent = 0
    with httpx.Client(timeout=15.0) as http:
        for hook in hooks:
            events = read_events(conn, tenant_id, int(hook["last_seq"]), hook["types"], limit)
            if not events:
                continue
            secret = open_secret(
                master_key, hook["secret"], tenant_id, "webhooks", hook["webhook_id"]
            ).get("secret", "")
            # The audit chain's head goes out signed with every delivery, so a
            # copy lives outside Postgres for `health.audit --head` (SEC-1).
            body = json.dumps({"events": to_json(events), "audit_head": head}, default=str).encode()
            timestamp = str(int(time.time()))
            try:
                resp = http.post(
                    hook["url"],
                    content=body,
                    headers={
                        "content-type": "application/json",
                        TIMESTAMP_HEADER: timestamp,
                        SIGNATURE_HEADER: sign(secret, timestamp, body),
                    },
                )
                resp.raise_for_status()
                execute(
                    conn,
                    "UPDATE shoc.webhooks SET last_ok_at=now(), last_error=NULL, last_seq=%s "
                    "WHERE webhook_id=%s",
                    (events[-1]["seq"], hook["webhook_id"]),
                )
                sent += len(events)
            except Exception as exc:  # a broken subscriber is health, not an outage
                execute(
                    conn,
                    "UPDATE shoc.webhooks SET last_error=%s WHERE webhook_id=%s",
                    (f"{type(exc).__name__}: {exc}"[:500], hook["webhook_id"]),
                )
    return sent


@dataclass
class DeliverInput:
    """Each webhook resumes from its own cursor (API-2)."""


@dataclass
class Delivery:
    sent: int = 0


@capability(
    name="stream.deliver",
    summary="Send pending events to every enabled webhook",
    input=DeliverInput,
    output=Delivery,
    scope="stream:deliver",
    principals=("human", "service"),
    audit=True,
    tags=("stream", "write"),
)
def deliver_now(ctx: Context, inp: DeliverInput) -> Result:
    sent = deliver(ctx.db, ctx.tenant_id, ctx.config.master_key)
    return Result(
        data=Delivery(sent=sent), summary=f"stream: delivered {sent} event(s) to webhooks"
    )
