"""Vendor push ingest (ING-2).

shoc polls every source whose vendor offers an API, and takes a push only in
the form the vendor sends it: today that is GitHub's organisation webhook,
signed with `X-Hub-Signature-256`. The source's push key is the webhook secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from shoc.db.pool import Conn, execute, fetch_one
from shoc.errors import Denied

GITHUB_SIGNATURE_HEADER = "X-Hub-Signature-256"


def new_key() -> str:
    return "shoc_push_" + secrets.token_urlsafe(32)


def push_key(conn: Conn, tenant_id: str, source: str, master_key: str) -> str | None:
    """The push key configured for this source, if it has one."""
    from shoc.db.secrets import open_secret

    row = fetch_one(
        conn,
        "SELECT secret FROM shoc.connector_config WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    if not row or not row["secret"]:
        return None
    return open_secret(master_key, row["secret"], tenant_id, "connector_config", source).get(
        "push_key"
    )


def verify_github(
    conn: Conn,
    tenant_id: str,
    master_key: str,
    body: bytes,
    signature: str,
    source: str = "github",
) -> None:
    """Raise `Denied` unless GitHub signed this webhook with the push key (ING-2).

    GitHub cannot send a bearer token, so the signature is the only thing that
    says who sent the request, and a source with no push key accepts nothing.
    The HMAC covers the body alone, with no timestamp; a delivery sent twice
    keeps its delivery id and loads as the same event. A second organisation
    is its own source, `github:<label>`, with its own key.
    """
    key = push_key(conn, tenant_id, source, master_key)
    if not key:
        raise Denied(
            f"no push key for {source}: run `shoc source push-key --source {source}` and "
            "give the key to GitHub as the webhook secret"
        )
    expected = "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise Denied("webhook signature does not match")


def first_delivery(conn: Conn, tenant_id: str, source: str, delivery: str, keep_days: int) -> bool:
    """Record a pushed delivery's id; False when it was seen before (ING-2).

    The signature has no timestamp, so a replay verifies like the original. A
    replayed id loads nothing, whatever its format. Ids older than the event
    retention go: the events they loaded are gone by then too.
    """
    execute(
        conn,
        "DELETE FROM shoc.push_deliveries WHERE tenant_id = %s "
        "AND received_at < now() - make_interval(days => %s)",
        (tenant_id, keep_days),
    )
    return bool(
        fetch_one(
            conn,
            """INSERT INTO shoc.push_deliveries (tenant_id, source, delivery) VALUES (%s, %s, %s)
           ON CONFLICT DO NOTHING RETURNING 1 AS new""",
            (tenant_id, source, delivery),
        )
    )


def forget_delivery(conn: Conn, tenant_id: str, source: str, delivery: str) -> None:
    """A delivery that failed to load may be sent again and must then load."""
    execute(
        conn,
        "DELETE FROM shoc.push_deliveries WHERE tenant_id = %s AND source = %s AND delivery = %s",
        (tenant_id, source, delivery),
    )
