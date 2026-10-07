"""Tenant memory: facts a human told us, and what past cases taught us (AGT-4 start).

Postgres rows with full-text search, no vector database until evals justify one
(decision D6). Semantic facts have an expiry, because "the VPN pool is
10.8.0.0/16" stops being true.
"""

from __future__ import annotations

import hashlib
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all

KINDS = ("semantic", "episodic", "correction")


def add(
    conn: Conn,
    tenant_id: str,
    body: str,
    subject: str = "",
    kind: str = "semantic",
    source: str = "human",
    expires_at: Any = None,
    confidence: float = 1.0,
) -> str:
    memory_id = "MEM-" + hashlib.sha256(f"{tenant_id}|{subject}|{body}".encode()).hexdigest()[:20]
    execute(
        conn,
        """INSERT INTO shoc.memory
               (memory_id, tenant_id, kind, subject, body, source, confidence, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (memory_id) DO UPDATE SET
               body = EXCLUDED.body, confidence = EXCLUDED.confidence,
               expires_at = EXCLUDED.expires_at, source = EXCLUDED.source
           -- A person confirming what the crew wrote makes it a person's fact;
           -- the crew repeating a person's fact changes nothing.
           WHERE shoc.memory.source <> 'human' OR EXCLUDED.source = 'human'""",
        (memory_id, tenant_id, kind, subject, body, source, confidence, expires_at),
    )
    return memory_id


def search(conn: Conn, tenant_id: str, query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Full-text search over live facts. An empty query returns the most recent."""
    if not query.strip():
        return fetch_all(
            conn,
            """SELECT memory_id, kind, subject, body, source, confidence, created_at
               FROM shoc.memory
               WHERE tenant_id = %s AND (expires_at IS NULL OR expires_at > now())
               ORDER BY created_at DESC LIMIT %s""",
            (tenant_id, limit),
        )
    return fetch_all(
        conn,
        """SELECT memory_id, kind, subject, body, source, confidence, created_at,
                  ts_rank(search, plainto_tsquery('english', %s)) AS rank
           FROM shoc.memory
           WHERE tenant_id = %s
             AND (expires_at IS NULL OR expires_at > now())
             AND search @@ plainto_tsquery('english', %s)
           ORDER BY rank DESC, created_at DESC LIMIT %s""",
        (query, tenant_id, query, limit),
    )


def context_for(conn: Conn, tenant_id: str, entity: str, limit: int = 8) -> list[dict[str, Any]]:
    """Facts worth putting in front of an agent for this entity."""
    hits = search(conn, tenant_id, entity, limit) if entity else []
    if len(hits) < limit:
        seen = {h["memory_id"] for h in hits}
        hits += [
            m for m in search(conn, tenant_id, "", limit - len(hits)) if m["memory_id"] not in seen
        ]
    return hits[:limit]


def split(facts: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """What people told us, and what the system concluded, as two lists of bodies.

    Only a human principal's fact can settle an explanation. A crew verdict, a
    hunt baseline or an agent's own note is a reading, and quoting it as "the
    company told us" is how one case talked into benign clears the next one.
    """
    told = [str(m["body"]) for m in facts if m.get("source") == "human"]
    concluded = [str(m["body"]) for m in facts if m.get("source") != "human"]
    return told, concluded
