"""The world graph (AGT-4): who and what this company is made of.

Two tables and SQL, no graph database (decision D6). Nodes are the typed
entities the detection engine already produces — users, keys, addresses,
resources, accounts — and an edge means "these appeared in the same event".
Walks are capped at three hops, which is as far as this kind of evidence stays
meaningful anyway.

The graph is rebuilt from events, so it is always a description of what
actually happened rather than an inventory somebody forgot to update.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all
from shoc.detect.engine import ENTITY_COLUMNS
from shoc.store import ocsf as layout
from shoc.store.base import EventStore

MAX_HOPS = 3
# The most events one rebuild reads, newest first. A busier window is cut here,
# and the stats say so.
MAX_EVENTS = 20_000


@dataclass
class GraphStats:
    nodes: int = 0
    edges: int = 0
    events_read: int = 0
    window_days: int = 0
    # True when the window held more than `limit` events: the graph then
    # describes the newest `limit` of them, not the whole window.
    truncated: bool = False
    limit: int = MAX_EVENTS


def refresh(
    conn: Conn, store: EventStore, tenant_id: str, days: int = 30, limit: int = MAX_EVENTS
) -> GraphStats:
    """Rebuild the graph from the last `days` of events."""
    since = datetime.now(UTC) - timedelta(days=days)
    columns = ", ".join(["time", *ENTITY_COLUMNS])
    read = store.query(
        f"SELECT {columns} FROM {layout.EVENTS_TABLE} "
        "WHERE tenant_id = :tenant_id AND time >= :since ORDER BY time DESC",
        {"tenant_id": tenant_id, "since": since},
        limit,
    )
    rows = read.rows

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        present = [
            (f"{prefix}:{row[column]}", prefix, str(row[column]))
            for column, prefix in ENTITY_COLUMNS.items()
            if row.get(column) not in (None, "", "-")
        ]
        when = row["time"]
        for node_id, kind, label in present:
            node = nodes.setdefault(
                node_id,
                {"kind": kind, "label": label, "events": 0, "first": when, "last": when},
            )
            node["events"] += 1
            node["first"] = min(node["first"], when)
            node["last"] = max(node["last"], when)
        for i, (a, _k, _l) in enumerate(present):
            for b, _k2, _l2 in present[i + 1 :]:
                key = (a, b) if a < b else (b, a)
                edge = edges.setdefault(key, {"weight": 0, "first": when, "last": when})
                edge["weight"] += 1
                edge["first"] = min(edge["first"], when)
                edge["last"] = max(edge["last"], when)

    for node_id, node in nodes.items():
        execute(
            conn,
            """INSERT INTO shoc.graph_nodes
                   (tenant_id, node_id, kind, label, events, first_seen, last_seen)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, node_id) DO UPDATE SET
                   events = EXCLUDED.events,
                   first_seen = LEAST(shoc.graph_nodes.first_seen, EXCLUDED.first_seen),
                   last_seen = GREATEST(shoc.graph_nodes.last_seen, EXCLUDED.last_seen)""",
            (
                tenant_id,
                node_id,
                node["kind"],
                node["label"],
                node["events"],
                node["first"],
                node["last"],
            ),
        )
    for (src, dst), edge in edges.items():
        execute(
            conn,
            """INSERT INTO shoc.graph_edges (tenant_id, src, dst, weight, first_seen, last_seen)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, src, dst, kind) DO UPDATE SET
                   weight = EXCLUDED.weight,
                   first_seen = LEAST(shoc.graph_edges.first_seen, EXCLUDED.first_seen),
                   last_seen = GREATEST(shoc.graph_edges.last_seen, EXCLUDED.last_seen)""",
            (tenant_id, src, dst, edge["weight"], edge["first"], edge["last"]),
        )
    return GraphStats(
        nodes=len(nodes),
        edges=len(edges),
        events_read=len(rows),
        window_days=days,
        truncated=read.truncated,
        limit=limit,
    )


@dataclass
class Neighbourhood:
    root: str = ""
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    hops: int = 1


def neighbours(
    conn: Conn, tenant_id: str, node_id: str, hops: int = 2, limit: int = 100
) -> Neighbourhood:
    """Walk out from a node, up to three hops, widest edges first."""
    hops = max(1, min(int(hops), MAX_HOPS))
    rows = fetch_all(
        conn,
        """WITH RECURSIVE walk(node, depth) AS (
               SELECT %(root)s::text, 0
               UNION
               SELECT CASE WHEN e.src = w.node THEN e.dst ELSE e.src END, w.depth + 1
               FROM walk w
               JOIN shoc.graph_edges e
                 ON e.tenant_id = %(tenant_id)s AND (e.src = w.node OR e.dst = w.node)
               WHERE w.depth < %(hops)s
           )
           SELECT DISTINCT n.node_id, n.kind, n.label, n.events, n.first_seen, n.last_seen,
                  min(w.depth) AS depth
           FROM walk w
           JOIN shoc.graph_nodes n ON n.tenant_id = %(tenant_id)s AND n.node_id = w.node
           GROUP BY n.node_id, n.kind, n.label, n.events, n.first_seen, n.last_seen
           ORDER BY depth, n.events DESC
           LIMIT %(limit)s""",
        {"root": node_id, "tenant_id": tenant_id, "hops": hops, "limit": limit},
    )
    found = {r["node_id"] for r in rows}
    links = fetch_all(
        conn,
        """SELECT src, dst, kind, weight, last_seen FROM shoc.graph_edges
           WHERE tenant_id = %s AND src = ANY(%s) AND dst = ANY(%s)
           ORDER BY weight DESC LIMIT %s""",
        (tenant_id, list(found), list(found), limit * 4),
    )
    return Neighbourhood(root=node_id, nodes=rows, edges=links, hops=hops)
