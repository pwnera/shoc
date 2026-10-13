"""The stores, queries and jobs guidelines that need Postgres (DAT-G9).

Each scheduled or polled control-plane read of `shoc.jobs` and
`shoc.stream_events` is planned with sequential scans switched off: a read an
index can serve then uses it, and one no index serves still shows a Seq Scan.
Statements are taken from the functions that send them, with the pool's
helpers replaced by recorders, or read from the function's source where the
function does much else. A read listed in `KNOWN` still scans today: one not
listed fails, and so does a listed one that no longer scans.
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from psycopg import ClientCursor

from shoc import worker
from shoc.agents import ops, reporter
from shoc.capabilities import health
from shoc.db import jobs
from shoc.db.pool import q

pytestmark = pytest.mark.postgres

SCANNED = {"jobs", "stream_events"}

KNOWN_SCANS = {
    "health.status": (
        "counts every job of the tenant in each state, and no index leads with tenant_id "
        "over every state (data-7)"
    ),
}


def _recorded(module: ModuleType, run: Callable[[], Any]) -> list[tuple[str, Any]]:
    """What `run` sends through `module`'s pool helpers, none of it executed."""
    sent: list[tuple[str, Any]] = []

    def fetch_all(conn: Any, sql: str, params: Any = None) -> list[dict[str, Any]]:
        sent.append((sql, params))
        return []

    def fetch_one(conn: Any, sql: str, params: Any = None) -> None:
        sent.append((sql, params))

    def execute(conn: Any, sql: str, params: Any = None) -> int:
        sent.append((sql, params))
        return 0

    fakes = {"fetch_all": fetch_all, "fetch_one": fetch_one, "execute": execute}
    with pytest.MonkeyPatch.context() as mp:
        for name, fake in fakes.items():
            if hasattr(module, name):
                mp.setattr(module, name, fake)
        run()
    return sent


def _written(fn: Callable[..., Any], needle: str) -> str:
    """The one string literal in `fn`'s source that holds `needle`."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    found = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and needle in n.value
    ]
    name = getattr(fn, "__qualname__", fn)
    assert len(found) == 1, f"{name} holds {len(found)} statements with {needle}"
    return found[0]


def _reads(conn: Any, tenant: str) -> list[tuple[str, str, Any]]:
    """(label, statement, params) for each scheduled or polled read of jobs and the stream."""
    out: list[tuple[str, str, Any]] = []
    ctx: Any = SimpleNamespace(db=conn, tenant_id=tenant)
    for label, module, run in (
        ("jobs.tick", jobs, lambda: jobs.tick(conn)),
        ("jobs.claim", jobs, lambda: jobs.claim(conn)),
        ("jobs.seconds_to_next", jobs, lambda: jobs.seconds_to_next(conn, 30)),
        ("jobs.requeue_stale", jobs, lambda: jobs.requeue_stale(conn)),
        ("ops.unpublished", ops, lambda: ops.unpublished(conn, tenant, [])),
        ("health.jobs", health, lambda: health.failed_jobs.fn(ctx, health.JobsQuery())),
    ):
        out += [(label, sql, params) for sql, params in _recorded(module, run)]
    for sql, params in _recorded(worker, lambda: worker.prune(conn, tenant, 90)):
        table = re.search(r"DELETE FROM shoc\.(\w+)", sql)
        out.append((f"worker.prune:{table.group(1) if table else '?'}", sql, params))
    now = datetime.now(UTC)
    out += [
        ("health.status", _written(health.status.fn, "FROM shoc.jobs"), (tenant,)),
        ("ops.alerts", _written(ops.alerts, "FROM shoc.jobs"), (tenant,)),
        (
            "reporter._handover",
            _written(reporter._handover, "FROM shoc.stream_events"),
            (tenant, now - timedelta(hours=12), now),
        ),
    ]
    return out


def _seq_scans(plan: dict[str, Any]) -> list[str]:
    found: list[str] = []
    if plan.get("Node Type") == "Seq Scan" and plan.get("Relation Name") in SCANNED:
        found.append(str(plan["Relation Name"]))
    for child in plan.get("Plans", []):
        found += _seq_scans(child)
    return found


def test_scheduled_reads_use_an_index(conn, config):
    """DAT-G9: every scheduled or polled read of shoc.jobs and shoc.stream_events is
    served by an index a migration created."""
    reads = _reads(conn, config.tenant_id)
    labels = {label for label, _, _ in reads}
    assert {"jobs.tick", "jobs.claim", "jobs.requeue_stale", "health.jobs"} <= labels
    assert {"worker.prune:jobs", "worker.prune:stream_events"} <= labels
    found: dict[str, str] = {}
    for label, statement, params in reads:
        with conn.transaction(), ClientCursor(conn) as cur:
            cur.execute("SET LOCAL enable_seqscan = off")
            cur.execute(q("EXPLAIN (FORMAT JSON) " + statement), params)
            row = cur.fetchone()
        assert row, f"{label} has no plan"
        scans = _seq_scans(row["QUERY PLAN"][0]["Plan"])
        if scans:
            found.setdefault(label, f"Seq Scan on {', '.join(sorted(set(scans)))}")
    new = {k: v for k, v in found.items() if k not in KNOWN_SCANS}
    assert not new, "DAT-G9: " + "; ".join(f"{k}: {v}" for k, v in sorted(new.items()))
    gone = sorted(set(KNOWN_SCANS) - set(found))
    assert not gone, f"DAT-G9: uses an index now, take out of KNOWN_SCANS: {gone}"
