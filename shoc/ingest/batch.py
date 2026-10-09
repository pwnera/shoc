"""Batch writer: NDJSON.gz on local disk, then one COPY into the store.

No object store and no streaming inserts (decision D6). A batch file is deleted
once the store reports it loaded, and kept on failure so it can be replayed.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import tempfile
import time
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from shoc.store.base import EventStore, LoadStats

log = logging.getLogger("shoc.ingest.batch")

# Below this share of distinct event_uids, the batch is not a batch of events:
# the mapping is reading a field that does not identify one.
UID_FLOOR = 0.9


def write_batch(rows: Iterable[dict[str, Any]], directory: str | None = None) -> tuple[Path, int]:
    """Write OCSF rows as gzipped NDJSON. Returns (path, row count)."""
    base = Path(directory or tempfile.gettempdir()) / "shoc-batches"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"batch-{int(time.time() * 1000)}-{os.getpid()}.ndjson.gz"
    count = 0
    uids: set[str] = set()
    with gzip.open(path, "wt") as fh:
        for row in rows:
            fh.write(json.dumps(row, default=str))
            fh.write("\n")
            count += 1
            uids.add(str(row.get("event_uid")))
    # Rows deduplicate on (event_uid, time), so a mapping pointed at a field that
    # repeats silently throws events away. Say so instead.
    if count > 10 and len(uids) < count * UID_FLOOR:
        log.warning(
            "batch of %d rows carries only %d distinct event_uid(s): the mapping is "
            "reading a field that does not identify an event",
            count,
            len(uids),
        )
    return path, count


def read_unique(path: str) -> list[dict[str, Any]]:
    """A batch's rows, each (event_uid, time) once, first copy kept.

    A warehouse has no primary key to drop a repeat inside one batch.
    """
    opener = gzip.open if str(path).endswith(".gz") else open
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    with opener(path, "rt") as fh:  # type: ignore[operator]
        for line in fh:
            if line.strip():
                row = json.loads(line)
                seen.setdefault((str(row.get("event_uid")), str(row.get("time"))), row)
    return list(seen.values())


# How long a recorded load is kept: a detection cycle can prove that nothing
# of a product was loaded since a time no older than this.
KEPT = timedelta(days=7)


def loaded(conn: Any, tenant_id: str, rows: Iterable[dict[str, Any]] = ()) -> None:
    """Record a committed load: its products, and the oldest `ingested_at` among its rows.

    The newest load of a product lets a cycle skip the rules over it that have
    read everything since (D71, D149); the oldest stamp lets a cycle read a load
    that committed after its watermark had passed the events' stamps (DET-3).
    Loads older than `KEPT` are pruned.
    """
    from shoc.db.pool import execute

    rows = list(rows)
    stamps = [str(r["ingested_at"]) for r in rows if r.get("ingested_at")]
    oldest = min(stamps, key=lambda s: datetime.fromisoformat(s)) if stamps else None
    # Without its rows a load could hold anything: NULL counts for every product.
    products = (
        sorted({str(r["metadata_product"]).lower() for r in rows if r.get("metadata_product")})
        if rows
        else None
    )
    execute(
        conn,
        """INSERT INTO shoc.store_loads (tenant_id, loaded_at, stamped_from, products)
           VALUES (%s, now(), %s, %s)""",
        (tenant_id, oldest, products),
    )
    execute(
        conn,
        "DELETE FROM shoc.store_loads WHERE tenant_id = %s AND loaded_at < now() - %s",
        (tenant_id, KEPT),
    )


def load(store: EventStore, rows: Iterable[dict[str, Any]], keep: bool = False) -> LoadStats:
    path, count = write_batch(rows)
    if count == 0:
        path.unlink(missing_ok=True)
        return LoadStats()
    stats = store.load_batch(str(path))
    if not keep:
        path.unlink(missing_ok=True)
    return stats
