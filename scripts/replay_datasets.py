#!/usr/bin/env python3
"""Replay fetched public datasets into the store, moved forward in time (ING-1, AGT-6).

A public dataset is years old. Retention drops it and every detection window is
relative to now, so replaying it as recorded puts it out of reach. This shifts
each dataset by one offset — the one that lands its newest event on now — so the
spacing between events, which is what a rate or burst rule reads, is unchanged.

The offset is found by mapping the dataset once and taking the latest `time`,
then the same records are mapped again and loaded. Two passes, because the
offset is not known until the whole dataset has been seen.

    python scripts/fetch_dataset.py --dir ~/shoc-datasets
    python scripts/replay_datasets.py --dir ~/shoc-datasets --name okta-attack-data
    python scripts/replay_datasets.py --dir ~/shoc-datasets
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from shoc.config import Config  # noqa: E402
from shoc.ingest import batch as batchwriter  # noqa: E402
from shoc.ingest import ocsf  # noqa: E402
from shoc.ingest.connectors.file import read_records, unwrap  # noqa: E402
from shoc.ingest.replay import shift_time  # noqa: E402
from shoc.store import open_store  # noqa: E402

MANIFEST = ROOT / "datasets" / "manifest.yaml"
CHUNK = 20_000
# Leave room for Postgres to write what we are loading.
DISK_FLOOR_GB = 5
# A published dataset ships a LICENSE and a README beside its records. Name the
# extensions that hold records rather than the ones that do not: the archive is
# the part nobody can enumerate.
RECORD_SUFFIX = {".json", ".ndjson", ".jsonl", ".log", ".gz"}


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield raw records without holding the file in memory.

    The wazuh set ships 670MB NDJSON files, so reading one whole would cost more
    than the box has. NDJSON streams a line at a time; a JSON array or a
    pretty-printed object cannot, and falls back to reading it all.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as fh:  # type: ignore[operator]
        first = fh.readline()
        if not first.strip():
            return
        try:
            head = json.loads(first)
        except json.JSONDecodeError:
            yield from read_records(path)
            return
        yield from unwrap(head)
        for line in fh:
            line = line.strip()
            if line:
                yield from unwrap(json.loads(line))


def files_of(directory: Path) -> list[Path]:
    if directory.is_file():
        return [directory]
    return sorted(
        p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in RECORD_SUFFIX
    )


def mapped(mapping: Any, files: list[Path], tenant: str) -> Iterator[dict[str, Any]]:
    """Every record of every file, mapped to an OCSF row."""
    for path in files:
        try:
            records = iter_records(path)
            for record in records:
                if not isinstance(record, dict):
                    continue
                try:
                    yield mapping.map_record(record, tenant)
                except Exception:  # one bad record is not a bad dataset
                    continue
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            print(f"    skipping unreadable {path.name}: {type(exc).__name__}")


def newest(rows: Iterator[dict[str, Any]], cut: str) -> tuple[str | None, int, int]:
    """The latest real timestamp in the dataset, and how many records lack one.

    A record the mapping reads no time from is stamped with the ingest time. One
    of those makes the dataset look like it ends today, the offset comes out as
    zero, and nothing moves — so anything at or after `cut` is counted as
    undated rather than used as the anchor.
    """
    hi, n, undated = None, 0, 0
    for row in rows:
        n += 1
        t = row.get("time")
        if not t:
            continue
        if t >= cut:
            undated += 1
            continue
        if hi is None or t > hi:
            hi = t
    return hi, n, undated


def free_gb() -> float:
    return shutil.disk_usage("/").free / 1e9


def replay(entry: dict[str, Any], root: Path, cfg: Config, margin_hours: int, dry: bool) -> None:
    name, source = entry["name"], entry["source"]
    directory = root / name
    if entry.get("replay_subdir") and (directory / entry["replay_subdir"]).exists():
        directory = directory / entry["replay_subdir"]
    if not directory.exists():
        print(f"{name}: not fetched, skipping")
        return
    try:
        mapping = ocsf.load_mapping(source)
    except Exception as exc:
        print(f"{name}: no mapping for source '{source}' ({exc}), skipping")
        return

    files = files_of(directory)
    tenant = cfg.tenant_id
    print(f"{name}: {len(files)} file(s), mapping '{source}'")

    cut = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    latest, seen, undated = newest(mapped(mapping, files, tenant), cut)
    if undated:
        print(f"  {undated} of {seen} record(s) carry no timestamp the mapping reads")
    if not latest:
        print(f"  no timestamped records in {seen}, skipping")
        return
    anchor = datetime.now(UTC) - timedelta(hours=margin_hours)
    offset = (anchor - datetime.fromisoformat(latest)).total_seconds()
    print(f"  {seen} record(s); newest {latest[:19]} -> {anchor.isoformat()[:19]}")
    print(f"  shift {offset / 86400:.0f} day(s)")
    if dry:
        return

    store = open_store(cfg, tenant)
    loaded, chunk = 0, []
    try:
        for row in mapped(mapping, files, tenant):
            # An undated record was stamped with the ingest time, not its own.
            # Moving that by the dataset's offset would put it in the future.
            if row.get("time") and row["time"] < cut:
                row["time"] = shift_time(row["time"], offset)
            chunk.append(row)
            if len(chunk) >= CHUNK:
                loaded += batchwriter.load(store, chunk).rows
                chunk = []
                print(f"    {loaded} loaded, {free_gb():.1f}GB free")
                if free_gb() < DISK_FLOOR_GB:
                    print(f"  stopping: under {DISK_FLOOR_GB}GB free")
                    return
        if chunk:
            loaded += batchwriter.load(store, chunk).rows
    finally:
        store.close()
    print(f"  loaded {loaded}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="where fetch_dataset.py put the files")
    parser.add_argument("--name", default="", help="one dataset from the manifest")
    parser.add_argument("--source", default="", help="every dataset for one shoc source")
    parser.add_argument(
        "--margin-hours", type=int, default=2, help="land the newest event this long before now"
    )
    parser.add_argument("--dry-run", action="store_true", help="report the shift, load nothing")
    args = parser.parse_args()

    entries = yaml.safe_load(MANIFEST.read_text())["datasets"]
    if args.name:
        entries = [e for e in entries if e["name"] == args.name]
    elif args.source:
        entries = [e for e in entries if e["source"] == args.source]
    if not entries:
        print("nothing in the manifest matches", file=sys.stderr)
        return 1

    cfg = Config.load()
    for entry in entries:
        if free_gb() < DISK_FLOOR_GB:
            print(f"under {DISK_FLOOR_GB}GB free, stopping")
            return 1
        try:
            replay(entry, Path(args.dir), cfg, args.margin_hours, args.dry_run)
        except Exception as exc:
            print(f"{entry['name']}: FAILED {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
