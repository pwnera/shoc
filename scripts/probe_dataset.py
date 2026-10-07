#!/usr/bin/env python3
"""Map a fetched dataset through its OCSF mapping and report what landed (ING-3).

A mapping is only right if it survives real records. This maps a dataset without
a database anywhere near it and prints how much of each column got filled, plus
the source keys nothing consumed — which is where the next missing path usually
hides.

    python scripts/fetch_dataset.py --name google-workspace-invictus
    python scripts/probe_dataset.py --name google-workspace-invictus
    python scripts/probe_dataset.py --path var/datasets/x --source okta
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shoc.ingest import ocsf  # noqa: E402
from shoc.ingest.connectors.file import read_records  # noqa: E402

REPORTED = (
    "time",
    "api_operation",
    "actor_user_name",
    "src_endpoint_ip",
    "resource_uid",
    "status",
)


def rows_of(source: str, path: Path, limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    mapping = ocsf.load_mapping(source)
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    for file in files:
        if len(rows) >= limit:
            break
        try:
            records = read_records(file)
        except Exception as exc:
            problems.append(f"{file.name}: unreadable ({type(exc).__name__})")
            continue
        for record in records[: limit - len(rows)]:
            if not isinstance(record, dict):
                problems.append(f"{file.name}: a record is {type(record).__name__}, not an object")
                continue
            try:
                rows.append(mapping.map_record(record, "probe"))
            except Exception as exc:
                problems.append(f"{file.name}: {type(exc).__name__}: {exc}")
    return rows, problems


def report(name: str, rows: list[dict[str, Any]], problems: list[str]) -> None:
    if not rows:
        print(f"{name}: nothing mapped. {problems[:2]}")
        return
    total = len(rows)
    filled = " ".join(
        f"{column}={round(100 * sum(1 for r in rows if r.get(column)) / total)}%"
        for column in REPORTED
    )
    unmapped: Counter[str] = Counter()
    for row in rows[:1000]:
        unmapped.update((row.get("unmapped") or {}).keys())
    unique = len({row["event_uid"] for row in rows})
    print(f"{name}: {total} record(s) mapped, {unique} distinct event_uid")
    print(f"  filled: {filled}")
    if unique < total * 0.9:
        print(
            "  WARNING: rows deduplicate on (event_uid, time), so this mapping is "
            "throwing events away — it is reading a field that does not identify an event"
        )
    print(f"  unmapped keys: {', '.join(k for k, _ in unmapped.most_common(8)) or 'none'}")
    if problems:
        print(f"  {len(problems)} problem(s): {problems[:3]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="", help="a dataset from datasets/manifest.yaml")
    parser.add_argument("--path", default="", help="a file or directory of records")
    parser.add_argument("--source", default="", help="which mapping to use with --path")
    parser.add_argument("--dir", default=str(ROOT / "var" / "datasets"))
    parser.add_argument("--limit", type=int, default=4000)
    args = parser.parse_args()

    if args.name:
        from scripts.fetch_dataset import load

        entries = {e["name"]: e for e in load()}
        entry = entries.get(args.name)
        if not entry:
            print(f"no dataset named '{args.name}'", file=sys.stderr)
            return 1
        path = Path(args.dir) / args.name
        if entry.get("replay_subdir"):
            path = path / entry["replay_subdir"]
        source = entry["source"]
    else:
        if not (args.path and args.source):
            print("give --name, or --path with --source", file=sys.stderr)
            return 1
        path, source = Path(args.path), args.source
    if not path.exists():
        print(f"{path} is not there; fetch it first", file=sys.stderr)
        return 1
    rows, problems = rows_of(source, path, args.limit)
    report(f"{path.name} as {source}", rows, problems)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
