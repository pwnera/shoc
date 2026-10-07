#!/usr/bin/env python3
"""Pull the raw records out of a Splunk CSV export (ING-3).

Some published datasets are Splunk exports rather than provider output: the
original event sits JSON-encoded in one column, wrapped in Splunk's own `_raw`,
`_time` and index fields. This writes that column back out as NDJSON, so the
records are raw again and the OCSF mapping sees what the API would have sent.

    python scripts/unwrap_splunk_csv.py auditrecords.csv --column AuditData --out ual.ndjson
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# A single audit record with a large payload runs past the default field limit.
csv.field_size_limit(10_000_000)


def unwrap(source: Path, column: str, out: Path) -> tuple[int, int]:
    kept = skipped = 0
    with source.open(newline="") as fh, out.open("w") as dst:
        reader = csv.DictReader(fh)
        if reader.fieldnames and column not in reader.fieldnames:
            raise SystemExit(
                f"{source} has no '{column}' column (columns: {', '.join(reader.fieldnames[:8])}…)"
            )
        for row in reader:
            blob = (row.get(column) or "").strip()
            if not blob:
                skipped += 1
                continue
            try:
                record = json.loads(blob)
            except json.JSONDecodeError:
                skipped += 1
                continue
            dst.write(json.dumps(record) + "\n")
            kept += 1
    return kept, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    parser.add_argument("--column", default="_raw", help="the column holding the record")
    parser.add_argument("--out", default="", help="where to write NDJSON (default: alongside)")
    args = parser.parse_args()
    source = Path(args.csv_path)
    if not source.exists():
        print(f"{source} is not there", file=sys.stderr)
        return 1
    out = Path(args.out) if args.out else source.with_suffix(".ndjson")
    kept, skipped = unwrap(source, args.column, out)
    print(f"{out}: {kept} record(s) unwrapped, {skipped} row(s) without a usable payload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
