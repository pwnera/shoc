"""File connector: replay NDJSON or JSON records from disk.

Used by the quick start, by `evals/` and by the conformance suite, so a scenario
can be reproduced without any cloud credentials. It also reads the public raw
datasets in `datasets/` (see `docs/datasets.md`), which is why it unwraps the
envelope providers put around an export.
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult
from shoc.ingest.replay import expand, has_shapes

log = logging.getLogger("shoc.ingest.file")

# What providers call the list inside an exported file: CloudTrail writes
# {"Records": […]}, Graph and Azure {"value": […]}, Cloud Logging {"entries": […]}.
ENVELOPES = ("Records", "value", "entries", "items", "data", "alerts", "activities")


def unwrap(payload: Any) -> list[dict[str, Any]]:
    """A single object that only carries a list of events is that list."""
    if isinstance(payload, list):
        return list(payload)
    if isinstance(payload, dict):
        for key in ENVELOPES:
            if isinstance(payload.get(key), list):
                return list(payload[key])
    return [payload]


def read_records(path: Path) -> list[dict[str, Any]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as fh:  # type: ignore[operator]
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        return list(json.loads(stripped))
    if stripped.startswith("{"):
        # One object, pretty-printed or not — unless it is NDJSON, where only the
        # first line parses, and the loop below is right.
        try:
            return unwrap(json.loads(stripped))
        except json.JSONDecodeError:
            pass
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            records.extend(unwrap(json.loads(line)))
    return records


class FileConnector:
    source = "file"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        path = Path(settings.get("path", ""))
        if not path.exists():
            raise ConfigError(f"file connector: no such path '{path}'")
        paths = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        # One file per page: a public dataset can be hundreds of megabytes across
        # hundreds of files, and re-reading all of them for every page would make
        # a replay slower than the incident.
        index, offset = int(cursor.get("file", 0)), int(cursor.get("offset", 0))
        records: list[dict[str, Any]] = []
        while index < len(paths):
            try:
                records = read_records(paths[index])
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                # A published dataset can carry a stray file that is not records
                # at all — a Splunk key=value export among the JSON. Strict by
                # default, because usually that means the wrong path.
                if not settings.get("skip_unreadable"):
                    raise
                log.warning("file connector: skipping unreadable %s", paths[index])
                index, offset = index + 1, 0
                continue
            # A recorded scenario (records carrying `_repeat`, no timestamps) is
            # replayed as if it were happening now, unless the caller asked for
            # the file exactly as recorded.
            if has_shapes(records) and not settings.get("as_recorded"):
                records = expand(
                    records, settings.get("mapping", "aws_cloudtrail"), spread_seconds=300
                )
            if offset < len(records):
                break
            index, offset = index + 1, 0
        else:
            return FetchResult(records=[], cursor={"file": index, "offset": 0}, more=False)
        page = records[offset : offset + limit]
        new_offset = offset + len(page)
        return FetchResult(
            records=page,
            cursor={"file": index, "offset": new_offset, "total": len(records)},
            more=new_offset < len(records) or index + 1 < len(paths),
        )


CONNECTOR = FileConnector()
