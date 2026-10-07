"""Cloudflare traffic and Zero Trust logs from a Logpush bucket (ING-1).

Logpush is the route Cloudflare documents for a SIEM. Each job pushes one
dataset as gzipped NDJSON to a bucket, Cloudflare R2 or AWS S3, under the path
its `destination_conf` names. With the `{DATE}` placeholder Cloudflare
recommends, a batch lands at `<path>/<YYYYMMDD>/<start>_<end>_<random>.log.gz`,
where `<start>` and `<end>` (`20260930T120000Z`) bound the batch's event times.

`datasets` maps each dataset to its job's path: `logs/http` stands for
`logs/http/{DATE}`, and a path holding `{DATE}` itself (`logs/http/date={DATE}`)
is taken as written. Each dataset keeps its own place. Keys sort by the batch's
start time, so a listing resumes after the last key read less OVERLAP, as
`cloudtrail_s3` does, and keys already read inside that window are kept in the
cursor. Every record is tagged `_dataset` for the mapping.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import OVERLAP, FetchResult, client
from shoc.ingest.connectors.cloudtrail_s3 import Bucket


def template(path: str) -> str:
    path = path.strip("/")
    return path if "{DATE}" in path else f"{path}/{{DATE}}"


def mark(path: str, when: datetime) -> str:
    """The key of a batch starting at `when`, without its end and suffix."""
    return f"{path.replace('{DATE}', f'{when:%Y%m%d}')}/{when:%Y%m%dT%H%M%SZ}"


def started(key: str) -> datetime:
    stamp = key.rsplit("/", 1)[-1].split("_", 1)[0]
    return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


class CloudflareLogsConnector:
    source = "cloudflare_logs"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        datasets: dict[str, str] = settings.get("datasets") or {}
        if not settings.get("bucket") or not datasets:
            raise ConfigError("cloudflare_logs: settings need bucket and datasets")
        if not secret.get("access_key_id") or not secret.get("secret_access_key"):
            raise ConfigError(
                "cloudflare_logs: the secret needs access_key_id and secret_access_key"
            )
        name = str(settings["bucket"])
        if settings.get("account_id"):
            # R2 signs with region `auto`.
            host = f"{settings['account_id']}.r2.cloudflarestorage.com"
            bucket = Bucket(name, "auto", secret, endpoint=host)
        else:
            region = settings.get("bucket_region") or cursor.get("bucket_region") or "us-east-1"
            bucket = Bucket(name, str(region), secret)
        start = datetime.now(UTC) - timedelta(hours=int(settings.get("backfill_hours", 24)))
        state = dict(cursor.get("datasets") or {})
        records: list[dict[str, Any]] = []
        with client() as http:
            # Datasets still paging go first.
            todo = [d for d in datasets if (state.get(d) or {}).get("more")] or list(datasets)
            for dataset in todo:
                path = template(datasets[dataset])
                mine = state.get(dataset) or {"after": mark(path, start), "seen": []}
                if len(records) >= limit:
                    state[dataset] = {**mine, "more": True}
                    continue
                after, seen = str(mine["after"]), set(mine["seen"])
                keys, _, more = bucket.list(http, path.split("{DATE}")[0], after)
                for key in keys:
                    if key in seen or not key.endswith(".gz"):
                        continue
                    try:
                        when = started(key)
                    except ValueError:
                        continue  # not a Logpush batch
                    if len(records) >= limit:
                        more = True
                        break
                    body = bucket.get(http, key)
                    # httpx has already inflated an object stored with Content-Encoding: gzip.
                    if body[:2] == b"\x1f\x8b":
                        body = gzip.decompress(body)
                    records += [
                        {**json.loads(line), "_dataset": dataset}
                        for line in body.splitlines()
                        if line.strip()
                    ]
                    after = max(after, mark(path, when - OVERLAP))
                    seen = {k for k in seen | {key} if k > after}
                state[dataset] = {"after": after, "seen": sorted(seen), "more": more}
        more = any(state[d]["more"] for d in todo)
        cursor = {"datasets": state}
        if not settings.get("account_id"):
            cursor["bucket_region"] = bucket.region
        return FetchResult(records=records, cursor=cursor, more=more)


CONNECTOR = CloudflareLogsConnector()
