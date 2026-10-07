"""SentinelOne Cloud Funnel 2.0 telemetry from the customer's S3 bucket (ING-1).

Cloud Funnel is SentinelOne's documented way to hand EDR telemetry to a SIEM:
it writes gzipped NDJSON objects into a bucket the customer owns, under
`s1/cloud_funnel/YYYY/MM/DD/account_id=<account>/`. shoc lists that prefix and
reads each object, with s3:ListBucket and s3:GetObject; `prefix` replaces
`s1/cloud_funnel` for a bucket laid out differently.

The day comes before the account in the key, so one listing walks every
account. SentinelOne does not document how object names sort inside a day, so
the cursor resumes at the start of the newest day it read, or the day before
for OVERLAP after midnight, and keeps the keys already read since then. A file
written later that sorts earlier is still found, and none is read twice.
`backfill_hours` therefore rounds down to the start of a day.

Records are flat dotted keys (`src.process.name`). The mapping engine splits a
path on dots, so `nest` turns each record into nested objects before it is
handed on. A key that is also a prefix of another, `winEventLog.description`
beside `winEventLog.description.userid`, keeps its value under `_value`.

Cloud Funnel is large: every process, file, registry, module and cross-process
event of every endpoint. `event_categories` keeps the categories a rule or a
hunt reads, by default `DEFAULT_CATEGORIES`, which leaves out the four that
make up most of the volume and are mostly the operating system talking to
itself; `all` keeps everything. The filter drops records after download, so to
send less, narrow the stream in SentinelOne's Cloud Funnel settings as well.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import OVERLAP, FetchResult, client
from shoc.ingest.connectors.cloudtrail_s3 import Bucket

PREFIX = "s1/cloud_funnel"
DEFAULT_CATEGORIES = (
    "process",
    "command_script",
    "logins",
    "scheduled_task",
    "driver",
    "dns",
    "ip",
    "url",
    "indicators",
    "threat_intelligence_indicators",
    "windows_event_logs",
)
LEAF = "_value"


class SentinelOneCloudFunnelConnector:
    source = "sentinelone_cloudfunnel"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        if not settings.get("bucket"):
            raise ConfigError("sentinelone_cloudfunnel: settings need bucket")
        if not secret.get("access_key_id") or not secret.get("secret_access_key"):
            raise ConfigError(
                "sentinelone_cloudfunnel: secret needs access_key_id and secret_access_key"
            )
        base = str(settings.get("prefix") or PREFIX).strip("/") + "/"
        region = settings.get("bucket_region") or cursor.get("bucket_region") or "us-east-1"
        bucket = Bucket(str(settings["bucket"]), str(region), secret)
        wanted = categories(settings.get("event_categories"))
        now = datetime.now(UTC)
        start = now - timedelta(hours=int(settings.get("backfill_hours", 24)))
        state = dict(cursor.get("prefixes") or {})
        mine = state.get(base) or {"after": day(base, start), "seen": []}
        after, seen = str(mine["after"]), set(mine["seen"])
        records: list[dict[str, Any]] = []
        newest, listed, more = after, after, False
        with client() as http:
            while True:
                keys, _, truncated = bucket.list(http, base, listed)
                for key in keys:
                    listed = key
                    if key in seen or key.endswith("/"):
                        continue
                    if len(records) >= limit:
                        more = True
                        break
                    records += read(bucket.get(http, key), wanted)
                    seen.add(key)
                    newest = max(newest, key)
                if more or not truncated or not keys:
                    break
        read_day = day_of(base, newest)
        if read_day:
            after = max(after, min(day(base, read_day), day(base, now - OVERLAP)))
        state[base] = {"after": after, "seen": sorted(k for k in seen if k > after), "more": more}
        return FetchResult(
            records=records,
            cursor={"prefixes": state, "bucket_region": bucket.region},
            more=more,
        )


def categories(value: Any) -> set[str] | None:
    """The event.category values to keep; None keeps them all."""
    if value is None or value == "":
        return set(DEFAULT_CATEGORIES)
    chosen = {value} if isinstance(value, str) else {str(v) for v in value}
    return None if "all" in chosen else chosen


def day(base: str, when: datetime) -> str:
    """The key every object written on `when`'s day sorts after."""
    return f"{base}{when:%Y/%m/%d}/"


def day_of(base: str, key: str) -> datetime | None:
    try:
        return datetime.strptime(key[len(base) : len(base) + 10], "%Y/%m/%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def read(body: bytes, wanted: set[str] | None) -> list[dict[str, Any]]:
    """One object's records, nested, keeping the wanted categories. A line that
    is not a JSON object is skipped rather than holding the cursor back."""
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    out = []
    for line in body.splitlines():
        try:
            flat = json.loads(line)
        except ValueError:
            continue
        if isinstance(flat, dict) and (wanted is None or flat.get("event.category") in wanted):
            out.append(nest(flat))
    return out


def nest(flat: dict[str, Any]) -> dict[str, Any]:
    """`{"src.process.name": x}` -> `{"src": {"process": {"name": x}}}`."""
    out: dict[str, Any] = {}
    for key, value in flat.items():
        *parents, leaf = key.split(".")
        node = out
        for part in parents:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {} if child is None else {LEAF: child}
            node = child
        if isinstance(node.get(leaf), dict):
            node[leaf][LEAF] = value
        else:
            node[leaf] = value
    return out


CONNECTOR = SentinelOneCloudFunnelConnector()
