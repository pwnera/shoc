"""CloudTrail from the trail's S3 bucket (ING-1).

LookupEvents answers 50 events a call, two calls a second, management events
only, and a busy account outgrows it. The trail's bucket holds everything the
trail recorded, as gzipped JSON under
`AWSLogs/[<org id>/]<account>/CloudTrail/<region>/YYYY/MM/DD/`, readable with
s3:ListBucket and s3:GetObject. Its records are the JSON LookupEvents returns,
so the CloudTrail mapping reads them unchanged.

Every account and region prefix keeps its own place. Keys sort by delivery
time, so a listing resumes after the last key read, less OVERLAP: two files
delivered in the same minute sort by a random suffix, and the later one can land
before the key we stopped at. Keys already read inside that window are kept in
the cursor and not fetched twice.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from shoc.ingest.connectors import awssig
from shoc.ingest.connectors.base import OVERLAP, FetchResult, client

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class Bucket:
    """Signed GETs on one bucket, which follow it to its region once.

    `endpoint` names an S3-compatible host other than AWS, Cloudflare R2's
    `<account>.r2.cloudflarestorage.com` for one, addressed path-style.
    """

    def __init__(self, name: str, region: str, secret: dict[str, Any], endpoint: str = "") -> None:
        self.name, self.region, self.secret = name, region, secret
        self.endpoint = endpoint.removeprefix("https://").rstrip("/")

    def get(self, http: httpx.Client, key: str = "", query: dict[str, str] | None = None) -> bytes:
        resp = self._get(http, key, query)
        moved = resp.headers.get("x-amz-bucket-region")
        if resp.status_code in (301, 400) and moved and moved != self.region:
            self.region = moved
            resp = self._get(http, key, query)
        resp.raise_for_status()
        return resp.content

    def _get(self, http: httpx.Client, key: str, query: dict[str, str] | None) -> httpx.Response:
        host = self.endpoint or f"{self.name}.s3.{self.region}.amazonaws.com"
        path = ("/" + self.name if self.endpoint else "") + "/" + quote(key, safe="/-_.~")
        headers = awssig.headers(
            access_key=self.secret["access_key_id"],
            secret_key=self.secret["secret_access_key"],
            session_token=self.secret.get("session_token"),
            region=self.region,
            service="s3",
            host=host,
            method="GET",
            path=path,
            query=query,
            extra={"x-amz-content-sha256": EMPTY_SHA256},
        )
        qs = awssig.canonical_query(query)
        return http.get(f"https://{host}{path}" + (f"?{qs}" if qs else ""), headers=headers)

    def list(
        self, http: httpx.Client, prefix: str, after: str = "", delimiter: str = ""
    ) -> tuple[list[str], list[str], bool]:
        """(keys, common prefixes, truncated) under `prefix`, after `after`."""
        query = {"list-type": "2", "prefix": prefix}
        if after:
            query["start-after"] = after
        if delimiter:
            query["delimiter"] = delimiter
        root = ET.fromstring(self.get(http, query=query))
        keys = [e.text or "" for e in root.findall(f"{NS}Contents/{NS}Key")]
        prefixes = [e.text or "" for e in root.findall(f"{NS}CommonPrefixes/{NS}Prefix")]
        return keys, prefixes, root.findtext(f"{NS}IsTruncated") == "true"


def trails(bucket: Bucket, http: httpx.Client, base: str, region: str = "") -> list[str]:
    """Every account and region prefix the trail writes under; an organisation
    trail puts one more level, the org id, above the accounts."""
    accounts: list[str] = []
    for p in bucket.list(http, f"{base}AWSLogs/", delimiter="/")[1]:
        org = p.rstrip("/").rsplit("/", 1)[-1].startswith("o-")
        accounts += bucket.list(http, p, delimiter="/")[1] if org else [p]
    found: list[str] = []
    for account in accounts:
        found += bucket.list(http, f"{account}CloudTrail/", delimiter="/")[1]
    return [p for p in found if not region or p.endswith(f"/{region}/")]


def mark(prefix: str, when: datetime) -> str:
    """The key of a file delivered at `when`, without its random suffix."""
    parts = prefix.rstrip("/").split("/")
    account, region = parts[-3], parts[-1]
    return f"{prefix}{when:%Y/%m/%d}/{account}_CloudTrail_{region}_{when:%Y%m%dT%H%M}Z"


def delivered(key: str) -> datetime:
    stamp = key.rsplit("/", 1)[-1].split("_")[3]
    return datetime.strptime(stamp, "%Y%m%dT%H%MZ").replace(tzinfo=UTC)


def fetch(
    settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
) -> FetchResult:
    base = str(settings.get("prefix") or "").strip("/")
    base = f"{base}/" if base else ""
    region = settings.get("bucket_region") or cursor.get("bucket_region") or "us-east-1"
    bucket = Bucket(str(settings["bucket"]), region, secret)
    start = datetime.now(UTC) - timedelta(hours=int(settings.get("backfill_hours", 24)))
    state = dict(cursor.get("prefixes") or {})
    records: list[dict[str, Any]] = []
    with client() as http:
        # Prefixes still paging go first; a new walk looks for new accounts and regions.
        todo = [p for p, s in state.items() if s.get("more")] or trails(
            bucket, http, base, str(settings.get("region") or "")
        )
        for prefix in todo:
            mine = state.get(prefix) or {"after": mark(prefix, start), "seen": []}
            if len(records) >= limit:
                state[prefix] = {**mine, "more": True}
                continue
            after, seen = str(mine["after"]), set(mine["seen"])
            keys, _, more = bucket.list(http, prefix, after)
            for key in keys:
                if key in seen or not key.endswith(".json.gz"):
                    continue
                if len(records) >= limit:
                    more = True
                    break
                records += json.loads(gzip.decompress(bucket.get(http, key))).get("Records", [])
                after = max(after, mark(prefix, delivered(key) - OVERLAP))
                seen = {k for k in seen | {key} if k > after}
            state[prefix] = {"after": after, "seen": sorted(seen), "more": more}
    more = any(state[p]["more"] for p in todo)
    cursor = {"prefixes": state, "bucket_region": bucket.region}
    return FetchResult(records=records, cursor=cursor, more=more)
