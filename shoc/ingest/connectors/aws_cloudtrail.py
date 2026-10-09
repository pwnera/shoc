"""AWS CloudTrail connector (ING-1): LookupEvents, signed with SigV4, or the trail's
S3 bucket when `bucket` is set (see `cloudtrail_s3`). LookupEvents is per region;
every enabled region is read unless `region` names some."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors import awssig, cloudtrail_s3
from shoc.ingest.connectors.base import FetchResult, client, settled, since_default, utc

SERVICE = "cloudtrail"
TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
# AWS: CloudTrail "typically delivers logs within an average of about 5 minutes"
# of the call. A poll reads no closer to now than that (D154).
LAG = dt.timedelta(minutes=5)


def sigv4_headers(
    *,
    access_key: str,
    secret_key: str,
    session_token: str | None,
    region: str,
    body: str,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Signed headers for a CloudTrail JSON POST."""
    return awssig.headers(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=region,
        service=SERVICE,
        host=f"{SERVICE}.{region}.amazonaws.com",
        method="POST",
        path="/",
        body=body,
        extra={"content-type": "application/x-amz-json-1.1", "x-amz-target": TARGET},
        now=now,
    )


class AwsCloudTrailConnector:
    source = "aws_cloudtrail"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        access_key = secret.get("access_key_id")
        secret_key = secret.get("secret_access_key")
        if not access_key or not secret_key:
            raise ConfigError("aws_cloudtrail: secret needs access_key_id and secret_access_key")
        if settings.get("bucket"):
            return cloudtrail_s3.fetch(settings, secret, cursor, limit)
        region = settings.get("region") or "us-east-1"
        start = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        until = settled(cursor, LAG)
        if utc(start) >= utc(until):
            return FetchResult(cursor={"since": start})
        body_obj: dict[str, Any] = {
            "StartTime": _epoch(start),
            "EndTime": _epoch(until),
            "MaxResults": min(int(limit), 50),
        }
        if cursor.get("next_token"):
            body_obj["NextToken"] = cursor["next_token"]
        body = json.dumps(body_obj)
        headers = sigv4_headers(
            access_key=access_key,
            secret_key=secret_key,
            session_token=secret.get("session_token"),
            region=region,
            body=body,
        )
        url = f"https://{SERVICE}.{region}.amazonaws.com/"
        with client() as http:
            resp = http.post(url, content=body, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
        records: list[dict[str, Any]] = []
        # LookupEvents answers newest first, so the newest event is on the first
        # page and has to be carried to the last one.
        newest = str(cursor.get("newest") or start)
        for item in payload.get("Events", []):
            raw = item.get("CloudTrailEvent")
            record = json.loads(raw) if isinstance(raw, str) else dict(item)
            record.setdefault("eventID", item.get("EventId"))
            records.append(record)
            newest = max(newest, str(record.get("eventTime") or start))
        next_token = payload.get("NextToken")
        if next_token:
            # A NextToken belongs to the window it was issued for: hold it
            # until the walk is done.
            held = {"since": start, "until": until, "newest": newest, "next_token": next_token}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


def cannot_carry(settings: dict[str, Any], rule: Any) -> str:
    """Why this source, as configured, cannot feed `rule`; "" when it can.

    A rule whose logsource `definition` asks for data events (S3 object reads
    and writes, SNS publishing) needs the trail's bucket: LookupEvents returns
    management events only.
    """
    if settings.get("bucket") or "data events" not in str(rule.logsource.get("definition", "")):
        return ""
    return (
        "needs CloudTrail data events, which LookupEvents never returns: set `bucket` to "
        "the S3 bucket of a trail that records them"
    )


def _epoch(iso: str) -> float:
    return dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()


CONNECTOR = awssig.Regions(AwsCloudTrailConnector())
