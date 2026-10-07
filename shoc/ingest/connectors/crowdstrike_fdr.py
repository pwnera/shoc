"""CrowdStrike Falcon Data Replicator connector (ING-1): raw sensor events.

FDR is the route CrowdStrike documents for a SIEM. CrowdStrike provisions an SQS
queue and an S3 bucket for the customer and hands over an AWS key pair. Each
message names one batch, `{"bucket": …, "files": [{"path": …}]}`, and each file
is gzipped NDJSON, one sensor event a line, with `event_simpleName`, the sensor
id `aid` and an epoch-millisecond `timestamp`. Events are under `data/`; the
`aidmaster`, `managedassets` and `notmanaged` inventory files beside them are
skipped.

A page's messages are deleted at the start of the next fetch, after the run loop
has loaded their events, as gcp_audit acknowledges Pub/Sub. A message the queue
hands out again in between loads again, and the store keeps one row per event id.

FDR carries every event the sensor records, which for a few hundred endpoints is
more than all of a small company's other sources together. `event_names` keeps
the ones detections and questions read (DEFAULT_EVENTS); `["*"]` keeps all.
"""

from __future__ import annotations

import gzip
import json
from typing import Any
from urllib.parse import urlparse

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors import awssig
from shoc.ingest.connectors.base import FetchResult, client
from shoc.ingest.connectors.cloudtrail_s3 import Bucket

# Process starts, DNS, connections, logons, account changes, executable and
# script writes, scheduled tasks, services and autorun registry values.
DEFAULT_EVENTS = (
    "ProcessRollup2",
    "SyntheticProcessRollup2",
    "DnsRequest",
    "NetworkConnectIP4",
    "NetworkConnectIP6",
    "NetworkReceiveAcceptIP4",
    "NetworkReceiveAcceptIP6",
    "UserLogon",
    "UserLogonFailed2",
    "UserLogoff",
    "UserAccountCreated",
    "UserAccountAddedToGroup",
    "NewExecutableWritten",
    "NewScriptWritten",
    "PeFileWritten",
    "ScheduledTaskRegistered",
    "ServiceStarted",
    "AsepValueUpdate",
)
BATCH = 10  # the most SQS hands out or deletes in one call
HOLD = 1800  # seconds a received message stays hidden; longer than a poll interval


def region_of(queue_url: str) -> str:
    """`https://sqs.<region>.amazonaws.com/<account>/<queue>`, or the legacy
    `https://<region>.queue.amazonaws.com/…`."""
    parts = (urlparse(queue_url).hostname or "").split(".")
    if len(parts) < 3:
        raise ConfigError(f"crowdstrike_fdr: '{queue_url}' is not an SQS queue URL")
    return parts[1] if parts[0] == "sqs" else parts[0]


def _sqs(
    http: httpx.Client, secret: dict[str, Any], region: str, action: str, body: dict[str, Any]
) -> httpx.Response:
    host = f"sqs.{region}.amazonaws.com"
    payload = json.dumps(body)
    headers = awssig.headers(
        access_key=secret["access_key_id"],
        secret_key=secret["secret_access_key"],
        session_token=secret.get("session_token"),
        region=region,
        service="sqs",
        host=host,
        body=payload,
        extra={"content-type": "application/x-amz-json-1.0", "x-amz-target": f"AmazonSQS.{action}"},
    )
    return http.post(f"https://{host}/", content=payload, headers=headers)


class CrowdStrikeFDRConnector:
    source = "crowdstrike_fdr"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        queue = str(settings.get("queue_url") or "")
        if not queue:
            raise ConfigError("crowdstrike_fdr: settings need queue_url")
        if not (secret.get("access_key_id") and secret.get("secret_access_key")):
            raise ConfigError("crowdstrike_fdr: secret needs access_key_id and secret_access_key")
        region = region_of(queue)
        keep = set(settings.get("event_names") or DEFAULT_EVENTS)
        buckets: dict[str, Bucket] = {}
        records: list[dict[str, Any]] = []
        handles: list[str] = []
        more = True
        with client() as http:
            done = list(cursor.get("delete") or [])
            for i in range(0, len(done), BATCH):
                # A handle past its visibility timeout deletes nothing; that
                # message comes back and loads once, so a refusal is not fatal.
                entries = [
                    {"Id": str(n), "ReceiptHandle": h} for n, h in enumerate(done[i : i + BATCH])
                ]
                _sqs(
                    http,
                    secret,
                    region,
                    "DeleteMessageBatch",
                    {"QueueUrl": queue, "Entries": entries},
                )
            while more and len(records) < limit:
                resp = _sqs(
                    http,
                    secret,
                    region,
                    "ReceiveMessage",
                    {"QueueUrl": queue, "MaxNumberOfMessages": BATCH, "VisibilityTimeout": HOLD},
                )
                resp.raise_for_status()
                messages = resp.json().get("Messages") or []
                more = len(messages) == BATCH
                for message in messages:
                    batch = json.loads(message["Body"])
                    name = str(batch["bucket"])
                    bucket = buckets.setdefault(name, Bucket(name, region, secret))
                    for item in batch.get("files") or []:
                        path = str(item.get("path") or "")
                        if not path.startswith("data/"):
                            continue
                        for line in gzip.decompress(bucket.get(http, path)).splitlines():
                            if not line.strip():
                                continue
                            event = json.loads(line)
                            if "*" in keep or event.get("event_simpleName") in keep:
                                records.append(event)
                    handles.append(message["ReceiptHandle"])
        return FetchResult(records=records, cursor={"delete": handles}, more=more)


CONNECTOR = CrowdStrikeFDRConnector()
