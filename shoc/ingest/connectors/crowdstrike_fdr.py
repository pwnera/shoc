"""CrowdStrike Falcon Data Replicator connector (ING-1): raw sensor events.

FDR is the route CrowdStrike documents for a SIEM. CrowdStrike provisions an SQS
queue and an S3 bucket for the customer and hands over an AWS key pair. Each
message names one batch, `{"bucket": …, "files": [{"path": …}]}`, and each file
is gzipped NDJSON, one sensor event a line, with `event_simpleName`, the sensor
id `aid` and an epoch-millisecond `timestamp`. Events are under `data/`; the
`aidmaster`, `managedassets` and `notmanaged` inventory files beside them are
skipped.

A page's messages are deleted at the start of the next fetch, after the run loop
has loaded their events; HOLD outlasts the cycle between two runs. A message
the queue hands out again in between loads again, and the store keeps one row
per event id.
A page reads whole messages until it holds `limit` events, and each data file is
unpacked line by line as it downloads: one file can be hundreds of MB unpacked.

FDR carries every event the sensor records, which for a few hundred endpoints is
more than all of a small company's other sources together. `event_names` keeps
the ones detections and questions read (DEFAULT_EVENTS); `["*"]` keeps all.
"""

from __future__ import annotations

import json
import zlib
from collections.abc import Iterator
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
# A short poll samples a few SQS servers and often answers empty while messages
# wait; a long poll waits up to this many seconds for one.
WAIT = 20


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


def _lines(
    http: httpx.Client, secret: dict[str, Any], region: str, bucket: str, key: str
) -> Iterator[bytes]:
    """The lines of one gzipped data file, unpacked as it downloads, so neither
    the file nor what it unpacks to is held whole. CrowdStrike puts the bucket
    in the queue's region; one elsewhere is followed there."""
    unzip, rest = zlib.decompressobj(wbits=31), b""
    with Bucket(bucket, region, secret).stream(http, key) as resp:
        for chunk in resp.iter_bytes():
            while chunk:
                rest += unzip.decompress(chunk)
                chunk = unzip.unused_data
                if unzip.eof:
                    # A file can be several gzip members, one after another.
                    unzip = zlib.decompressobj(wbits=31)
            *lines, rest = rest.split(b"\n")
            yield from lines
    yield rest


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
                    {
                        "QueueUrl": queue,
                        "MaxNumberOfMessages": BATCH,
                        "VisibilityTimeout": HOLD,
                        "WaitTimeSeconds": WAIT,
                    },
                )
                resp.raise_for_status()
                messages = resp.json().get("Messages") or []
                more = bool(messages)
                for message in messages:
                    if len(records) >= limit:
                        # Not deleted, so the queue hands it out again after HOLD.
                        break
                    batch = json.loads(message["Body"])
                    for item in batch.get("files") or []:
                        path = str(item.get("path") or "")
                        if not path.startswith("data/"):
                            continue
                        for line in _lines(http, secret, region, str(batch["bucket"]), path):
                            if not line.strip():
                                continue
                            event = json.loads(line)
                            if "*" in keep or event.get("event_simpleName") in keep:
                                records.append(event)
                    handles.append(message["ReceiptHandle"])
        return FetchResult(records=records, cursor={"delete": handles}, more=more)


CONNECTOR = CrowdStrikeFDRConnector()
