"""Falcon Data Replicator: SQS names the files, S3 holds them (ING-1)."""

from __future__ import annotations

import gzip
import json
from typing import Any

import httpx
import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors
from shoc.ingest.connectors.crowdstrike_fdr import region_of

QUEUE = "https://sqs.us-west-1.amazonaws.com/111111111111/cs-prod-fdr-queue"
AWS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"}


def transport(monkeypatch, replies: list[dict[str, Any]]) -> list[httpx.Request]:
    """Answer each request with the next reply, and keep what was sent.

    A reply is `{"json": …}` or `{"content": b"…"}` plus optional `headers` and `status`.
    """
    seen: list[httpx.Request] = []
    real_client = httpx.Client
    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        reply: dict[str, Any] = queue.pop(0) if queue else {}
        body = (
            {"content": reply["content"]} if "content" in reply else {"json": reply.get("json", {})}
        )
        return httpx.Response(
            int(reply.get("status", 200)), headers=dict(reply.get("headers") or {}), **body
        )

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    return seen


def messages(*batches: tuple[str, list[str]]) -> dict[str, Any]:
    return {
        "json": {
            "Messages": [
                {
                    "MessageId": f"m{n}",
                    "ReceiptHandle": f"handle-{n}",
                    "Body": json.dumps(
                        {
                            "bucket": "cs-prod-fdr-bucket",
                            "files": [{"path": p} for p in paths],
                            "fileCount": len(paths),
                        }
                    ),
                }
                for n, (_, paths) in enumerate(batches)
            ]
        }
    }


def ndjson(*names: str) -> dict[str, Any]:
    lines = [
        json.dumps(
            {
                "event_simpleName": name,
                "aid": "111111111111111",
                "id": f"e{n}",
                "timestamp": "1687509722190",
            }
        )
        for n, name in enumerate(names)
    ]
    return {"content": gzip.compress("\n".join(lines).encode() + b"\n")}


def target(request: httpx.Request) -> str:
    return request.headers.get("x-amz-target", "")


def test_a_message_names_the_files_whose_events_are_loaded(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            messages(("b1", ["data/a1b2/part-00000.gz", "aidmaster/a1b2/part-00000.gz"])),
            ndjson("ProcessRollup2", "SensorHeartbeat", "DnsRequest"),
        ],
    )
    page = connectors.get("crowdstrike_fdr").fetch({"queue_url": QUEUE}, AWS, {}, 1000)

    receive = seen[0]
    assert receive.url.host == "sqs.us-west-1.amazonaws.com"
    assert target(receive) == "AmazonSQS.ReceiveMessage"
    assert receive.headers["content-type"] == "application/x-amz-json-1.0"
    assert "/us-west-1/sqs/aws4_request" in receive.headers["authorization"]
    assert json.loads(receive.content)["QueueUrl"] == QUEUE
    get = seen[1]
    assert get.url.host == "cs-prod-fdr-bucket.s3.us-west-1.amazonaws.com"
    assert get.url.path == "/data/a1b2/part-00000.gz"
    assert len(seen) == 2, "the aidmaster inventory file is not fetched"
    # The default filter drops the heartbeat.
    assert [r["event_simpleName"] for r in page.records] == ["ProcessRollup2", "DnsRequest"]
    assert page.cursor == {"delete": ["handle-0"]} and page.more is False


@pytest.mark.parametrize(
    ("names", "kept"),
    [(["*"], ["SensorHeartbeat", "DnsRequest"]), (["SensorHeartbeat"], ["SensorHeartbeat"])],
)
def test_event_names_widens_or_narrows_the_filter(monkeypatch, names, kept):
    transport(
        monkeypatch,
        [messages(("b1", ["data/x/part-0.gz"])), ndjson("SensorHeartbeat", "DnsRequest")],
    )
    settings = {"queue_url": QUEUE, "event_names": names}
    page = connectors.get("crowdstrike_fdr").fetch(settings, AWS, {}, 1000)
    assert [r["event_simpleName"] for r in page.records] == kept


def test_the_previous_page_is_deleted_at_the_next_fetch(monkeypatch):
    seen = transport(monkeypatch, [{"json": {}}, {"json": {}}])
    handles = [f"h{n}" for n in range(12)]
    page = connectors.get("crowdstrike_fdr").fetch(
        {"queue_url": QUEUE}, AWS, {"delete": handles}, 1000
    )

    deletes = [r for r in seen if target(r) == "AmazonSQS.DeleteMessageBatch"]
    assert [len(json.loads(r.content)["Entries"]) for r in deletes] == [10, 2]
    sent = [e["ReceiptHandle"] for r in deletes for e in json.loads(r.content)["Entries"]]
    assert sent == handles
    assert target(seen[-1]) == "AmazonSQS.ReceiveMessage", "deleted before receiving"
    assert page.records == [] and page.cursor == {"delete": []} and page.more is False


def test_a_full_receive_is_followed_by_another(monkeypatch):
    full = messages(*[(f"b{n}", []) for n in range(10)])
    transport(monkeypatch, [full, {"json": {}}])
    page = connectors.get("crowdstrike_fdr").fetch({"queue_url": QUEUE}, AWS, {}, 1000)
    assert len(page.cursor["delete"]) == 10 and page.more is False


def test_region_comes_from_the_queue_url():
    assert region_of(QUEUE) == "us-west-1"
    assert region_of("https://eu-central-1.queue.amazonaws.com/111111111111/q") == "eu-central-1"
    with pytest.raises(ConfigError):
        region_of("not a url")


def test_missing_settings_are_a_config_error():
    fdr = connectors.get("crowdstrike_fdr")
    with pytest.raises(ConfigError):
        fdr.fetch({}, AWS, {}, 10)
    with pytest.raises(ConfigError):
        fdr.fetch({"queue_url": QUEUE}, {"access_key_id": "a"}, {}, 10)
