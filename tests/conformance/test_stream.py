"""The event stream and signed webhooks (API-2)."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from shoc.capabilities.registry import call
from shoc.capabilities.stream import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    deliver,
    read_events,
    sign,
    verify,
)
from shoc.cases.engine import publish
from shoc.db.pool import fetch_one
from shoc.errors import ValidationError

pytestmark = pytest.mark.postgres


def test_detection_publishes_findings_and_cases(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    events = read_events(ctx.db, config.tenant_id, 0, None, 500)
    types = [e["type"] for e in events]
    assert types.count("finding.new") >= 5
    assert "case.opened" in types
    assert all(e["subject"] for e in events)


def test_tail_resumes_from_a_sequence_number(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    first = call("stream.tail", ctx, {"limit": 3})
    assert first.data.count == 3
    second = call("stream.tail", ctx, {"since_seq": first.data.last_seq, "limit": 500})
    assert second.data.count > 0
    assert all(e["seq"] > first.data.last_seq for e in second.data.events)


def test_tail_filters_by_type(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    page = call("stream.tail", ctx, {"types": ["case.opened"], "limit": 50})
    assert page.data.count >= 1
    assert {e["type"] for e in page.data.events} == {"case.opened"}


def test_webhook_registration_returns_a_secret_once_and_stores_it_encrypted(ctx, config, clean):
    result = call(
        "stream.subscribe", ctx, {"url": "https://example.test/hook", "types": ["case.opened"]}
    )
    secret = result.data.secret
    assert secret and len(secret) > 20
    row = fetch_one(
        ctx.db,
        "SELECT secret, types FROM shoc.webhooks WHERE webhook_id = %s",
        (result.data.webhook_id,),
    )
    assert row and secret.encode() not in bytes(row["secret"])
    assert row["types"] == ["case.opened"]


def test_a_non_http_webhook_is_refused(ctx, config, clean):
    with pytest.raises(ValidationError, match="http or https"):
        call("stream.subscribe", ctx, {"url": "file:///etc/passwd"})


def test_signatures_round_trip_and_reject_tampering():
    body = json.dumps({"events": [{"type": "case.opened"}]}).encode()
    signature = sign("s3cret", "1790000000", body)
    assert verify("s3cret", "1790000000", body, signature)
    assert not verify("s3cret", "1790000001", body, signature), "the timestamp is signed too"
    assert not verify("s3cret", "1790000000", body + b" ", signature)
    assert not verify("other", "1790000000", body, signature)


def test_an_unreachable_subscriber_is_recorded_as_health(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    result = call("stream.subscribe", ctx, {"url": "http://127.0.0.1:9/hook"})
    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    sent = deliver(ctx.db, config.tenant_id, config.master_key, 10)
    assert sent == 0
    row = fetch_one(
        ctx.db,
        "SELECT last_error, last_ok_at FROM shoc.webhooks WHERE webhook_id = %s",
        (result.data.webhook_id,),
    )
    assert row and row["last_error"] and row["last_ok_at"] is None


def test_tail_says_where_the_stream_is_now(ctx, store, config, clean):
    """A client that only wants what happens next needs to know where "next" starts."""
    from evals.run import SCENARIOS, replay

    empty = call("stream.tail", ctx, {})
    assert empty.data.latest_seq == 0

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    page = call("stream.tail", ctx, {"limit": 2})
    assert page.data.count == 2
    assert page.data.latest_seq > page.data.last_seq, "there is more after this page"

    rest = call("stream.tail", ctx, {"since_seq": page.data.latest_seq})
    assert rest.data.count == 0, "starting at latest_seq means starting live"


def test_a_webhook_is_delivered_signed_and_moves_on(ctx, config, clean):
    """A real receiver gets each event once, in order, signed with the secret it was given."""
    received: list[tuple] = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            received.append((self.headers, body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tenant, key = config.tenant_id, config.master_key
    try:
        publish(ctx.db, tenant, "case.opened", "C-before", {})
        url = f"http://127.0.0.1:{server.server_address[1]}/hook"
        call("stream.subscribe", ctx, {"url": url})
        secret = call("stream.subscribe", ctx, {"url": url}).data.secret
        for n in range(3):
            publish(ctx.db, tenant, "case.opened", f"C-{n}", {"n": n})
        ctx.db.execute(
            "UPDATE shoc.stream_events SET created_at = now() - interval '1 day' "
            "WHERE tenant_id = %s",
            (tenant,),
        )
        assert deliver(ctx.db, tenant, key, limit=2) == 2
        assert deliver(ctx.db, tenant, key, limit=2) == 1, "the second run starts after the first"
        assert deliver(ctx.db, tenant, key, limit=2) == 0
    finally:
        server.shutdown()

    subjects = [e["subject"] for _, body in received for e in json.loads(body)["events"]]
    assert subjects == ["C-0", "C-1", "C-2"], "nothing from before the subscription, nothing twice"
    for headers, body in received:
        stamp = headers[TIMESTAMP_HEADER]
        assert verify(secret, stamp, body, headers[SIGNATURE_HEADER]), "signed with the last secret"
        assert abs(int(stamp) - time.time()) < 300, "the timestamp is when it was sent"
