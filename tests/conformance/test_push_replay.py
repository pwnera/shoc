"""A replayed GitHub delivery loads once, whatever its id looks like (ING-2)."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from starlette.testclient import TestClient

from shoc.api.rest import build_app
from shoc.db.pool import execute
from tests.conformance.test_rest import _webhook

pytestmark = pytest.mark.postgres


def test_a_replayed_delivery_loads_nothing_whatever_its_id(config, ctx, store, clean):
    from shoc.capabilities.registry import call

    execute(ctx.db, "DELETE FROM shoc.push_deliveries WHERE tenant_id = %s", (config.tenant_id,))
    key = call("source.push_key", ctx, {"source": "github", "rotate": True}).data.push_key
    body = json.dumps(
        {
            "action": "publicized",
            "repository": {"full_name": "acme/payments"},
            "organization": {"login": "acme"},
            "sender": {"login": "mallory", "id": 4242},
        }
    ).encode()
    url = f"/ingest/github?tenant={config.tenant_id}"
    # Not a version-1 UUID, so the delivery's time is the time it arrived.
    later = "c0ffee00-0000-4000-8000-000000000001"
    with TestClient(build_app(config), base_url="https://shoc.example.com") as github:
        # A delivery that fails to load is not remembered: GitHub's retry loads.
        with mock.patch("shoc.ingest.batch.load", side_effect=RuntimeError("store down")):
            assert (
                github.post(url, content=body, headers=_webhook(key, body, later)).status_code
                >= 500
            )
        loads = [
            github.post(url, content=body, headers=_webhook(key, body, later)).json()["data"][
                "loaded"
            ]
            for _ in range(3)
        ]
    assert loads == [1, 0, 0]
    rows = store.query(
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :t", {"t": config.tenant_id}
    ).rows
    assert [r["event_uid"] for r in rows] == [f"github-webhook-{later}"]
