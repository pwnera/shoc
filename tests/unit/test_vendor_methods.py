"""Each connector reads the way its vendor documents for a SIEM (ING-1)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors, ocsf
from shoc.ingest.connectors import base, wazuh
from shoc.store.base import LoadStats
from tests.support import FIXTURES
from tests.unit.test_connectors import REREAD, SINCE, query, transport


def test_wazuh_reads_alerts_from_the_indexer_and_pages_by_search_after(monkeypatch):
    hits = [
        {
            "_source": {"id": f"a{i}", "timestamp": f"2026-09-20T10:0{i}:00.000+0000"},
            "sort": [1790000000000 + i, f"a{i}"],
        }
        for i in range(2)
    ]
    seen = transport(monkeypatch, [{"json": {"hits": {"hits": hits}}}, {"json": {"hits": {}}}])
    connector = connectors.get("wazuh")
    settings = {"indexer_url": "https://wazuh.internal:9200/", "verify_tls": False}
    secret = {"username": "shoc", "password": "pw"}
    first = connector.fetch(settings, secret, {"since": SINCE}, 2)
    request = seen[0]
    assert request.url.path == "/wazuh-alerts-4.x-*/_search"
    assert request.headers["authorization"].startswith("Basic ")
    body = json.loads(request.content)
    assert body["query"] == {"range": {"timestamp": {"gt": REREAD}}}, "the overlap again (D164)"
    assert body["sort"] == [{"timestamp": "asc"}, {"id": "asc"}] and body["size"] == 2
    assert [r["id"] for r in first.records] == ["a0", "a1"]
    assert first.more and first.cursor["after"] == hits[1]["sort"]
    assert first.cursor["since"] == SINCE, "held while paging"

    second = connector.fetch(settings, secret, first.cursor, 2)
    assert json.loads(seen[1].content)["search_after"] == hits[1]["sort"]
    assert second.more is False and second.cursor == {"since": "2026-09-20T10:01:00.000+0000"}


def test_wazuh_trusts_its_own_root_ca_before_turning_verification_off(monkeypatch):
    """`ca_cert` pins Wazuh's self-signed root, and wins over `verify_tls: false`."""
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    monkeypatch.setattr("ssl.create_default_context", lambda cadata: ("trusts", cadata))
    assert wazuh.verify({"ca_cert": pem, "verify_tls": False}) == ("trusts", pem)
    assert wazuh.verify({"verify_tls": False}) is False
    assert wazuh.verify({}) is True


def test_wazuh_needs_the_indexer_and_a_user():
    with pytest.raises(ConfigError, match="indexer_url"):
        connectors.get("wazuh").fetch({}, {"username": "u", "password": "p"}, {}, 10)


def test_gcp_reads_the_sinks_subscription_and_acknowledges_after_loading(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "tok")
    entry = {"insertId": "i1", "timestamp": "2026-09-20T10:00:00Z", "logName": "cloudaudit"}
    data = base64.b64encode(json.dumps(entry).encode()).decode()
    seen = transport(
        monkeypatch,
        [
            {"json": {"receivedMessages": [{"ackId": "k2", "message": {"data": data}}]}},
            {"json": {}},
            {"json": {}},
            {"json": {}},
        ],
    )
    sub = "projects/acme/subscriptions/shoc-audit"
    page = connectors.get("gcp_audit").fetch({"subscription": sub}, {}, {}, 10)
    pulled, held = seen
    assert pulled.url.path == f"/v1/{sub}:pull"
    assert held.url.path == f"/v1/{sub}:modifyAckDeadline"
    assert json.loads(held.content) == {"ackIds": ["k2"], "ackDeadlineSeconds": 600}
    # A pull returns fewer than maxMessages while more wait: only an empty one
    # ends the run.
    assert page.records == [entry] and page.cursor == {} and page.more is True
    assert page.commit is not None, "nothing is acknowledged before the run loop stores it"

    page.commit()
    acked = seen[2]
    assert acked.url.path == f"/v1/{sub}:acknowledge"
    assert json.loads(acked.content) == {"ackIds": ["k2"]}

    last = connectors.get("gcp_audit").fetch({"subscription": sub}, {}, page.cursor, 10)
    assert last.records == [] and last.more is False and last.commit is None


def test_gcp_acknowledges_each_page_in_the_run_that_stored_it(monkeypatch):
    """The last page of a run is acknowledged before the run ends, not at the
    next cycle, which comes after Pub/Sub's deadline (D153)."""
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "tok")
    entry = json.loads((FIXTURES / "mappings" / "gcp_audit.json").read_text())[0]
    data = base64.b64encode(json.dumps(entry).encode()).decode()
    pulled = {"json": {"receivedMessages": [{"ackId": "k1", "message": {"data": data}}]}}
    sub = "projects/acme/subscriptions/shoc-audit"
    # One transport for both runs: a second would wrap the first, whose emptied
    # queue would then answer every pull.
    seen = transport(monkeypatch, [pulled, {"json": {}}, {"json": {}}, pulled, {"json": {}}])

    def run(load: Any) -> tuple[base.RunStats, list[str]]:
        start = len(seen)
        monkeypatch.setattr(base.batchwriter, "load", load)
        stats = base.run(
            None,
            None,  # type: ignore[arg-type]
            "t1",
            "gcp_audit",
            {"subscription": sub},
            {},
            cursor={},
            persist=False,
            max_pages=1,
        )
        return stats, [r.url.path.rsplit(":", 1)[1] for r in seen[start:]]

    stats, calls = run(lambda store, rows: LoadStats(len(rows)))
    assert stats.loaded == 1 and stats.more is True, "cut off by its page cap"
    assert calls == ["pull", "modifyAckDeadline", "acknowledge"]

    def down(store: Any, rows: Any) -> LoadStats:
        raise RuntimeError("warehouse unreachable")

    failed, calls = run(down)
    assert failed.fetched == 1 and failed.error and failed.loaded == 0
    assert "acknowledge" not in calls, "a page that was not stored comes back"


def test_gcp_a_pull_an_empty_subscription_holds_open_is_an_empty_page(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "tok")

    def wait(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("no message", request=request)

    real_client = httpx.Client
    mock = httpx.MockTransport(wait)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    sub = "projects/acme/subscriptions/shoc-audit"
    page = connectors.get("gcp_audit").fetch({"subscription": sub}, {}, {}, 10)
    assert page.records == [] and page.cursor == {} and page.more is False


def test_gcp_pubsub_out_of_reach_is_an_error_not_an_empty_page(monkeypatch):
    """A cached token outlives a blocked egress: a pull that never connects must
    turn health stale, not read as an empty subscription."""
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "tok")

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("no route", request=request)

    real_client = httpx.Client
    mock = httpx.MockTransport(unreachable)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    sub = "projects/acme/subscriptions/shoc-audit"
    with pytest.raises(httpx.ConnectTimeout):
        connectors.get("gcp_audit").fetch({"subscription": sub}, {}, {}, 10)


def test_gcp_an_acknowledge_that_fails_to_send_does_not_fail_the_run(monkeypatch):
    """The page is stored; a lost ack is one redelivery, deduped by insertId."""
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "tok")
    entry = json.loads((FIXTURES / "mappings" / "gcp_audit.json").read_text())[0]
    data = base64.b64encode(json.dumps(entry).encode()).decode()
    pulled = {"receivedMessages": [{"ackId": "k1", "message": {"data": data}}]}

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(":acknowledge"):
            raise httpx.ReadTimeout("dropped", request=request)
        return httpx.Response(200, json=pulled if request.url.path.endswith(":pull") else {})

    real_client = httpx.Client
    mock = httpx.MockTransport(answer)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    monkeypatch.setattr(base.batchwriter, "load", lambda store, rows: LoadStats(len(rows)))
    stats = base.run(
        None,
        None,  # type: ignore[arg-type]
        "t1",
        "gcp_audit",
        {"subscription": "projects/acme/subscriptions/shoc-audit"},
        {},
        cursor={},
        persist=False,
        max_pages=1,
    )
    assert stats.loaded == 1 and stats.error is None and stats.more is True


def test_entra_reads_the_sign_ins_graph_v1_leaves_out(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.entra.access_token", lambda secret: "tok")
    seen = transport(monkeypatch, [{"json": {"value": []}}])
    connectors.get("entra").fetch({"stream": "servicePrincipalSignIns"}, {}, {"since": SINCE}, 10)
    assert seen[0].url.path == "/beta/auditLogs/signIns"
    signed = query(seen[0])["$filter"]
    assert signed.startswith(f"createdDateTime ge {SINCE} and createdDateTime le ")
    assert signed.endswith(" and signInEventTypes/any(t: t eq 'servicePrincipal')")


def test_workspace_waits_out_the_lag_google_documents_for_each_application(monkeypatch):
    """Tokens up to a few hours, logins a couple of minutes (D154)."""
    monkeypatch.setattr("shoc.ingest.connectors.google_workspace.access_token", lambda *_: "tok")
    seen = transport(monkeypatch, [{"json": {}}, {"json": {}}])
    connector = connectors.get("google_workspace")
    for application in ("token", "login"):
        connector.fetch(
            {"application": application, "admin_email": "a@acme.example"}, {}, {"since": SINCE}, 10
        )
    token, login = (query(r) for r in seen)
    assert token["startTime"] == login["startTime"] == SINCE, "no overlap"
    behind = [datetime.now(UTC) - datetime.fromisoformat(q["endTime"]) for q in (token, login)]
    assert timedelta(hours=3) <= behind[0] < timedelta(hours=3, minutes=1)
    assert timedelta(minutes=5) <= behind[1] < timedelta(minutes=6)


def test_anthropic_reads_the_activity_feed_only_when_it_is_on(monkeypatch):
    feed = {
        "data": [
            {
                "id": "act_1",
                "type": "platform_api_key_created",
                "created_at": "2026-09-20T10:00:00Z",
            }
        ],
        "has_more": False,
    }
    seen = transport(monkeypatch, [{"json": {"data": []}}, {"json": {"data": []}}, {"json": feed}])
    cursor = {"keys": {"since": SINCE}, "usage": {"since": SINCE}, "feed": {"since": SINCE}}
    secret = {"admin_key": "sk-ant-admin01-x"}
    page = connectors.get("anthropic").fetch({"activity_feed": True}, secret, cursor, 10)
    activities = seen[-1]
    assert activities.url.path == "/v1/compliance/activities"
    assert query(activities)["created_at.gt"] == SINCE and query(activities)["order"] == "asc"
    assert page.records[-1]["id"] == "act_1"
    assert page.cursor["feed"] == {"since": "2026-09-20T10:00:00Z"}

    seen.clear()
    connectors.get("anthropic").fetch({}, secret, cursor, 10)
    assert all(r.url.path != "/v1/compliance/activities" for r in seen)


def test_sentinelone_reads_the_unified_alerts_the_threats_api_leaves_out(monkeypatch):
    alerts = {
        "data": {
            "alerts": {
                "pageInfo": {"hasNextPage": True, "endCursor": "c2"},
                "edges": [
                    {
                        "node": {
                            "id": "u1",
                            "name": "STAR rule",
                            "severity": "HIGH",
                            "detectedAt": "2026-09-20T10:00:00Z",
                            "updatedAt": "2026-09-20T10:30:00Z",
                        }
                    }
                ],
            }
        }
    }
    seen = transport(monkeypatch, [{"json": {"data": []}}, {"json": alerts}])
    page = connectors.get("sentinelone").fetch(
        {"console_url": "https://acme.sentinelone.net"},
        {"api_token": "tok"},
        {"streams": {"alerts": {"since": SINCE}}},
        10,
    )
    graphql = seen[1]
    assert graphql.url.path == "/web/api/v2.1/unifiedalerts/graphql"
    assert graphql.headers["authorization"] == "Bearer tok"
    variables = json.loads(graphql.content)["variables"]
    assert variables["sort"] == {"by": "updatedAt", "order": "ASC"}
    assert variables["filters"][0]["fieldId"] == "updatedAt"
    start = variables["filters"][0]["dateTimeRange"]["start"]
    assert start == int(datetime.fromisoformat(REREAD).timestamp() * 1000)
    assert page.records[0]["_stream"] == "unified_alerts" and "_update" not in page.records[0]
    assert page.cursor["streams"]["alerts"]["after"] == "c2" and page.more
    assert page.cursor["streams"]["alerts"]["newest"] == "2026-09-20T10:30:00Z"
    row = ocsf.load_mapping("sentinelone").map_record(page.records[0], "t1")
    assert row["time"].startswith("2026-09-20T10:30:00"), "a unified alert's time is its update"
    assert row["activity_id"] == 1
