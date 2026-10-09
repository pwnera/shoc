"""Each connector reads the way its vendor documents for a SIEM (ING-1)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors
from tests.unit.test_connectors import SINCE, query, transport


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
    assert body["query"] == {"range": {"timestamp": {"gt": SINCE}}}
    assert body["sort"] == [{"timestamp": "asc"}, {"id": "asc"}] and body["size"] == 2
    assert [r["id"] for r in first.records] == ["a0", "a1"]
    assert first.more and first.cursor["after"] == hits[1]["sort"]
    assert first.cursor["since"] == SINCE, "held while paging"

    second = connector.fetch(settings, secret, first.cursor, 2)
    assert json.loads(seen[1].content)["search_after"] == hits[1]["sort"]
    assert second.more is False and second.cursor == {"since": "2026-09-20T10:01:00.000+0000"}


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
            {"json": {}},
            {"json": {"receivedMessages": [{"ackId": "k2", "message": {"data": data}}]}},
            {"json": {}},
        ],
    )
    sub = "projects/acme/subscriptions/shoc-audit"
    page = connectors.get("gcp_audit").fetch({"subscription": sub}, {}, {"ack": ["k1"]}, 10)
    acked, pulled, held = seen
    assert acked.url.path == f"/v1/{sub}:acknowledge" and json.loads(acked.content) == {
        "ackIds": ["k1"]
    }, "the page before was loaded, so it is acknowledged now"
    assert pulled.url.path == f"/v1/{sub}:pull"
    assert held.url.path == f"/v1/{sub}:modifyAckDeadline"
    assert json.loads(held.content) == {"ackIds": ["k2"], "ackDeadlineSeconds": 600}
    assert page.records == [entry] and page.cursor == {"ack": ["k2"]} and page.more is False


def test_entra_reads_the_sign_ins_graph_v1_leaves_out(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.entra.access_token", lambda secret: "tok")
    seen = transport(monkeypatch, [{"json": {"value": []}}])
    connectors.get("entra").fetch({"stream": "servicePrincipalSignIns"}, {}, {"since": SINCE}, 10)
    assert seen[0].url.path == "/beta/auditLogs/signIns"
    assert query(seen[0])["$filter"] == (
        f"createdDateTime gt {SINCE} and signInEventTypes/any(t: t eq 'servicePrincipal')"
    )


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
        {"alerts": {"since": SINCE}},
        10,
    )
    graphql = seen[1]
    assert graphql.url.path == "/web/api/v2.1/unifiedalerts/graphql"
    assert graphql.headers["authorization"] == "Bearer tok"
    variables = json.loads(graphql.content)["variables"]
    assert variables["sort"] == {"by": "detectedAt", "order": "ASC"}
    start = variables["filters"][0]["dateTimeRange"]["start"]
    assert start == int(datetime.fromisoformat(SINCE).timestamp() * 1000)
    assert page.records[0]["_stream"] == "unified_alerts"
    assert page.cursor["alerts"]["after"] == "c2" and page.more
