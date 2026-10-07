"""Cloudflare, Tailscale, Stripe, OpenAI and Anthropic: what each connector asks
for and where it leaves the cursor (ING-1), and what each action sends (RSP-4)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from shoc.actions import get
from shoc.actions.base import Credentials
from shoc.errors import ConfigError, ValidationError
from shoc.ingest import connectors
from shoc.ingest.connectors import base, tailscale
from shoc.ingest.connectors.stripe import PREVIEW
from tests.unit.test_connectors import SINCE, query, transport


def epoch(iso: str) -> str:
    return str(int(datetime.fromisoformat(iso).timestamp()))


# -- Cloudflare --------------------------------------------------------------


def test_cloudflare_holds_the_window_while_following_the_cursor(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "result": [{"id": "a1", "action": {"time": "2026-09-20T10:00:00Z"}}],
                    "result_info": {"cursor": "c2"},
                }
            },
            {
                "json": {
                    "result": [{"id": "a2", "action": {"time": "2026-09-20T10:05:00Z"}}],
                    "result_info": {"cursor": ""},
                }
            },
        ],
    )
    connector = connectors.get("cloudflare")
    settings, secret = {"account_id": "acc1"}, {"api_token": "tok"}
    first = connector.fetch(settings, secret, {"since": SINCE}, 5000)
    asked = query(seen[0])
    assert seen[0].url.path == "/client/v4/accounts/acc1/logs/audit"
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert asked["since"] == SINCE and asked["direction"] == "asc" and asked["limit"] == "1000"
    assert first.more and first.cursor["page"] == "c2" and first.cursor["since"] == SINCE

    second = connector.fetch(settings, secret, first.cursor, 5000)
    assert query(seen[1])["cursor"] == "c2"
    assert query(seen[1])["before"] == asked["before"], "the window is held while paging"
    assert second.more is False and second.cursor == {"since": "2026-09-20T10:05:00Z"}


def test_cloudflare_needs_an_account_and_a_token():
    with pytest.raises(ConfigError, match="account_id"):
        connectors.get("cloudflare").fetch({}, {"api_token": "t"}, {}, 10)


# -- Tailscale ---------------------------------------------------------------


def test_tailscale_reads_a_bounded_window_and_names_each_event(monkeypatch):
    tailscale._TOKENS.clear()
    seen = transport(
        monkeypatch,
        [
            {"json": {"access_token": "minted", "expires_in": 3600}},
            {
                "json": {
                    "version": "1.1",
                    "tailnetId": "T1CNTRL",
                    "logs": [
                        {
                            "action": "UPDATE",
                            "type": "CONFIG",
                            "eventTime": "2026-09-20T09:30:00Z",
                            "target": {"id": "T1CNTRL", "type": "TAILNET", "property": "ACL"},
                        },
                    ],
                }
            },
        ],
    )
    secret = {"client_id": "k123", "client_secret": "tskey-client-x"}
    page = connectors.get("tailscale").fetch({}, secret, {"since": SINCE}, 1000)
    token, logs = seen
    assert token.url.path == "/api/v2/oauth/token"
    assert logs.url.path == "/api/v2/tailnet/-/logging/configuration"
    assert query(logs) == {"start": "2026-09-20T09:00:00Z", "end": "2026-09-20T15:00:00Z"}
    assert logs.headers["authorization"] == "Bearer minted"
    assert page.records[0]["event"] == "TAILNET.UPDATE.ACL"
    assert page.records[0]["tailnet"] == "T1CNTRL"
    assert page.more and page.cursor == {"since": "2026-09-20T15:00:00+00:00"}


def test_a_tailscale_access_token_is_used_as_given():
    assert tailscale.access_token({"api_key": "tskey-api-x"}) == "tskey-api-x"
    with pytest.raises(ConfigError):
        tailscale.access_token({})


# -- Stripe ------------------------------------------------------------------


def test_stripe_reads_the_activity_log_and_payment_events_each_with_its_cursor(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "data": [{"id": "accact_1"}],
                    "next_page_url": "/v2/iam/activity_logs?page=p2",
                }
            },
            {
                "json": {
                    "data": [
                        {"id": "evt_2", "created": 1790000300},
                        {"id": "evt_1", "created": 1790000000},
                    ],
                    "has_more": True,
                }
            },
        ],
    )
    page = connectors.get("stripe").fetch(
        {}, {"api_key": "rk_test"}, {"events": {"since": SINCE}}, 2
    )
    logs, events = seen
    assert logs.url.path == "/v2/iam/activity_logs" and logs.headers["stripe-version"] == PREVIEW
    assert events.url.path == "/v1/events" and "stripe-version" not in events.headers
    assert events.url.params.get_list("types[]") == [
        "charge.failed",
        "radar.early_fraud_warning.created",
    ]
    assert events.url.params["created[gt]"] == epoch(SINCE)
    assert page.cursor["logs"] == {"next": "/v2/iam/activity_logs?page=p2"}
    held = page.cursor["events"]
    assert held["since"] == SINCE and held["after"] == "evt_1", "paging back, newest first"
    assert page.more


def test_stripe_starts_the_activity_log_again_once_its_page_expired(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {"status": 400, "json": {"error": {"code": "invalid_filters"}}},
            {"json": {"data": [], "next_page_url": "/v2/iam/activity_logs?page=p9"}},
            {"json": {"data": [], "has_more": False}},
        ],
    )
    stale = {"logs": {"next": "/v2/iam/activity_logs?page=old"}}
    page = connectors.get("stripe").fetch({}, {"api_key": "rk"}, stale, 100)
    assert seen[0].url.params["page"] == "old" and "page" not in seen[1].url.params
    assert page.cursor["logs"] == {"next": "/v2/iam/activity_logs?page=p9"}


# -- OpenAI and Anthropic ------------------------------------------------------


def test_openai_reads_the_audit_log_and_settled_hours_of_key_usage(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "data": [
                        {
                            "id": "audit_log-1",
                            "type": "api_key.created",
                            "effective_at": 1790000000,
                            "api_key.created": {"id": "key_new"},
                        }
                    ],
                    "has_more": False,
                }
            },
            {
                "json": {
                    "data": [
                        {
                            "start_time": 1790002800,
                            "end_time": 1790006400,
                            "results": [
                                {
                                    "api_key_id": "key_new",
                                    "project_id": "proj_1",
                                    "output_tokens": 10,
                                }
                            ],
                        }
                    ],
                    "has_more": False,
                }
            },
        ],
    )
    hour = "2026-09-20T09:00:00+00:00"
    cursor = {"audit": {"since": SINCE}, "usage": {"since": hour}}
    page = connectors.get("openai").fetch({}, {"admin_key": "sk-admin"}, cursor, 1000)
    audit, usage = seen
    assert audit.url.path == "/v1/organization/audit_logs"
    assert (
        audit.url.params["effective_at[gt]"] == epoch(SINCE) and audit.url.params["limit"] == "100"
    )
    entry, spent = page.records
    assert entry["details"] == {"id": "key_new"} and entry["key_id"] == "key_new"
    newest = datetime.fromtimestamp(1790000000, tz=UTC).isoformat()
    assert page.cursor["audit"] == {"since": base.resume(SINCE, newest)}

    assert usage.url.path == "/v1/organization/usage/completions"
    assert usage.url.params.get_list("group_by[]") == ["api_key_id", "project_id"]
    assert usage.url.params["start_time"] == epoch(hour) and usage.url.params["limit"] == "168"
    began = datetime.fromtimestamp(1790002800, tz=UTC).isoformat()
    assert spent["event"] == "usage" and spent["key_id"] == "key_new"
    assert spent["id"] == f"openai-usage-key_new-proj_1-{began}"
    assert page.cursor["usage"] == {"since": "2026-09-27T09:00:00+00:00"}, "a week at most"


def test_anthropic_reports_the_keys_created_since_the_cursor(monkeypatch):
    seen = transport(
        monkeypatch,
        [
            {
                "json": {
                    "data": [
                        {"id": "apikey_old", "created_at": "2026-09-19T00:00:00Z"},
                        {"id": "apikey_new", "created_at": "2026-09-20T10:00:00Z"},
                    ],
                    "has_more": False,
                }
            },
            {"json": {"data": [], "has_more": False}},
        ],
    )
    hour = "2026-09-20T09:00:00+00:00"
    cursor = {"keys": {"since": SINCE}, "usage": {"since": hour}}
    page = connectors.get("anthropic").fetch({}, {"admin_key": "sk-ant-admin01-x"}, cursor, 1000)
    keys, usage = seen
    assert keys.url.path == "/v1/organizations/api_keys"
    assert keys.headers["x-api-key"] == "sk-ant-admin01-x"
    assert keys.headers["anthropic-version"] == "2023-06-01"
    assert [(r["key_id"], r["event"]) for r in page.records] == [("apikey_new", "api_key.created")]
    assert page.cursor["keys"] == {"since": "2026-09-20T10:00:00Z"}
    assert usage.url.path == "/v1/organizations/usage_report/messages"
    assert usage.url.params["starting_at"] == hour
    assert usage.url.params.get_list("group_by[]") == ["api_key_id"]


def test_an_hour_of_usage_is_read_only_once_it_has_settled(monkeypatch):
    seen = transport(monkeypatch, [{"json": {"data": [], "has_more": False}}])
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0).isoformat()
    cursor = {"keys": {"since": SINCE}, "usage": {"since": now}}
    page = connectors.get("anthropic").fetch({}, {"admin_key": "k"}, cursor, 10)
    assert [r.url.path for r in seen] == ["/v1/organizations/api_keys"]
    assert page.cursor["usage"] == {"since": now}


def test_a_first_usage_read_takes_a_week_whatever_the_backfill(monkeypatch):
    """The usage rules compare a key with its own week (`first_seen`, 7d)."""
    seen = transport(monkeypatch, [{"json": {"data": [], "has_more": False}}] * 2)
    connectors.get("openai").fetch({"backfill_hours": 2}, {"admin_key": "k"}, {}, 10)
    usage = next(r for r in seen if r.url.path.endswith("/usage/completions"))
    began = datetime.fromtimestamp(int(usage.url.params["start_time"]), tz=UTC)
    assert timedelta(days=7) <= datetime.now(UTC) - began < timedelta(days=7, hours=1)


# -- actions -------------------------------------------------------------------


def scripted(replies: list[Any]) -> tuple[list[httpx.Request], httpx.Client]:
    seen: list[httpx.Request] = []
    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=queue.pop(0) if queue else {})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_a_cloudflare_token_is_disabled_as_it_was_and_enabled_again():
    token = {
        "id": "t1",
        "name": "ci",
        "status": "active",
        "issued_on": "2026-01-01",
        "policies": [{"effect": "allow", "resources": {}}],
        "condition": {"request_ip": {"in": ["192.0.2.0/24"]}},
    }
    creds = Credentials("cloudflare", settings={"account_id": "acc1"}, secret={"api_token": "tok"})
    action = get("cloudflare.disable_api_token")
    seen, client = scripted([{"result": token}, {"result": {}}])
    result = action.execute(creds, {"token_id": "t1"}, client)
    put = seen[1]
    assert put.method == "PUT" and put.url.path == "/client/v4/accounts/acc1/tokens/t1"
    assert json.loads(put.content) == {
        "name": "ci",
        "policies": token["policies"],
        "condition": token["condition"],
        "status": "disabled",
    }
    assert result.undo == {"token_id": "t1", "status": "active"}
    seen, client = scripted([{"result": {**token, "status": "disabled"}}, {"result": {}}])
    action.undo(creds, result.undo, client)
    assert json.loads(seen[1].content)["status"] == "active"


def test_a_tailscale_device_is_deauthorized_and_authorized_again():
    creds = Credentials("tailscale", secret={"api_key": "tskey-api-x"})
    action = get("tailscale.deauthorize_device")
    seen, client = scripted([{}, {}])
    action.undo(creds, action.execute(creds, {"device_id": "n123CNTRL"}, client).undo, client)
    assert seen[0].url.path == "/api/v2/device/n123CNTRL/authorized"
    assert seen[0].headers["authorization"] == "Bearer tskey-api-x"
    assert [json.loads(r.content) for r in seen] == [{"authorized": False}, {"authorized": True}]


def test_suspending_a_tailscale_user_finds_the_id_behind_the_login():
    creds = Credentials("tailscale", secret={"api_key": "k"})
    action = get("tailscale.suspend_user")
    seen, client = scripted([{"users": [{"id": "u9", "loginName": "mallory@example.com"}]}])
    action.undo(creds, action.execute(creds, {"user": "mallory@example.com"}, client).undo, client)
    assert [r.url.path for r in seen] == [
        "/api/v2/tailnet/-/users",
        "/api/v2/users/u9/suspend",
        "/api/v2/users/u9/restore",
    ]


def test_a_fraudulent_charge_puts_its_card_and_email_on_radar_block_lists():
    lists = {
        "data": [
            {"id": "rsl_allow", "name": "Allowed emails", "item_type": "email"},
            {
                "id": "rsl_card",
                "alias": "card_fingerprint_block_list",
                "item_type": "card_fingerprint",
            },
            {"id": "rsl_mail", "name": "Blocked emails", "item_type": "email"},
        ]
    }
    charge = {
        "id": "ch_1",
        "payment_method_details": {"card": {"fingerprint": "fp1"}},
        "billing_details": {"email": "thief@example.net"},
    }
    seen, client = scripted([charge, lists, {"id": "rsli_1"}, lists, {"id": "rsli_2"}])
    creds = Credentials("stripe", secret={"api_key": "rk_live_x"})
    action = get("stripe.block_charge_card")
    result = action.execute(creds, {"charge": "ch_1"}, client)
    posted = [r.content for r in seen if r.method == "POST"]
    assert posted == [
        b"value_list=rsl_card&value=fp1",
        b"value_list=rsl_mail&value=thief%40example.net",
    ]
    seen, client = scripted([])
    action.undo(creds, result.undo, client)
    assert [(r.method, r.url.path) for r in seen] == [
        ("DELETE", "/v1/radar/value_list_items/rsli_1"),
        ("DELETE", "/v1/radar/value_list_items/rsli_2"),
    ]
    with pytest.raises(ValidationError):
        action.execute(creds, {"charge": "../accounts"}, client)


def test_a_claude_key_is_disabled_and_enabled_again():
    creds = Credentials("anthropic", secret={"admin_key": "sk-ant-admin01-x"})
    action = get("anthropic.disable_api_key")
    seen, client = scripted([{"status": "active"}])
    action.undo(creds, action.execute(creds, {"key_id": "apikey_1"}, client).undo, client)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/v1/organizations/api_keys/apikey_1"),
        ("POST", "/v1/organizations/api_keys/apikey_1"),
        ("POST", "/v1/organizations/api_keys/apikey_1"),
    ]
    assert seen[0].headers["x-api-key"] == "sk-ant-admin01-x"
    assert [json.loads(r.content) for r in seen[1:]] == [
        {"status": "inactive"},
        {"status": "active"},
    ]


def test_an_openai_key_can_only_be_deleted_and_waits_for_a_human():
    creds = Credentials("openai", secret={"admin_key": "sk-admin"})
    action = get("openai.delete_api_key")
    seen, client = scripted([{"deleted": True}])
    action.execute(creds, {"key_id": "key_1", "project_id": "proj_1"}, client)
    assert (seen[0].method, seen[0].url.path) == (
        "DELETE",
        "/v1/organization/projects/proj_1/api_keys/key_1",
    )
    assert not action.reversible
