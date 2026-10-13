"""Hostile or broken requests to serve, and audited changes that fail (API-1, SEC-1)."""

from __future__ import annotations

import json
import logging

import pytest
from starlette.testclient import TestClient

from shoc.api import auth, people, rest
from shoc.api.rest import build_app
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.errors import ConfigError
from tests.support import audit_seq

pytestmark = pytest.mark.postgres

LOCAL = "http://localhost"
JSON = {"content-type": "application/json"}


def chunked(size: int):
    """A body sent without a Content-Length, as a chunked upload is."""
    yield b"x" * size


@pytest.fixture
def api(config, conn, store, clean, monkeypatch):
    monkeypatch.setattr(config, "max_request_bytes", 1024)
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        yield client


# -- bodies -----------------------------------------------------------------------
def test_a_chunked_body_is_counted_as_it_arrives(api):
    answer = api.post("/v1/finding/list", content=chunked(2048), headers=JSON)
    assert answer.status_code == 413 and answer.json()["error"]["code"] == "payload_too_large"


def test_slack_takes_a_few_kilobytes_and_no_more(api):
    answer = api.post("/slack/commands", content=chunked(rest.SLACK_MAX_BODY + 1))
    assert answer.status_code == 413


def test_the_body_is_read_only_once_the_caller_is_known(config, conn, store, clean, monkeypatch):
    monkeypatch.setattr(config, "max_request_bytes", 1024)
    monkeypatch.setenv(
        "SHOC_TOKENS",
        json.dumps({"tok-read": {"kind": "service", "id": "ci", "scopes": ["findings:read"]}}),
    )
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        answer = client.post("/v1/finding/list", content=b"x" * 2048, headers=JSON)
        assert answer.status_code == 401, "an unknown caller is refused before its body is read"


# -- errors -----------------------------------------------------------------------
def test_an_unexpected_error_is_logged_and_never_returned(api, monkeypatch, caplog):
    def down(*args, **kwargs):
        raise RuntimeError('password authentication failed for user "shoc_app"')

    monkeypatch.setattr(rest, "authenticate", down)
    with caplog.at_level(logging.ERROR, logger="shoc.serve"):
        for answer in (
            api.post("/v1/finding/list", json={}),
            api.get("/metrics"),
            api.get("/v1/stream"),
            api.post("/mcp/", json={}),
        ):
            error = answer.json()["error"]
            assert answer.status_code == 500 and error["code"] == "internal_error"
            assert "shoc_app" not in error["message"]
            request_id = error["message"].rpartition("(")[2].rstrip(")")
            assert request_id and request_id in caplog.text and "shoc_app" in caplog.text


def test_serve_will_not_start_on_a_key_the_audit_log_was_not_keyed_with(config, conn, monkeypatch):
    monkeypatch.setenv("SHOC_MASTER_KEY", "not-the-key-migrate-recorded")
    with pytest.raises(ConfigError, match="SHOC_MASTER_KEY"), TestClient(build_app(config)):
        pass


# -- audited changes --------------------------------------------------------------
@pytest.fixture
def accounts(config, conn, clean, monkeypatch):
    """No account or token in the tenant before and after, so single-user mode comes back."""
    monkeypatch.setattr(config, "public_url", "https://shoc.example.com")
    monkeypatch.setattr(config, "smtp_url", "")

    def forget() -> None:
        for table in ("user_links", "users", "api_tokens"):
            execute(conn, f"DELETE FROM shoc.{table} WHERE tenant_id = %s", (config.tenant_id,))
        auth._issued = False

    forget()
    yield
    forget()


def test_a_disable_that_fails_halfway_changes_nothing_and_is_audited(
    ctx, conn, accounts, monkeypatch
):
    call("user.invite", ctx, {"email": "bob@example.com"})

    def lost(*args):
        raise RuntimeError("server closed the connection unexpectedly")

    monkeypatch.setattr(people, "revoke_person", lost)
    after = audit_seq(conn, ctx.tenant_id)
    with pytest.raises(RuntimeError):
        call("user.update", ctx, {"email": "bob@example.com", "disabled": True})
    row = fetch_one(
        conn,
        "SELECT disabled_at FROM shoc.users WHERE tenant_id = %s AND email = %s",
        (ctx.tenant_id, "bob@example.com"),
    )
    assert row and row["disabled_at"] is None, "half a disable is no disable"
    rows = fetch_all(
        conn,
        "SELECT capability, error FROM shoc.audit_log WHERE tenant_id = %s AND seq > %s",
        (ctx.tenant_id, after),
    )
    assert rows == [{"capability": "user.update", "error": "RuntimeError"}]
