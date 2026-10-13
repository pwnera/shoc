"""What a request leaves behind, and where a kept secret may go (STO-4, SEC-1)."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from shoc.api.mcp import tool_hints
from shoc.capabilities.registry import Caller, Context, get
from shoc.cases import credentials
from shoc.errors import ValidationError
from shoc.store.snowflake import SnowflakeStore


class Closable:
    closed = 0

    def close(self) -> None:
        self.closed += 1


def test_a_context_closes_the_store_it_opened_and_no_other(monkeypatch):
    opened = Closable()
    monkeypatch.setattr("shoc.store.open_store", lambda *a, **k: opened)
    ctx = Context(tenant_id="acme", caller=Caller())
    assert ctx.store is opened
    ctx.close()
    ctx.close()
    assert opened.closed == 1 and ctx._store is None

    lent = Closable()
    Context(tenant_id="acme", caller=Caller(), _store=lent).close()
    assert lent.closed == 0, "a store handed in belongs to whoever handed it in"


def test_snowflake_shares_one_staging_dir_and_keeps_no_session_alive(monkeypatch):
    """A store per request made a directory each, and a heartbeat thread held each session."""
    given: dict[str, Any] = {}
    connector = SimpleNamespace(connect=lambda **kw: given.update(kw) or Closable())
    monkeypatch.setitem(sys.modules, "snowflake", SimpleNamespace(connector=connector))
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)
    first = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    second = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    assert first._staging_dir == second._staging_dir
    assert first.conn is not None
    assert "client_session_keep_alive" not in given


def test_retain_is_marked_destructive_for_mcp_clients():
    """Deleting events cannot be undone; a client that auto-approves non-destructive
    tools would run it unasked."""
    assert tool_hints(get("events.retain"))["destructiveHint"] is True


@pytest.mark.parametrize(
    ("name", "stored", "moved"),
    [
        ("org_url", "https://acme.okta.com", "https://okta.example.net"),  # okta
        ("base_url", "https://gitlab.com", "https://gitlab.example.net"),  # gitlab, crowdstrike
        ("indexer_url", "https://198.51.100.7:9200", "https://203.0.113.9:9200"),  # wazuh
        ("console_url", "https://acme.sentinelone.net", "https://s1.example.net"),
        ("url", "https://misp.example.org", "https://misp.example.net"),  # intel feeds
        ("cloud", "eu-1", "us-1"),  # crowdstrike
        ("storage_account", "acmelogs", "otherlogs"),  # defender hunting export
        ("base_url", "https://acme.okta.com", "https://acme.okta.com@203.0.113.9"),
        ("org_url", "https://acme.okta.com", "http://acme.okta.com"),  # in clear
        ("indexer_url", "https://198.51.100.7:9200", "https://198.51.100.7:9201"),
    ],
)
def test_a_kept_secret_never_follows_a_setting_to_another_host(name, stored, moved):
    same = stored + "/" if "://" in stored else stored.upper()
    credentials.same_host({name: stored}, {name: same})
    with pytest.raises(ValidationError, match=name):
        credentials.same_host({name: stored}, {name: moved})
    with pytest.raises(ValidationError, match=name):
        credentials.same_host({}, {name: moved})


def test_a_default_port_written_out_is_the_same_place():
    stored = {"org_url": "https://acme.okta.com"}
    credentials.same_host(stored, {"org_url": "https://acme.okta.com:443"})


def test_a_store_that_fails_to_close_fails_no_call(monkeypatch):
    """A Databricks session close lost on a blip turned a committed write into a 500."""

    class Broken:
        def close(self) -> None:
            raise OSError("connection reset")

    monkeypatch.setattr("shoc.store.open_store", lambda *a, **k: Broken())
    ctx = Context(tenant_id="acme", caller=Caller())
    assert isinstance(ctx.store, Broken)
    ctx.close()
    assert ctx._store is None


def test_settings_that_name_no_host_change_freely():
    credentials.same_host(
        {"org": "acme", "accounts": ["111111111111"], "verify_tls": True},
        {"org": "acme-two", "accounts": [], "per_day": 500},
    )
