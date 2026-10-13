"""What serve, worker, migrate and mcp check and set up as they start (OPS-1, SEC-1)."""

from __future__ import annotations

import argparse
import logging

import pytest

from shoc.config import Config
from shoc.db import secrets
from shoc.errors import ConfigError


# -- the master key (sre-7) ---------------------------------------------------
@pytest.fixture
def strict(monkeypatch):
    monkeypatch.delenv("SHOC_ALLOW_WEAK_KEY", raising=False)


def test_the_example_master_key_is_refused(strict):
    with pytest.raises(ConfigError, match="shoc keygen"):
        secrets.check_master_key("replace-me")


def test_a_short_key_in_use_is_warned_about_but_still_starts(strict, caplog):
    """An install keyed before the check must survive the upgrade that adds it."""
    with caplog.at_level(logging.WARNING, logger="shoc"):
        secrets.check_master_key("a-passphrase-of-31-characters!!")
    assert "shoc rotate-key" in caplog.text


def test_a_short_new_key_is_refused(strict):
    with pytest.raises(ConfigError, match="SHOC_NEW_MASTER_KEY"):
        secrets.check_master_key("a-passphrase-of-31-characters!!", "SHOC_NEW_MASTER_KEY", new=True)


def test_the_key_keygen_prints_is_accepted(strict):
    secrets.check_master_key(secrets.generate_key())


def test_an_unset_key_is_left_to_the_paths_that_need_one(strict):
    secrets.check_master_key("")


def test_tests_can_allow_a_short_key(monkeypatch):
    monkeypatch.setenv("SHOC_ALLOW_WEAK_KEY", "1")
    secrets.check_master_key("replace-me")


def test_migrate_refuses_the_example_key_before_it_keys_anything(strict, monkeypatch, capsys):
    """`cp .env.example .env && docker compose up -d` sealed every secret with a public key."""
    from shoc.cli import main
    from shoc.db import pool

    monkeypatch.setenv("SHOC_MASTER_KEY", "replace-me")
    monkeypatch.setenv("SHOC_DSN", "postgresql://shoc@192.0.2.10/shoc")
    monkeypatch.setattr(pool, "connect_owner", lambda *a, **k: pytest.fail("migrate connected"))
    assert main(["migrate"]) == 1
    assert "SHOC_MASTER_KEY" in capsys.readouterr().err


def test_rotate_key_refuses_a_short_new_key(strict, monkeypatch):
    from shoc.cli import cmd_rotate_key

    cfg = Config()
    cfg.master_key = "replace-me"
    monkeypatch.setenv("SHOC_NEW_MASTER_KEY", "still-short")
    with pytest.raises(ConfigError, match="SHOC_NEW_MASTER_KEY"):
        cmd_rotate_key(argparse.Namespace(), cfg)


# -- rules check (qa-10) ------------------------------------------------------
def test_rules_check_fails_when_it_finds_no_rules(tmp_path, capsys):
    """An image that lost content/ started with nothing to detect, and CI stayed green."""
    from shoc.cli import cmd_rules_check

    cfg = Config()
    cfg.content_dir = tmp_path
    assert cmd_rules_check(argparse.Namespace(), cfg) == 1
    assert "no rules" in capsys.readouterr().out


# -- logging (sre-23) ---------------------------------------------------------
@pytest.fixture
def configured(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(logging, "basicConfig", lambda **kw: seen.append(kw))
    return seen


@pytest.fixture
def lists(monkeypatch):
    """The lists serve and mcp start loading; nothing is downloaded here."""
    from shoc.detect import osint

    started: list[str] = []
    monkeypatch.delenv("SHOC_INTEL_FEEDS", raising=False)
    monkeypatch.setattr(osint, "load_soon", lambda key, wait=0.0: bool(started.append(key)))
    return started


def test_serve_logs_with_time_level_and_logger(configured, lists, monkeypatch):
    """uvicorn configures only its own loggers; shoc.* INFO lines were dropped."""
    import uvicorn

    from shoc.api import rest
    from shoc.cli import main

    for name in ("SHOC_DSN", "SHOC_MASTER_KEY", "SHOC_BIND", "SHOC_TOKENS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(rest, "build_app", lambda cfg: None)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    assert main(["serve"]) == 0
    assert configured and configured[0]["level"] == logging.INFO
    assert "%(name)s" in configured[0]["format"] and "%(asctime)s" in configured[0]["format"]
    assert lists == ["warninglists", "rdap_bootstrap"], "a digest after a restart is checked"


def test_uvicorns_trace_level_does_not_crash_serve(configured):
    from shoc.cli import _setup_logging

    _setup_logging("trace")
    assert configured[0]["level"] == logging.DEBUG


def test_mcp_logs_to_stderr_in_the_same_format(configured, lists, monkeypatch):
    from shoc.api import mcp
    from shoc.cli import main

    async def nothing(cfg):
        return None

    monkeypatch.setattr(mcp, "serve_stdio", nothing)
    assert main(["mcp"]) == 0
    assert configured and "stream" not in configured[0], "stderr, so stdout stays MCP's"
    assert "%(name)s" in configured[0]["format"]
    assert lists == ["warninglists", "rdap_bootstrap"]


def test_no_list_loads_with_the_feeds_off(lists):
    from shoc.cli import _warm_lists

    cfg = Config()
    cfg.intel_feeds = "off"
    _warm_lists(cfg)
    assert lists == [], "SHOC_INTEL_FEEDS=off reaches no host nobody configured"


# -- the owner warning (po-10) ------------------------------------------------
@pytest.mark.parametrize("owner", [True, False])
def test_migrate_warns_only_when_the_runtime_role_owns_the_schema(owner, monkeypatch, capsys):
    """`docker compose run shoc migrate` runs as shoc_app, which owns nothing."""
    import contextlib
    from types import SimpleNamespace

    from shoc import store
    from shoc.cli import OWNER_WARNING, cmd_migrate
    from shoc.db import migrate, pool

    cursor = SimpleNamespace(execute=lambda *a: None)
    conn = SimpleNamespace(cursor=lambda: contextlib.nullcontext(cursor))
    monkeypatch.setattr(pool, "connect_owner", lambda cfg: conn)
    monkeypatch.setattr(pool, "connect", lambda cfg: conn)
    monkeypatch.setattr(pool, "set_tenant", lambda *a: None)
    monkeypatch.setattr(pool, "fetch_one", lambda *a, **k: {"me": "shoc_app"})
    monkeypatch.setattr(pool, "owns_audit_log", lambda c: owner)
    monkeypatch.setattr(pool, "is_superuser", lambda c: False)
    monkeypatch.setattr(pool, "fetch_all", lambda *a, **k: [])
    monkeypatch.setattr(migrate, "migrate", lambda c: [])
    monkeypatch.setattr(
        store, "open_store", lambda cfg, tenant=None: SimpleNamespace(migrate=lambda: None)
    )
    cfg = Config()
    cfg.dsn, cfg.migrate_dsn, cfg.readonly_dsn = "postgresql://shoc_app@192.0.2.10/shoc", "", ""
    cfg.master_key = secrets.generate_key()
    assert cmd_migrate(argparse.Namespace(), cfg) == 0
    assert (OWNER_WARNING in capsys.readouterr().err) is owner


def test_migrate_reaches_every_tenant_on_its_backend(monkeypatch, capsys):
    """data-6: the worker loads for every registered tenant, so each gets the new columns."""
    from types import SimpleNamespace

    from shoc import store
    from shoc.cli import _migrate_other_tenants
    from shoc.db import pool

    rows = [
        {"tenant_id": "lab", "backend": "postgres"},
        {"tenant_id": "wh", "backend": "databricks"},
        {"tenant_id": "gone", "backend": "postgres"},
    ]
    monkeypatch.setattr(pool, "fetch_all", lambda *a, **k: rows)
    migrated: list[str] = []

    def opened(cfg, tenant=None):
        def run() -> None:
            if tenant == "gone":
                raise RuntimeError("no such schema")
            migrated.append(str(tenant))

        return SimpleNamespace(migrate=run, close=lambda: None)

    monkeypatch.setattr(store, "open_store", opened)
    cfg = Config()
    cfg.backend = "postgres"
    _migrate_other_tenants(object(), cfg)
    out = capsys.readouterr()
    assert migrated == ["lab"], "a tenant on another backend is not opened on this one"
    assert "tenant 'wh' is on databricks" in out.out
    assert "tenant 'gone' was not migrated" in out.err


# -- session limits (data-14) ---------------------------------------------------
def test_control_plane_sessions_carry_lock_and_idle_limits(monkeypatch):
    """Set once connected: libpq's `options` replaced the DSN's own, and PgBouncer refuses it."""
    from typing import Any

    from shoc.db import pool

    sent: list[tuple[str, Any]] = []
    monkeypatch.setattr(pool, "execute", lambda conn, sql, params=None: sent.append((sql, params)))
    cfg = Config()
    cfg.statement_timeout_seconds = 45
    conn: Any = object()
    assert pool.limit(conn, cfg) is conn
    [(sql, params)] = sent
    assert "'statement_timeout', %s" in sql and params == ("45000",)
    assert "'lock_timeout', '10s'" in sql
    assert "'idle_in_transaction_session_timeout', '5min'" in sql
