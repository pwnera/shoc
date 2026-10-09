"""`shoc plan` and `shoc apply` (API-4)."""

from __future__ import annotations

import pytest

from shoc import configcode
from shoc.api.auth import role_caller
from shoc.capabilities.registry import Caller, Context, call
from shoc.db.pool import fetch_all, fetch_one
from shoc.errors import ConfigError, Denied, ValidationError

pytestmark = pytest.mark.postgres

CONFIG = {
    "version": 1,
    "retention_days": 30,
    "sources": [
        {
            "source": "okta",
            "settings": {"org_url": "https://acme.okta.com"},
            "secret_env": {"api_token": "SHOC_SECRET_TEST_OKTA_TOKEN"},
            "interval_seconds": 1800,
        }
    ],
    "intel_feeds": [{"feed": "abuse_ch_urlhaus"}],
}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SHOC_SECRET_TEST_OKTA_TOKEN", "00-token")


@pytest.fixture(autouse=True)
def no_retention_yet(conn, config):
    conn.execute(
        "DELETE FROM shoc.schedules WHERE schedule_id = %s", (f"{config.tenant_id}:retention",)
    )


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    """Apply verifies each source's credential; answer that probe here, not at acme.okta.com."""
    from shoc.ingest.connectors import okta
    from shoc.ingest.connectors.base import FetchResult

    seen: list[str] = []

    def fetch(settings, secret, cursor, limit):
        seen.append(settings["org_url"])
        return FetchResult()

    monkeypatch.setattr(okta.CONNECTOR, "fetch", fetch)
    return seen


def test_a_plan_on_an_empty_deployment_is_all_creates(ctx, config, clean):
    result = call("config.plan", ctx, {"config": CONFIG})
    actions = {(c["kind"], c["target"]): c["action"] for c in result.data.changes}
    assert actions[("source", "okta")] == "create"
    assert actions[("intel_feed", "abuse_ch_urlhaus")] == "create"
    assert actions[("retention", "30d")] == "update"
    assert result.data.invalid == 0


def test_the_plan_validates_content_before_anything_else(ctx, config, clean):
    result = call("config.plan", ctx, {"config": CONFIG})
    content = {c["target"]: c for c in result.data.changes if c["kind"] == "content"}
    assert set(content) == {"rules", "playbooks", "policy"}
    assert "compile" in content["rules"]["detail"]
    assert all(c["action"] == "unchanged" for c in content.values())


def test_apply_is_idempotent(ctx, config, clean):
    first = call("config.apply", ctx, {"config": CONFIG})
    assert first.data.to_change >= 2
    second = call("config.plan", ctx, {"config": CONFIG})
    assert second.data.to_change == 0
    again = call("config.apply", ctx, {"config": CONFIG})
    assert "Nothing to do" in again.summary


def test_apply_configures_the_source_and_its_schedule(ctx, config, clean, probes):
    call("config.apply", ctx, {"config": CONFIG})
    assert probes == ["https://acme.okta.com"], "the credential is tried once, offline"
    row = fetch_one(
        ctx.db,
        "SELECT settings, interval_seconds, secret FROM shoc.connector_config "
        "WHERE tenant_id=%s AND source='okta'",
        (config.tenant_id,),
    )
    assert row and row["interval_seconds"] == 1800
    assert row["settings"]["org_url"] == "https://acme.okta.com"
    assert b"00-token" not in bytes(row["secret"]), "the token is encrypted at rest"
    schedule = fetch_one(
        ctx.db,
        "SELECT interval_seconds FROM shoc.schedules WHERE schedule_id=%s",
        (f"{config.tenant_id}:sync:okta",),
    )
    assert schedule and schedule["interval_seconds"] == 1800


def test_a_changed_setting_shows_up_as_an_update(ctx, config, clean):
    call("config.apply", ctx, {"config": CONFIG})
    changed = {**CONFIG, "sources": [{**CONFIG["sources"][0], "interval_seconds": 3600}]}
    result = call("config.plan", ctx, {"config": changed})
    actions = {(c["kind"], c["target"]): c["action"] for c in result.data.changes}
    assert actions[("source", "okta")] == "update"


def test_a_missing_environment_variable_stops_the_apply(ctx, config, clean, monkeypatch):
    monkeypatch.delenv("SHOC_SECRET_TEST_OKTA_TOKEN", raising=False)
    plan = call("config.plan", ctx, {"config": CONFIG})
    assert "SHOC_SECRET_TEST_OKTA_TOKEN" in plan.data.missing_env
    with pytest.raises(ConfigError, match="SHOC_SECRET_TEST_OKTA_TOKEN"):
        call("config.apply", ctx, {"config": CONFIG})


def test_an_unknown_source_is_invalid_and_nothing_is_applied(ctx, config, clean):
    bad = {"version": 1, "sources": [{"source": "carrier_pigeon"}]}
    plan = call("config.plan", ctx, {"config": bad})
    assert plan.data.invalid == 1
    with pytest.raises(ValidationError, match="nothing was applied"):
        call("config.apply", ctx, {"config": bad})
    left = fetch_one(
        ctx.db,
        "SELECT count(*) AS n FROM shoc.connector_config WHERE tenant_id=%s",
        (config.tenant_id,),
    )
    assert left and left["n"] == 0


def test_pruning_removes_a_source_that_left_the_file(ctx, config, clean):
    call("config.apply", ctx, {"config": CONFIG})
    pruned = {"version": 1, "retention_days": 30, "sources": [], "prune_unlisted": True}
    result = call("config.apply", ctx, {"config": pruned})
    assert any(c["action"] == "delete" for c in result.data.changes)
    left = fetch_one(
        ctx.db,
        "SELECT count(*) AS n FROM shoc.connector_config WHERE tenant_id=%s AND source='okta'",
        (config.tenant_id,),
    )
    assert left and left["n"] == 0


def test_without_pruning_an_unlisted_source_is_left_alone(ctx, config, clean):
    call("config.apply", ctx, {"config": CONFIG})
    result = call("config.plan", ctx, {"config": {"version": 1, "retention_days": 30}})
    assert not [c for c in result.data.changes if c["action"] == "delete"]


def test_the_example_file_parses_and_names_no_secrets(tmp_path):
    path = configcode.write_example(tmp_path / "shoc.yaml")
    desired = configcode.Desired.from_dict(configcode.read_file(path))
    assert {s.source for s in desired.sources} == {"aws_cloudtrail", "okta", "github"}
    assert desired.slack and desired.slack.approvers
    text = path.read_text()
    for spec in desired.sources:
        assert spec.secret_env, "every source names environment variables, not values"
        assert all(v.startswith("SHOC_SECRET_") for v in spec.secret_env.values())
    assert "xoxb-" not in text and "AKIA" not in text


def test_writing_the_example_twice_is_refused(tmp_path):
    configcode.write_example(tmp_path / "shoc.yaml")
    with pytest.raises(ValidationError, match="already exists"):
        configcode.write_example(tmp_path / "shoc.yaml")


def test_a_retention_set_by_apply_survives_a_worker_start(ctx, config, clean):
    from shoc.worker import ensure_default_schedules

    call("config.apply", ctx, {"config": CONFIG})
    ensure_default_schedules(ctx.db, config)  # SHOC_RETENTION_DAYS, 90 here
    row = fetch_one(
        ctx.db,
        "SELECT payload FROM shoc.schedules WHERE schedule_id = %s",
        (f"{config.tenant_id}:retention",),
    )
    assert row and row["payload"]["days"] == 30
    plan = call("config.plan", ctx, {"config": CONFIG})
    assert ("retention", "30d", "unchanged") in {
        (c["kind"], c["target"], c["action"]) for c in plan.data.changes
    }


def test_a_file_without_retention_leaves_it_alone(ctx, config, clean):
    plan = call("config.plan", ctx, {"config": {"version": 1}})
    assert not [c for c in plan.data.changes if c["kind"] == "retention"]


def _as(ctx, caller):
    other = Context(tenant_id=ctx.tenant_id, caller=caller, config=ctx.config)
    other._store = ctx._store
    return other


def _audit(ctx, since):
    return fetch_all(
        ctx.db,
        """SELECT principal_kind, principal_id, capability, error FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s ORDER BY seq""",
        (ctx.tenant_id, since),
    )


def _head(ctx):
    row = fetch_one(
        ctx.db,
        "SELECT coalesce(max(seq), 0) AS seq FROM shoc.audit_log WHERE tenant_id = %s",
        (ctx.tenant_id,),
    )
    return row["seq"] if row else 0


def test_apply_runs_each_change_as_the_caller(ctx, config, clean):
    """config:write alone cannot reach what sources:write and intel:configure guard."""
    narrow = _as(ctx, Caller(kind="human", id="dee", scopes=("config:read", "config:write")))
    since = _head(ctx)
    with pytest.raises(Denied, match=r"source\.configure: caller lacks scope"):
        call("config.apply", narrow, {"config": CONFIG})
    left = fetch_one(
        ctx.db,
        "SELECT count(*) AS n FROM shoc.connector_config WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert left and left["n"] == 0, "a refusal changes nothing"
    refused = _audit(ctx, since)
    assert [(r["principal_id"], r["capability"]) for r in refused] == [("dee", "config.apply")]
    assert refused[0]["error"]

    since = _head(ctx)
    call("config.apply", _as(ctx, role_caller("deployer", "dee")), {"config": CONFIG})
    rows = _audit(ctx, since)
    assert {r["capability"] for r in rows} >= {
        "source.configure",
        "intel.configure",
        "config.apply",
    }
    assert {(r["principal_kind"], r["principal_id"]) for r in rows} == {("human", "dee")}


def test_secret_env_names_only_shoc_secret_variables(ctx, config, clean, monkeypatch):
    monkeypatch.setenv("SHOC_MASTER_KEY", config.master_key)
    bad = {
        "version": 1,
        "sources": [{**CONFIG["sources"][0], "secret_env": {"api_token": "SHOC_MASTER_KEY"}}],
        "slack": {"channel": "C0123", "bot_token_env": "SHOC_DSN"},
    }
    plan = call("config.plan", ctx, {"config": bad})
    refused = [c for c in plan.data.changes if c["action"] == "invalid"]
    assert {c["kind"] for c in refused} == {"source", "slack"}
    assert all("SHOC_SECRET_" in c["detail"] for c in refused)
    with pytest.raises(ValidationError, match="SHOC_MASTER_KEY"):
        call("config.apply", ctx, {"config": bad})


def test_the_server_reads_no_path_a_caller_names(ctx, config, clean):
    with pytest.raises(ValidationError, match="unknown field"):
        call("config.plan", ctx, {"path": "/etc/passwd"})
