"""The Integrator: sample without storing, onboarded only on a finding, and a
mapping moved only when the events fill more (AGT-13, D50, D74)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shoc.agents import integrator
from shoc.agents.llm import ScriptedClient
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all, fetch_one

pytestmark = pytest.mark.postgres

FIXTURE = Path("tests/fixtures/mappings/aws_cloudtrail.json").resolve()


def _configure(ctx, tenant: str, source: str, settings: dict) -> None:
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings)
           VALUES (%s, %s, true, %s)""",
        (tenant, source, json.dumps(settings)),
    )


def _onboarding(ctx, tenant: str) -> dict[str, dict]:
    rows = fetch_all(ctx.db, "SELECT * FROM shoc.source_onboarding WHERE tenant_id = %s", (tenant,))
    return {r["source"]: r for r in rows}


def test_a_sample_maps_real_records_and_stores_nothing(ctx, store, config, clean):
    _configure(ctx, config.tenant_id, "file", {"path": str(FIXTURE), "mapping": "aws_cloudtrail"})
    out = call("source.sample", ctx, {"source": "file", "limit": 5}).data
    assert out.ok and out.fetched > 0
    assert all(row["event_uid"] for row in out.rows)
    counted = store.query(
        "SELECT COUNT(*) AS n FROM ocsf_events WHERE tenant_id = :t", {"t": config.tenant_id}
    )
    assert counted.rows[0]["n"] == 0
    assert not fetch_one(
        ctx.db, "SELECT 1 FROM shoc.connector_state WHERE tenant_id = %s", (config.tenant_id,)
    ), "a sample moves no cursor"


def test_a_sample_of_a_broken_source_says_what_is_wrong(ctx, config, clean):
    _configure(ctx, config.tenant_id, "file", {"path": "/nonexistent"})
    out = call("source.sample", ctx, {"source": "file"}).data
    assert not out.ok and "no such path" in out.error


def test_a_push_source_is_not_sampled_for_a_credential_it_never_needed(ctx, config, clean):
    call("source.push_key", ctx, {"source": "github", "rotate": True})
    out = call("source.sample", ctx, {"source": "github"}).data
    assert not out.ok and "no page to pull" in out.error and not out.needs


def test_a_push_source_is_not_pulled_and_loses_an_old_pull_failure(ctx, config, clean):
    call("source.push_key", ctx, {"source": "github", "rotate": True})
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state (tenant_id, source, last_ok_at, last_error)
           VALUES (%s, 'github', now(), 'ConfigError: github: settings need org')""",
        (config.tenant_id,),
    )
    out = call("source.sync", ctx, {"source": "github"})
    assert out.data.fetched == 0 and "nothing was pulled" in out.summary
    row = fetch_one(
        ctx.db,
        "SELECT last_error FROM shoc.connector_state WHERE tenant_id = %s AND source = 'github'",
        (config.tenant_id,),
    )
    assert row and row["last_error"] is None


def test_a_push_source_waits_on_no_credential_before_its_first_push(ctx, store, config, clean):
    call("source.push_key", ctx, {"source": "github", "rotate": True})
    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config, source="github")
    assert out["waiting"] == []
    assert _onboarding(ctx, config.tenant_id)["github"]["step"] == "prove"


def test_a_source_is_onboarded_by_a_finding_and_nothing_else(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    _configure(ctx, config.tenant_id, "aws_cloudtrail", {})
    _configure(ctx, config.tenant_id, "okta", {})
    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)

    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    assert out["onboarded"] == ["aws_cloudtrail"]
    rows = _onboarding(ctx, config.tenant_id)
    assert rows["aws_cloudtrail"]["step"] == "done" and rows["aws_cloudtrail"]["proof_finding"]
    assert rows["okta"]["onboarded_at"] is None, "configured is not onboarded"

    tested = call("mapping.test", ctx, {"source": "aws_cloudtrail"}).data
    assert tested.proof_finding and tested.supports


def test_a_source_that_cannot_be_read_waits_on_a_credential(ctx, store, config, clean):
    _configure(ctx, config.tenant_id, "okta", {})
    integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    assert out["waiting"] == ["okta"]
    row = _onboarding(ctx, config.tenant_id)["okta"]
    assert row["step"] == "credentials" and row["onboarded_at"] is None
    assert (
        row["scopes"]
        == [
            "an API token of a read-only administrator, which reads the System Log, users and network zones"
        ]
        and "Admin Console" in row["click_path"]
    )
    told = fetch_all(
        ctx.db,
        "SELECT body FROM shoc.notices WHERE tenant_id = %s AND group_key = %s",
        (config.tenant_id, "onboarding:okta"),
    )
    assert len(told) == 1, "the Manager hears of a wait once, not once a day"
    assert fetch_all(
        ctx.db,
        "SELECT 1 FROM shoc.stream_events WHERE tenant_id = %s AND type = 'source.needs_credentials'",
        (config.tenant_id,),
    )


def test_a_source_removed_mid_turn_waits_on_nothing(ctx, store, config, clean, monkeypatch):
    _configure(ctx, config.tenant_id, "okta", {})

    def removed(conn, tenant_id, source, master_key):
        call("source.remove", ctx, {"source": source})
        return {"ok": False, "error": "It has no settings and no secret yet."}

    monkeypatch.setattr(integrator, "sample", removed)
    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    assert out["waiting"] == []
    assert "okta" not in _onboarding(ctx, config.tenant_id)


def test_a_push_source_that_delivers_is_not_asked_for_a_token(ctx, store, config, clean):
    _configure(ctx, config.tenant_id, "github", {})
    execute(
        ctx.db,
        "INSERT INTO shoc.connector_state (tenant_id, source, events_seen) VALUES (%s, 'github', 24)",
        (config.tenant_id,),
    )
    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    assert out["waiting"] == []
    assert _onboarding(ctx, config.tenant_id)["github"]["step"] == "prove"


def test_a_product_in_the_events_with_no_source_is_dark(ctx, store, config, clean):
    from datetime import UTC, datetime

    call(
        "events.ingest",
        ctx,
        {
            "source": "okta",
            "records": [
                {
                    "uuid": "ok-dark-1",
                    "published": datetime.now(UTC).isoformat(),
                    "eventType": "user.session.start",
                    "actor": {"alternateId": "jane@example.com"},
                    "outcome": {"result": "SUCCESS"},
                }
            ],
        },
    )
    out = integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    assert out["dark"] == ["okta"] and _onboarding(ctx, config.tenant_id)["okta"]["dark"]


def _moved_tailscale(ctx, n: int = 5) -> None:
    """Tailscale renamed `target.id` to `target.nodeId`: resource_uid, which a rule
    correlates on, goes empty."""
    from datetime import UTC, datetime

    from shoc.ingest.connectors.base import write_state

    call(
        "events.ingest",
        ctx,
        {
            "source": "tailscale",
            "records": [
                {
                    "eventTime": datetime.now(UTC).isoformat(),
                    "event": "NODE.KEY_EXPIRY.DISABLE",
                    "action": "UPDATE",
                    "actor": {"loginName": "ana@example.com", "id": f"u{i}"},
                    "target": {"type": "node", "nodeId": f"n{i}"},
                    "tailnet": "example.com",
                }
                for i in range(n)
            ],
        },
    )
    write_state(ctx.db, ctx.tenant_id, "tailscale", {}, n, None)


def _patch(column: str, path: str) -> ScriptedClient:
    return ScriptedClient(
        default=json.dumps(
            {
                "fields": [{"column": column, "paths": [path]}],
                "reason": "target.id became target.nodeId",
            }
        )
    )


def test_a_vendor_rename_is_remapped_once_and_audited(ctx, store, config, clean):
    from shoc.ingest import ocsf

    _moved_tailscale(ctx)
    client = _patch("resource_uid", "target.nodeId")
    said = integrator.repair(ctx.db, ctx.store, config.tenant_id, config, "tailscale", client)
    assert "resource_uid 0%→100%" in said
    mapping = ocsf.for_tenant(ctx.db, config.tenant_id, "tailscale")
    row = mapping.map_record({"target": {"nodeId": "n9"}}, config.tenant_id)
    assert row["resource_uid"] == "n9"
    assert ocsf.load_mapping("tailscale").fields["resource_uid"] != mapping.fields["resource_uid"]
    assert fetch_one(
        ctx.db,
        "SELECT 1 FROM shoc.audit_log WHERE tenant_id = %s AND capability = 'mapping.write'",
        (config.tenant_id,),
    )
    assert fetch_one(
        ctx.db,
        "SELECT 1 FROM shoc.notices WHERE tenant_id = %s AND group_key = 'mapping:tailscale'",
        (config.tenant_id,),
    )

    call("mapping.write", ctx, {"source": "tailscale", "fields": {}})
    again = _patch("resource_uid", "target.nodeId")
    integrator.repair(ctx.db, ctx.store, config.tenant_id, config, "tailscale", again)
    assert not again.calls, "the same shape is not asked about twice"


def test_a_patch_that_fills_nothing_is_not_kept(ctx, store, config, clean):
    _moved_tailscale(ctx)
    said = integrator.repair(
        ctx.db,
        ctx.store,
        config.tenant_id,
        config,
        "tailscale",
        _patch("resource_uid", "nope"),
    )
    assert "not kept" in said
    assert not fetch_one(
        ctx.db,
        "SELECT 1 FROM shoc.mapping_overrides WHERE tenant_id = %s",
        (config.tenant_id,),
    )


def test_a_patch_cannot_set_what_identifies_an_event(ctx, store, config, clean):
    from shoc.errors import ValidationError

    _moved_tailscale(ctx)
    for fields in (
        {"metadata_product": "eventName"},
        {"class_uid": "eventName"},
        {"not_a_column": "eventName"},
        {"resource_uid": {"const": "x"}},
    ):
        with pytest.raises(ValidationError):
            call("mapping.write", ctx, {"source": "tailscale", "fields": fields})
    out = call(
        "mapping.write", ctx, {"source": "tailscale", "fields": {"resource_uid": "target.nodeId"}}
    ).data
    assert out.fill["resource_uid"] == [0.0, 1.0]


def test_an_install_with_nothing_connected_is_told_weekly(ctx, store, config, clean):
    for _ in range(2):
        integrator.work(ctx.db, ctx.store, config.tenant_id, config)
    told = fetch_all(
        ctx.db,
        "SELECT body FROM shoc.notices WHERE tenant_id = %s AND group_key = 'onboarding'",
        (config.tenant_id,),
    )
    assert len(told) == 1 and "No log source" in told[0]["body"]


def test_source_list_says_what_each_connector_needs(ctx, clean):
    needs = call("source.list", ctx, {}).data.needs
    assert needs["okta"] == {
        "permission": "an API token of a read-only administrator, which reads the System Log, users and network zones",
        "where": "Admin Console → Security → API → Tokens → Create token, as a read-only administrator",
        "push_where": "",
        "settings": ["org_url"],
        "secret": ["api_token"],
    }
    from shoc.ingest import connectors

    assert set(connectors.available()) | set(connectors.push_sources()) <= set(needs)
    for name, need in needs.items():
        assert need["where"] or need["push_where"], f"{name}'s form says nowhere to click"
        assert bool(need["push_where"]) == connectors.accepts_push(name), name


def test_a_source_that_never_synced_has_seen_no_events(ctx, clean):
    """A count, never null: the console formats it as a number."""
    call("source.configure", ctx, {"source": "wazuh", "settings": {}})
    (row,) = [r for r in call("source.list", ctx, {}).data.configured if r["source"] == "wazuh"]
    assert row["events_seen"] == 0 and row["last_ok_at"] is None
    assert row["has_secret"] is False
    call(
        "source.configure",
        ctx,
        {
            "source": "wazuh",
            "settings": {"indexer_url": "https://x"},
            "secret": {"username": "u", "password": "p"},
            "verify": False,
        },
    )
    (row,) = [r for r in call("source.list", ctx, {}).data.configured if r["source"] == "wazuh"]
    assert row["has_secret"] is True and "secret" not in row


def test_removing_a_source_keeps_the_events_it_delivered(ctx, store, config, clean):
    from datetime import UTC, datetime

    from shoc.errors import NotFound

    tenant = config.tenant_id
    call(
        "source.configure",
        ctx,
        {
            "source": "okta",
            "settings": {"org_url": "https://x"},
            "secret": {"api_token": "t"},
            "verify": False,
        },
    )
    call(
        "events.ingest",
        ctx,
        {
            "source": "okta",
            "records": [
                {
                    "uuid": "ok-remove-1",
                    "published": datetime.now(UTC).isoformat(),
                    "eventType": "user.session.start",
                    "actor": {"alternateId": "jane@example.com"},
                    "outcome": {"result": "SUCCESS"},
                }
            ],
        },
    )
    call("source.remove", ctx, {"source": "okta"})

    assert "okta" not in {r["source"] for r in call("source.list", ctx, {}).data.configured}
    assert not fetch_all(
        ctx.db,
        "SELECT 1 FROM shoc.schedules WHERE tenant_id = %s AND schedule_id = %s",
        (tenant, f"{tenant}:sync:okta"),
    )
    assert not fetch_all(
        ctx.db,
        """SELECT 1 FROM shoc.jobs WHERE tenant_id = %s AND state = 'pending'
             AND payload->>'source' = 'okta'""",
        (tenant,),
    )
    kept = store.query("SELECT COUNT(*) AS n FROM ocsf_events WHERE tenant_id = :t", {"t": tenant})
    assert kept.rows[0]["n"] == 1
    with pytest.raises(NotFound):
        call("source.remove", ctx, {"source": "okta"})


def test_configuring_a_source_hands_it_to_the_integrator(ctx, config, clean):
    call(
        "source.configure",
        ctx,
        {"source": "okta", "settings": {"org_url": "https://x"}, "verify": False},
    )
    queued = fetch_all(
        ctx.db,
        "SELECT payload FROM shoc.jobs WHERE tenant_id = %s AND kind = 'source.onboard'",
        (config.tenant_id,),
    )
    assert [j["payload"]["source"] for j in queued] == ["okta"]
