"""The Detection Engineer: intake, the gate, its own merges and its daily turn (AGT-3).

Every source of a detection idea ends up in one queue, no exclusion outlives
its reason, a rule merges only through the gate (D48), and the daily turn ends
backlog items instead of leaving them for a human who does not come.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shoc.agents import detection_engineer as engineer
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all
from shoc.errors import Denied, NotFound, ValidationError

pytestmark = pytest.mark.postgres


@pytest.fixture
def tenant(ctx, config, clean):
    return config.tenant_id


def _report(
    ctx,
    tenant: str,
    techniques: list[str],
    procedures: list[dict] | None = None,
    source: str = "huntress",
    by: str = "",
    deliver: str = "AWS CloudTrail",
) -> None:
    """A report read from a feed, while a source that can see its techniques sends."""
    if deliver:
        _delivering(ctx, tenant, deliver)
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_reports
               (report_uid, tenant_id, title, techniques, procedures, source, digested_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (
            f"REP-{tenant}",
            tenant,
            "A campaign against small SaaS companies",
            techniques,
            json.dumps(procedures or []),
            source,
            by or "service:worker",
        ),
    )


def _delivering(ctx, tenant: str, product: str) -> None:
    """A connected source that loaded `product` events today."""
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products)
           VALUES (%s, %s, %s) ON CONFLICT (tenant_id, source) DO NOTHING""",
        (tenant, product.lower().replace(" ", "_"), [product]),
    )


def _suppression(ctx, tenant: str, days: str) -> str:
    execute(
        ctx.db,
        f"""INSERT INTO shoc.suppressions
               (suppression_uid, tenant_id, rule_id, entity, reason, case_uid, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s, now() + interval '{days}')""",
        (
            f"SUP-{tenant}",
            tenant,
            "aws_console_login_without_mfa",
            "user:backup-job",
            "the nightly backup job",
            "CASE-test",
        ),
    )
    return f"SUP-{tenant}"


# -- intake -----------------------------------------------------------------
def test_a_technique_we_read_about_and_cannot_look_for_is_recorded_as_a_gap(ctx, tenant):
    _report(ctx, tenant, ["T1499"])
    items = engineer.intake(ctx.db, tenant, ctx.config)
    cti = [i for i in items if i.intake == "cti"]
    assert cti, "reading about a technique and having no rule for it is a coverage gap"
    assert cti[0].evidence["report_uid"] == f"REP-{tenant}"


def test_a_coverage_gap_carries_what_the_report_saw_the_attacker_do(ctx, tenant):
    said = {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "evidence": "a burst of login requests from rented hosts until the portal fell over",
        "seen_in": ["web"],
    }
    _report(ctx, tenant, ["T1499"], [said])
    (item,) = [i for i in engineer.intake(ctx.db, tenant, ctx.config) if i.intake == "cti"]
    assert item.evidence["name"] == said["name"]
    assert item.evidence["procedure"] == said["evidence"], "the behaviour, not the id alone"


def test_a_coverage_gap_says_what_would_show_it_and_whether_we_receive_it(ctx, tenant):
    said = {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "evidence": "curl fetched the second stage into the temp folder",
        "seen_in": ["process", "admin_api"],
    }
    _report(ctx, tenant, ["T1105"], [said], deliver="CrowdStrike Falcon")
    execute(
        ctx.db,
        "INSERT INTO shoc.source_history (tenant_id, source, products) VALUES (%s,'aws',%s)",
        (tenant, ["AWS CloudTrail"]),
    )
    page = call("detection.backlog", ctx, {"run": True}).data
    (item,) = [i for i in page.items if i["evidence"].get("technique") == "T1105"]
    context = item["context"]
    assert context["techniques"] == [{"id": "T1105", "name": "Ingress Tool Transfer"}]
    assert context["reports"][0]["said"][0]["procedure"] == said["evidence"]
    shows = {s["kind"]: s for s in context["seen_in"]}
    carriers = {p["source"]: p["product"] for p in shows["process"]["products"]}
    assert carriers["crowdstrike_fdr"] == "CrowdStrike Falcon Data Replicator"
    assert "crowdstrike" not in carriers, "an alert feed is not telemetry"
    assert shows["process"]["received"] == []
    assert shows["admin_api"]["received"] == ["AWS CloudTrail"]


def test_a_technique_no_delivering_product_can_show_is_left_off(ctx, tenant):
    # T1003.001 is Windows only; Workspace shows identity, mail and SaaS activity.
    _report(ctx, tenant, ["T1003.001", "T1595"], deliver="Google Workspace")
    items = engineer.intake(ctx.db, tenant, ctx.config)
    assert not [i for i in items if i.intake == "cti"], (
        "a model turn that can only end in source_gap is not worth starting"
    )


def test_only_a_configured_source_or_a_person_puts_a_report_on_the_backlog(ctx, tenant):
    _report(ctx, tenant, ["T1499"], source="", by="agent:CTI")
    items = engineer.intake(ctx.db, tenant, ctx.config)
    assert not [i for i in items if i.intake == "cti"], "a read inside a case is the case's"
    execute(
        ctx.db,
        "UPDATE shoc.intel_reports SET digested_by = 'human:rettila' WHERE tenant_id = %s",
        (tenant,),
    )
    items = engineer.intake(ctx.db, tenant, ctx.config)
    assert [i for i in items if i.intake == "cti"]


def test_a_technique_a_rule_already_covers_does_not_reach_the_backlog(ctx, tenant):
    from shoc.detect import rules as ruleset

    covered = next((t for rule in ruleset.load(ctx.config) for t in (rule.attack or [])), None)
    assert covered, "the shipped rule set must map to ATT&CK at all"
    _report(ctx, tenant, [covered])
    items = engineer.intake(ctx.db, tenant, ctx.config)
    assert not [i for i in items if i.intake == "cti"], (
        "the backlog is for what we cannot see, not for everything we have read"
    )


def test_a_sub_technique_is_covered_by_a_rule_that_maps_to_its_parent(ctx, tenant):
    from shoc.detect import rules as ruleset

    parent = next(
        (t for rule in ruleset.load(ctx.config) for t in (rule.attack or []) if "." not in t),
        None,
    )
    if parent is None:
        pytest.skip("no rule maps to a bare technique")
    _report(ctx, tenant, [f"{parent}.001"])
    items = engineer.intake(ctx.db, tenant, ctx.config)
    assert not [i for i in items if i.intake == "cti"]


# -- observability ----------------------------------------------------------
def test_work_we_cannot_observe_is_marked_rather_than_queued_forever(ctx, tenant):
    items = [
        engineer.BacklogItem(
            item_uid="DBL-x", kind="coverage", intake="cti", title="t", reason="r", priority=4
        )
    ]
    engineer.score_observability(ctx.db, tenant, items)
    assert items[0].observability == "none", (
        "with no connector sending, a proposed detection is a source gap"
    )


# -- suppressions ------------------------------------------------------------
def test_suppression_list_expires_what_has_run_out(ctx, tenant):
    _suppression(ctx, tenant, "-1 day")
    result = call("suppression.list", ctx, {"review": True})
    assert result.data.expired == 1 and result.data.count == 0


def test_listing_suppressions_changes_nothing_by_default(ctx, tenant):
    _suppression(ctx, tenant, "-1 day")
    result = call("suppression.list", ctx, {})
    assert result.data.expired == 0


# -- through the registry ---------------------------------------------------
def test_the_backlog_says_where_each_item_came_from(ctx, tenant):
    _report(ctx, tenant, ["T1499"])
    result = call("detection.backlog", ctx, {"run": True})
    assert result.data.count >= 1
    assert "cti" in result.data.by_intake
    assert "from cti" in result.summary


def test_the_backlog_is_ranked(ctx, tenant):
    _report(ctx, tenant, ["T1499"])
    call("detection.backlog", ctx, {"run": True})
    rows = fetch_all(
        ctx.db,
        "SELECT priority FROM shoc.detection_backlog WHERE tenant_id = %s ORDER BY priority",
        (tenant,),
    )
    assert rows == sorted(rows, key=lambda r: r["priority"])


def test_only_a_human_ends_an_item_by_hand(ctx, tenant):
    from shoc.capabilities.registry import Caller, Context

    _report(ctx, tenant, ["T1499"])
    call("detection.backlog", ctx, {"run": True})
    item = engineer.backlog(ctx.db, tenant)[0]

    as_agent = Context(tenant_id=tenant, caller=Caller(kind="agent", id="crew"), config=ctx.config)
    as_agent._db, as_agent._store = ctx.db, ctx.store
    with pytest.raises(Denied):
        call("detection.decide", as_agent, {"item_uid": item["item_uid"], "state": "rejected"})

    with pytest.raises(ValidationError, match="say why"):
        call("detection.decide", ctx, {"item_uid": item["item_uid"], "state": "rejected"})
    out = call(
        "detection.decide",
        ctx,
        {"item_uid": item["item_uid"], "state": "rejected", "reason": "we run no public site"},
    )
    assert out.data.state == "rejected"
    (row,) = engineer.backlog(ctx.db, tenant, state="rejected")
    assert row["evidence"]["decision"] == "rejected"
    assert row["evidence"]["because"] == "we run no public site"

    call("detection.decide", ctx, {"item_uid": item["item_uid"], "state": "open"})
    (row,) = engineer.backlog(ctx.db, tenant, state="open")
    assert row["evidence"]["reopened"] == "reopened by human:test"


def test_the_detection_engineer_never_writes_to_content():
    """Enforced by there being no such call, not by a line in a prompt."""
    body = Path("shoc/agents/detection_engineer.py").read_text()
    for forbidden in ("open(", "write_text", "Path(", "shutil", "subprocess"):
        assert forbidden not in body, (
            f"the Detection Engineer must not be able to touch files ({forbidden})"
        )


# -- the gate and its own merges (D48) ----------------------------------------
def _cloudtrail(event: str) -> dict:
    return {
        "eventVersion": "1.09",
        "eventName": event,
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/deploy-ci",
            "accountId": "123456789012",
            "userName": "deploy-ci",
        },
    }


def _spec(**over) -> dict:
    spec = {
        "rule": {
            "id": "aws_iam_user_deleted",
            "title": "IAM user deleted",
            "description": "An IAM user was deleted, which can remove an audit trail.",
            "severity": "medium",
            "attack": ["T1531"],
            "logsource": {"product": "aws", "service": "cloudtrail"},
            "detection": {
                "selection": {"api.operation": "DeleteUser"},
                "condition": "selection",
                "timeframe": "15m",
            },
            "entity": "actor.user.name",
        },
        "playbook_id": "contain_leaked_cloud_key",
        "ads": {k: f"the {k}" for k in engineer.ADS_FIELDS},
        "fixtures": {
            "source": "aws_cloudtrail",
            "positive": [_cloudtrail("DeleteUser")],
            "negative": [_cloudtrail("ListUsers")],
        },
    }
    return spec | over


def test_a_rule_that_passes_the_gate_is_merged_and_bound_to_its_playbook(ctx, tenant):
    from shoc.cases import playbooks
    from shoc.detect import rules as ruleset

    _report(ctx, tenant, ["T1498"])
    item = engineer.intake(ctx.db, tenant, ctx.config)[0].item_uid
    out = engineer.merge(ctx.db, ctx.store, tenant, ctx.config, _spec(item_uid=item))

    assert out["rule_id"] == "aws_iam_user_deleted" and not out["narrows"]
    assert "aws_iam_user_deleted" in {r.id for r in ruleset.load(ctx.config, ctx.db, tenant)}
    assert "aws_iam_user_deleted" not in {r.id for r in ruleset.load(ctx.config)}
    book = next(
        b for b in playbooks.load(ctx.config, ctx.db, tenant) if b.id == "contain_leaked_cloud_key"
    )
    assert "aws_iam_user_deleted" in book.rules
    assert engineer.backlog(ctx.db, tenant, state="done")[0]["item_uid"] == item


def _item(ctx, tenant) -> str:
    _report(ctx, tenant, ["T1498"])
    return engineer.intake(ctx.db, tenant, ctx.config)[0].item_uid


def test_the_gate_names_everything_missing(ctx, tenant):
    from shoc.errors import GateRefused

    with pytest.raises(GateRefused) as refused:
        engineer.merge(
            ctx.db,
            ctx.store,
            tenant,
            ctx.config,
            _spec(ads={}, playbook_id="nope", item_uid=_item(ctx, tenant)),
        )
    reasons = refused.value.reasons
    assert refused.value.stage == "lint" and len(reasons) == 2
    assert "no playbook" in reasons[0] and "ADS form" in reasons[1]


def test_a_rule_that_does_not_parse_names_what_it_lacks(ctx, tenant):
    from shoc.errors import GateRefused

    with pytest.raises(GateRefused, match="does not parse") as refused:
        engineer.merge(ctx.db, ctx.store, tenant, ctx.config, {"rule": {}, "dry_run": True})
    assert refused.value.stage == "parse" and "detection" in refused.value.reasons[0]


def test_a_merge_names_the_item_it_answers(ctx, tenant):
    with pytest.raises(ValidationError, match="backlog item"):
        engineer.merge(ctx.db, ctx.store, tenant, ctx.config, _spec())


def test_a_rule_that_does_not_fire_on_its_positive_fixture_is_not_merged(ctx, tenant):
    fixtures = _spec()["fixtures"] | {"positive": [_cloudtrail("GetUser")]}
    with pytest.raises(ValidationError, match="did not fire on its positive"):
        engineer.merge(
            ctx.db,
            ctx.store,
            tenant,
            ctx.config,
            _spec(fixtures=fixtures, item_uid=_item(ctx, tenant)),
        )


def test_a_dry_run_runs_the_gate_without_an_item_and_writes_nothing(ctx, tenant):
    from shoc.detect import rules as ruleset

    out = call("detection.merge", ctx, _spec(dry_run=True))
    assert out.data.dry_run and out.data.rule_id == "aws_iam_user_deleted"
    assert "nothing merged" in out.summary
    assert "aws_iam_user_deleted" not in {r.id for r in ruleset.load(ctx.config, ctx.db, tenant)}
    with pytest.raises(ValidationError, match="ADS form"):
        call("detection.merge", ctx, _spec(ads={}, dry_run=True))


def test_a_person_proposes_a_rule_and_the_merge_that_answers_it_closes_it(ctx, tenant):
    uid = call(
        "detection.propose",
        ctx,
        {"title": "An IAM user is deleted", "why": "an audit finding", "attack": ["t1531"]},
    ).data.item_uid
    (item,) = engineer.backlog(ctx.db, tenant, state="open")
    assert item["item_uid"] == uid and item["intake"] == "human"
    assert item["evidence"]["attack"] == ["T1531"] and item["evidence"]["by"] == "human:test"

    call("detection.merge", ctx, _spec(item_uid=uid, dry_run=True))
    assert engineer.backlog(ctx.db, tenant, state="open"), "a dry run leaves the item open"
    call("detection.merge", ctx, _spec(item_uid=uid))
    assert engineer.backlog(ctx.db, tenant, state="done")[0]["item_uid"] == uid


def test_a_proposal_for_a_product_we_do_not_ingest_waits_as_a_gap_until_it_delivers(ctx, tenant):
    out = call(
        "detection.propose",
        ctx,
        {
            "title": "An Okta log stream is turned off",
            "product": "Okta",
            "logic": "api.operation is system.log_stream.lifecycle.deactivate",
            "false_positives": "a planned SIEM migration",
            "event_uids": ["EV-1", " "],
        },
    )
    assert "waits for okta" in out.summary
    (item,) = engineer.backlog(ctx.db, tenant, state="open")
    assert item["observability"] == "none" and item["evidence"]["waiting_for"] == ["okta"]
    assert item["evidence"]["event_uids"] == ["EV-1"]
    assert item["evidence"]["false_positives"] == "a planned SIEM migration"

    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_event_at)
           VALUES (%s, 'okta', %s, now())""",
        (tenant, ["okta"]),
    )
    engineer.intake(ctx.db, tenant, ctx.config)
    (item,) = [i for i in engineer.backlog(ctx.db, tenant, state="open") if i["intake"] == "human"]
    assert item["observability"] == "have", "the nightly sweep reopens it once okta delivers"


def test_a_person_merges_a_new_rule_without_an_item_and_an_agent_cannot(ctx, tenant):
    from shoc.capabilities.registry import Caller, Context

    out = call("detection.merge", ctx, _spec())
    assert out.data.rule_id == "aws_iam_user_deleted" and not out.data.dry_run
    (item,) = engineer.backlog(ctx.db, tenant, state="done")
    assert item["intake"] == "human" and item["title"] == "IAM user deleted"
    assert item["evidence"]["by"] == "human:test"

    crew = Context(
        tenant_id=tenant, caller=Caller(kind="agent", id="crew", scopes=("*",)), config=ctx.config
    )
    crew._db, crew._store = ctx.db, ctx.store
    with pytest.raises(ValidationError, match="backlog item"):
        call("detection.merge", crew, _spec(rule=_spec()["rule"] | {"id": "aws_iam_user_gone"}))


def test_the_response_defaults_to_the_playbook_the_rule_names(ctx, tenant):
    ads = {k: f"the {k}" for k in engineer.ADS_FIELDS if k != "response"}
    call("detection.merge", ctx, _spec(ads=ads))
    row = fetch_all(
        ctx.db,
        "SELECT ads FROM shoc.merged_rules WHERE tenant_id = %s AND rule_id = 'aws_iam_user_deleted'",
        (tenant,),
    )[0]
    assert row["ads"]["response"].endswith("(contain_leaked_cloud_key)")


def test_a_merge_is_reverted_and_a_shipped_rule_is_out_of_reach(ctx, tenant):
    from shoc.detect import rules as ruleset

    uid = _item(ctx, tenant)
    engineer.merge(ctx.db, ctx.store, tenant, ctx.config, _spec(item_uid=uid))
    engineer.revert(ctx.db, tenant, "aws_iam_user_deleted", "noisy")
    assert "aws_iam_user_deleted" not in {r.id for r in ruleset.load(ctx.config, ctx.db, tenant)}
    (item,) = [i for i in engineer.backlog(ctx.db, tenant, state="") if i["item_uid"] == uid]
    reverted = item["evidence"]["reverted"]
    assert reverted["by"] == engineer.WHO and reverted["because"] == "noisy" and reverted["at"]
    with pytest.raises(NotFound, match="human"):
        engineer.revert(ctx.db, tenant, "aws_access_key_created", "noisy")


def test_the_daily_turn_ends_items_and_does_not_believe_an_unmerged_merge(ctx, tenant):
    from shoc.agents.llm import ScriptedClient

    _report(ctx, tenant, ["T1499", "T1498"])
    items = {
        i.evidence["technique"]: i.item_uid for i in engineer.intake(ctx.db, tenant, ctx.config)
    }
    reply = {
        "outcomes": [
            {"item_uid": items["T1499"], "outcome": "source_gap", "because": "no DNS logs"},
            {"item_uid": items["T1498"], "outcome": "merged", "because": "claimed"},
        ]
    }
    out = engineer.work(
        ctx.db, ctx.store, tenant, ctx.config, client=ScriptedClient(default=json.dumps(reply))
    )

    assert out["outcomes"] == {"source_gap": 1, "later": 1}
    later = next(r for r in engineer.backlog(ctx.db, tenant) if r["item_uid"] == items["T1498"])
    assert "claimed" in later["evidence"]["later"], "`later` keeps its reason"
    closed = {r["item_uid"]: r for r in engineer.backlog(ctx.db, tenant, state="")}
    assert closed[items["T1499"]]["state"] == "rejected"
    assert closed[items["T1499"]]["observability"] == "none"
    assert closed[items["T1498"]]["state"] == "open", "a merge the gate never saw is not one"


def test_without_a_model_the_turn_says_so_and_touches_nothing(ctx, tenant):
    from shoc.agents.llm import NoLLM

    _report(ctx, tenant, ["T1499"])
    engineer.intake(ctx.db, tenant, ctx.config)
    out = engineer.work(ctx.db, ctx.store, tenant, ctx.config, client=NoLLM())
    assert out["worked"] == 0 and "no model" in out["why"]
    assert engineer.backlog(ctx.db, tenant)


# -- narrowing a shipped rule (D77) ---------------------------------------------
BACKUP = "arn:aws:iam::123456789012:role/backup"
BACKUP_IP = "198.51.100.20"


def _backup_key(day: int, ip: str = BACKUP_IP, n: int = 0) -> dict:
    from datetime import UTC, datetime, timedelta

    return {
        "eventVersion": "1.09",
        "eventID": f"bk-{day}-{n}-{ip}",
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "eventTime": (datetime.now(UTC) - timedelta(days=day, minutes=n)).isoformat(),
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "arn": BACKUP, "accountId": "123456789012"},
    }


def _false_positive(ctx, store, tenant, closed_by: str = "human") -> dict:
    """Nine days of a backup tool rotating its key, and a case on the last one
    closed as the rule's mistake."""
    from datetime import UTC, datetime

    from shoc.cases import routing
    from shoc.detect.engine import Finding, upsert
    from shoc.ingest import batch, ocsf

    mapping = ocsf.load_mapping("aws_cloudtrail")
    batch.load(store, [mapping.map_record(_backup_key(d), tenant) for d in range(0, 9)])
    now = datetime.now(UTC)
    upsert(
        ctx.db,
        Finding(
            finding_uid="F-backup",
            tenant_id=tenant,
            rule_id="aws_access_key_created",
            title="key",
            severity="high",
            confidence=0.6,
            entity_key=BACKUP,
            window_start=now,
            window_end=now,
            first_seen=now,
            last_seen=now,
            event_count=1,
            event_uids=[f"bk-0-0-{BACKUP_IP}"],
            attack=[],
            evidence={},
            entities=[f"user:{BACKUP}"],
        ),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.cases (case_uid, tenant_id, title, state, verdict, closed_by, closed_at,
                                   finding_uids)
           VALUES ('CASE-backup', %s, 'key', 'closed', 'false_positive', %s, now(), '{F-backup}')""",
        (tenant, closed_by),
    )
    execute(
        ctx.db, "UPDATE shoc.findings SET case_uid = 'CASE-backup' WHERE finding_uid = 'F-backup'"
    )
    case = fetch_all(ctx.db, "SELECT * FROM shoc.cases WHERE case_uid = 'CASE-backup'")[0]
    routed = routing.route(
        ctx.db, tenant, case, "false_positive", summary="the backup tool", closer=closed_by
    )
    return {"case": case, "item": routed.entries[0].reference}


def _narrowing(item: str, **alt) -> dict:
    return {
        "narrows": "aws_access_key_created",
        "item_uid": item,
        "exclude": [alt or {"src_endpoint.ip": BACKUP_IP, "actor.user.uid": BACKUP}],
    }


def _shipped(ctx, tenant):
    from shoc.detect import rules as ruleset

    return next(
        r for r in ruleset.load(ctx.config, ctx.db, tenant) if r.id == "aws_access_key_created"
    )


def test_a_false_positive_closure_opens_an_item_with_its_evidence(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    item = next(r for r in engineer.backlog(ctx.db, tenant) if r["item_uid"] == made["item"])
    assert item["kind"] == "defect" and item["rule_id"] == "aws_access_key_created"
    assert (
        item["evidence"]["finding_uids"] == ["F-backup"] and item["evidence"]["closer"] == "human"
    )


def test_a_narrowing_on_a_routine_address_and_id_merges_and_composes(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    out = engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))
    assert out["narrows"] and out["backtest"]["findings"] >= 8
    from shoc.detect import rules as ruleset

    rule = _shipped(ctx, tenant)
    shipped = next(r for r in ruleset.load() if r.id == rule.id).detection.condition
    assert "filter_de" in rule.detection.condition
    assert rule.detection.condition.startswith(f"({shipped})"), "the shipped rule stays whole"


def test_the_same_credential_from_another_address_still_fires(ctx, store, tenant):
    from shoc.ingest import batch, ocsf

    made = _false_positive(ctx, store, tenant)
    engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))
    stolen = _backup_key(0, "203.0.113.99", 5)
    batch.load(store, [ocsf.load_mapping("aws_cloudtrail").map_record(stolen, tenant)])
    matched, hidden = engineer._replay(
        ctx.db, store, tenant, ctx.config, _shipped(ctx, tenant), [stolen["eventID"]]
    )
    assert matched == {stolen["eventID"]} and not hidden


def test_an_exclusion_without_an_address_is_refused(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    with pytest.raises(ValidationError, match="internet address"):
        engineer.merge(
            ctx.db,
            store,
            tenant,
            ctx.config,
            _narrowing(made["item"], **{"actor.user.uid": BACKUP}),
        )


def test_an_exclusion_on_a_pattern_or_a_name_is_refused(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    with pytest.raises(ValidationError) as refused:
        engineer.merge(
            ctx.db,
            store,
            tenant,
            ctx.config,
            _narrowing(
                made["item"],
                **{"src_endpoint.ip": BACKUP_IP, "actor.user.name|contains": "backup"},
            ),
        )
    assert "modifier" in str(refused.value) and "exactly one of" in str(refused.value)


def test_a_value_seen_for_less_than_a_week_cannot_be_excluded(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    execute(
        ctx.db,
        "UPDATE shoc.cases SET opened_at = now() - interval '5 days' WHERE case_uid = 'CASE-backup'",
    )
    with pytest.raises(ValidationError, match="only a routine value"):
        engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))


def test_a_crew_closure_waits_for_the_recheck(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant, closed_by="crew")
    with pytest.raises(ValidationError, match="recheck"):
        engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))


def test_reopening_the_case_takes_the_narrowing_back(ctx, store, tenant):
    from shoc.cases import engine

    made = _false_positive(ctx, store, tenant)
    engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))
    engine.transition(ctx.db, tenant, "CASE-backup", "triage", "it was not the backup tool")
    assert "filter_de" not in _shipped(ctx, tenant).detection.condition
    item = next(
        r for r in engineer.backlog(ctx.db, tenant, state="") if r["item_uid"] == made["item"]
    )
    assert item["state"] == "open"


def test_a_narrowing_lapses_and_its_item_comes_back(ctx, store, tenant):
    made = _false_positive(ctx, store, tenant)
    engineer.merge(ctx.db, store, tenant, ctx.config, _narrowing(made["item"]))
    execute(
        ctx.db,
        "UPDATE shoc.merged_rules SET lapses_at = now() - interval '1 minute' WHERE tenant_id = %s",
        (tenant,),
    )
    engineer.intake(ctx.db, tenant, ctx.config)
    assert "filter_de" not in _shipped(ctx, tenant).detection.condition
    item = next(
        r for r in engineer.backlog(ctx.db, tenant, state="") if r["item_uid"] == made["item"]
    )
    assert item["state"] == "open" and "lapsed" in item["evidence"]


def test_one_benign_closure_opens_nothing_and_a_second_does(ctx, store, tenant):
    from datetime import UTC, datetime, timedelta

    from shoc.cases import routing
    from shoc.detect.engine import Finding, upsert

    now = datetime.now(UTC)
    for n in (1, 2):
        upsert(
            ctx.db,
            Finding(
                finding_uid=f"F-b{n}",
                tenant_id=tenant,
                rule_id="aws_access_key_created",
                title="key",
                severity="high",
                confidence=0.6,
                entity_key="deploy-ci",
                window_start=now - timedelta(hours=n),
                window_end=now,
                first_seen=now,
                last_seen=now,
                event_count=1,
                event_uids=[f"e{n}"],
                attack=[],
                evidence={},
                entities=["user:deploy-ci"],
            ),
        )
        execute(
            ctx.db,
            """INSERT INTO shoc.cases (case_uid, tenant_id, title, state, verdict, closed_at)
               VALUES (%s,%s,'k','closed','benign_expected',now())""",
            (f"CASE-b{n}", tenant),
        )
        execute(
            ctx.db,
            "UPDATE shoc.findings SET case_uid = %s WHERE finding_uid = %s",
            (f"CASE-b{n}", f"F-b{n}"),
        )
        case = fetch_all(ctx.db, "SELECT * FROM shoc.cases WHERE case_uid = %s", (f"CASE-b{n}",))[0]
        routing.route(ctx.db, tenant, case, "benign_expected", summary="the deploy")
        items = [r for r in engineer.backlog(ctx.db, tenant) if r["kind"] == "defect"]
        assert len(items) == (0 if n == 1 else 1), "benign once is the rule doing its job"


def test_rule_health_counts_case_verdicts_and_sets_shoc_aside(ctx, store, tenant):
    from shoc.agents import ops

    _false_positive(ctx, store, tenant)
    health = {h.rule_id: h for h in ops.rule_health(ctx.db, tenant, config=ctx.config)}
    assert health["aws_access_key_created"].closed_30d == {"false_positive": 1}
    execute(ctx.db, "UPDATE shoc.findings SET status = 'self' WHERE finding_uid = 'F-backup'")
    health = {h.rule_id: h for h in ops.rule_health(ctx.db, tenant, config=ctx.config)}
    assert health["aws_access_key_created"].findings_7d == 0
    assert health["aws_access_key_created"].self_7d == 1


def test_a_silent_rule_says_why(ctx, store, tenant):
    """A rule that selects an operation the vendor never sends is not 'quiet'."""
    from datetime import UTC, datetime

    from shoc.agents import ops
    from shoc.ingest import batch, ocsf
    from shoc.ingest.connectors.base import write_state

    record = {
        "id": {
            "time": datetime.now(UTC).isoformat(),
            "uniqueQualifier": "g1",
            "applicationName": "admin",
            "customerId": "C01",
        },
        "actor": {"email": "admin@example.com"},
        "events": [{"type": "DELEGATED_ADMIN_SETTINGS", "name": "SOMETHING_ELSE"}],
    }
    batch.load(store, [ocsf.load_mapping("google_workspace").map_record(record, tenant)])
    write_state(ctx.db, tenant, "google_workspace", {}, 1, None)
    health = {h.rule_id: h for h in ops.rule_health(ctx.db, tenant, config=ctx.config, store=store)}
    reasons = {r: h.silent_reason for r, h in health.items() if h.silent_reason}
    assert reasons.get("aws_access_key_created") == "not_ingested"
    assert any(
        r.startswith("google_") and why.startswith("value_absent:") for r, why in reasons.items()
    ), reasons
