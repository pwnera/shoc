"""The Surveyor: posture derived from events, and the limit it admits to.

Every answer is a join over ingested events and the snapshots sources take
(D49). Nothing scans. The five answers never ask a model; the Surveyor's model
reads them afterwards (D47).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.agents import surveyor
from shoc.capabilities.registry import call
from shoc.ingest import batch, ocsf
from tests.support import expand

pytestmark = pytest.mark.postgres


def _load(store, tenant: str, now, records: list[dict]) -> None:
    mapping = ocsf.load_mapping("aws_cloudtrail")
    rows = [mapping.map_record(r, tenant) for r in expand(records, "aws_cloudtrail", now)]
    batch.load(store, rows)


def _event(name: str, user: str, ip: str, key: str = "AKIAEXAMPLE", **kw) -> dict:
    return {
        "eventID": f"{name}-{user}-{ip}",
        "eventName": name,
        "eventSource": "iam.amazonaws.com",
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "userName": user, "accessKeyId": key},
        **kw,
    }


@pytest.fixture
def surveyed(ctx, store, config, clean, now):
    _load(
        store,
        config.tenant_id,
        now,
        [
            # An administrator working from a public address: privileged and exposed.
            _event("AttachUserPolicy", "root-admin", "203.0.113.10"),
            _event("ListBuckets", "root-admin", "203.0.113.10"),
            # An ordinary account, only ever seen from inside.
            _event("GetObject", "reporting-job", "10.1.2.3", key="AKIAINTERNAL"),
        ],
    )
    return surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)


def test_what_exists_is_what_the_events_showed(surveyed):
    assert surveyed.counts["total"] >= 4  # two users, two keys, plus addresses
    assert surveyed.counts["user"] == 2


def test_privilege_is_observed_not_declared(surveyed):
    """A title in an IdP is a claim; an AttachUserPolicy is a fact."""
    privileged = {e["entity"] for e in surveyed.privileged}
    assert "user:root-admin" in privileged
    assert "user:reporting-job" not in privileged
    admin = next(e for e in surveyed.privileged if e["entity"] == "user:root-admin")
    assert "AttachUserPolicy" in admin["operations"]
    assert admin["citations"], "an answer with no citation is not an answer"


def test_exposure_means_used_from_outside_our_own_ranges(surveyed):
    exposed = {e["entity"] for e in surveyed.exposed}
    assert "user:root-admin" in exposed
    assert "user:reporting-job" not in exposed, "a private address is not the outside"


def test_an_address_is_the_outside_rather_than_exposed_by_it(surveyed):
    """The identity that used a public address is exposed; the address is not."""
    assert not any(e["kind"] == "ip" for e in surveyed.exposed)


def test_a_stale_identity_is_one_that_stopped_authenticating(ctx, store, config, clean, now):
    old = now - timedelta(days=surveyor.STALE_IDENTITY_DAYS + 5)
    _load(store, config.tenant_id, old, [_event("ConsoleLogin", "left-the-company", "203.0.113.9")])
    posture = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=120, config=config)
    assert "user:left-the-company" in {e["entity"] for e in posture.stale}


def test_every_answer_says_what_it_cannot_see(surveyed):
    assert "not everything that exists" in surveyed.caveat
    assert "exploitable" not in surveyed.to_json(), "D57 removed the KEV join"


def test_an_unseen_entity_reads_as_unknown_not_as_clear(ctx, config, surveyed):
    answer = surveyor.exposure_of(ctx.db, config.tenant_id, "user:nobody-here")
    assert answer["known"] is False
    assert "not that it does not exist" in answer["answer"], (
        "silence must never be read as absence by another agent"
    )


# -- through the registry ---------------------------------------------------
def test_posture_get_answers_with_the_caveat_attached(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [_event("CreateAccessKey", "admin", "203.0.113.4")])
    result = call("posture.get", ctx, {"days": 30, "refresh": True})
    assert result.data.counts["total"] > 0
    assert result.data.caveat and result.data.caveat in result.summary
    assert result.citations, "posture is evidence, not opinion"


def test_posture_exposure_answers_the_question_an_investigator_asks(ctx, config, surveyed):
    result = call("posture.exposure", ctx, {"entity": "user:root-admin"})
    assert result.data.known and result.data.privileged and result.data.exposed
    assert "AttachUserPolicy" in result.data.operations


def test_surface_list_is_what_is_reachable_from_outside(ctx, config, surveyed):
    result = call("surface.list", ctx, {"exposed_only": True, "limit": 50})
    entities = {e["entity"] for e in result.data.entities}
    assert "user:root-admin" in entities
    assert "user:reporting-job" not in entities


def test_the_five_answers_never_need_a_model(ctx, store, config, clean, now, monkeypatch):
    """With no LLM configured the survey is unchanged, by construction, and the
    Surveyor's reading is skipped rather than guessed."""
    from shoc.agents.llm import NoLLM

    monkeypatch.setenv("SHOC_LLM_PROVIDER", "none")
    _load(store, config.tenant_id, now, [_event("ListBuckets", "someone", "203.0.113.7")])
    first = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    second = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    assert first.counts == second.counts
    said = surveyor.read(ctx.db, store, config.tenant_id, first.to_json(), config, NoLLM())
    assert said == {"read": False, "why": "no model is configured"}


def test_the_scheduled_survey_is_read_by_the_surveyors_model(ctx, store, config, clean, now):
    """D47: the model sits above the queries. What it says becomes work only
    where code can check it: a product the query named, an entity it holds."""
    import json

    from shoc.agents.llm import ScriptedClient
    from shoc.db.pool import fetch_all

    rows = [
        ocsf.load_mapping("aws_cloudtrail").map_record(r, config.tenant_id)
        for r in expand([_event("ListBuckets", "widget-bot", "203.0.113.8")], "aws_cloudtrail", now)
    ]
    rows[0]["metadata_product"] = "Acme Widgets"
    batch.load(store, rows)
    _load(store, config.tenant_id, now, [_event("AttachUserPolicy", "root-admin", "203.0.113.10")])
    posture = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    assert posture.unwatched["products_with_no_rule"] == ["Acme Widgets"], (
        "a product we ingest and no rule reads is what nothing watches"
    )
    client = ScriptedClient(
        default=json.dumps(
            {
                "exposure_story": "One admin works from the internet; Acme Widgets is unwatched.",
                "unwatched_matters": [
                    "Acme Widgets carries the bot's API calls",
                    "Imaginary Product matters too",
                ],
                "changes": [
                    {"entity": "user:root-admin", "change": "newly privileged"},
                    {"entity": "user:nobody", "change": "invented"},
                ],
            }
        )
    )
    said = surveyor.read(ctx.db, store, config.tenant_id, posture.to_json(), config, client)
    assert said["read"] and len(said["items"]) == 1 and len(said["facts"]) == 1
    item = fetch_all(
        ctx.db, "SELECT * FROM shoc.detection_backlog WHERE item_uid = %s", (said["items"][0],)
    )[0]
    assert item["intake"] == "posture" and item["evidence"]["product"] == "Acme Widgets"
    fact = fetch_all(ctx.db, "SELECT * FROM shoc.memory WHERE memory_id = %s", (said["facts"][0],))[
        0
    ]
    assert fact["subject"] == "user:root-admin" and fact["source"] == "Surveyor"
    stored = call("posture.get", ctx, {"refresh": False}).data
    assert stored.reading.startswith("One admin works")


def test_a_cut_survey_says_so_and_marks_nothing_absent(ctx, store, config, clean, now):
    _load(
        store,
        config.tenant_id,
        now,
        [
            _event("ListBuckets", "alice", "203.0.113.20"),
            _event("ListBuckets", "bob", "203.0.113.21"),
        ],
    )
    surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    cut = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config, limit=1)
    assert cut.truncated and cut.limit == 1
    assert all(
        r["present"]
        for r in surveyor.surface(ctx.db, config.tenant_id, kind="user", exposed_only=False)
    ), "a cut window proves nothing absent"
    result = call("posture.get", ctx, {"refresh": False})
    assert result.data.truncated and "newest 1" in result.summary


def test_an_identity_stops_being_seen_and_turns_stale_on_the_30_day_survey(
    ctx, store, config, clean, now
):
    """The scheduled survey reads 30 days and staleness is 60: the earlier
    sighting it kept is what makes the answer possible."""
    old = now - timedelta(days=surveyor.STALE_IDENTITY_DAYS + 5)
    _load(store, config.tenant_id, old, [_event("AttachUserPolicy", "left", "203.0.113.9")])
    surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=120, config=config)
    store.reset()  # retention has dropped it; only the survey remembers
    _load(store, config.tenant_id, now, [_event("ListBuckets", "stays", "10.1.2.3")])
    posture = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    assert "user:left" in {e["entity"] for e in posture.stale}
    answer = surveyor.exposure_of(ctx.db, config.tenant_id, "user:left")
    assert answer["present"] is False and answer["exposed"] is False, (
        "an old survey's exposure is not today's"
    )
    assert "not seen in the latest survey" in answer["answer"]
    assert not surveyor.exposure_of(ctx.db, config.tenant_id, "ip:203.0.113.9")["known"], (
        "an absent address is dropped"
    )


def test_a_snapshot_shows_an_account_that_never_acts(ctx, store, config, clean, now):
    """D49: a user that exists and never signs in is in the IdP's list, not in a log."""
    from shoc.db.pool import execute

    execute(
        ctx.db,
        """INSERT INTO shoc.snapshots (tenant_id, source, entity, kind, attributes, last_active)
           VALUES (%s, 'okta', 'user:dormant@example.com', 'user', '{"status": "ACTIVE"}',
                   now() - interval '200 days'),
                  (%s, 'okta', 'network:198.51.100.0/24', 'network',
                   '{"zone": "Office", "usage": "POLICY"}', NULL)""",
        (config.tenant_id, config.tenant_id),
    )
    _load(store, config.tenant_id, now, [_event("ListBuckets", "someone", "198.51.100.7")])
    posture = surveyor.survey(ctx.db, ctx.store, config.tenant_id, days=30, config=config)
    assert "user:dormant@example.com" in {e["entity"] for e in posture.stale}
    assert "okta" in posture.caveat and "not everything that exists" not in posture.caveat
    listed = call("snapshot.list", ctx, {"source": "okta"})
    assert listed.data.count == 2
    office = call("asset.identify", ctx, {"target": "198.51.100.7"}).data
    assert office.is_ours and "Office" in office.what_it_is and office.source == "connector"
    assert office.principals == 1


def test_asset_identify_puts_a_person_first_and_says_unknown(ctx, store, config, clean, now):
    call(
        "memory.add_fact",
        ctx,
        {"body": "203.0.113.30 is our office egress", "subject": "203.0.113.30"},
    )
    told = call("asset.identify", ctx, {"target": "ip:203.0.113.30"}).data
    assert told.source == "declared" and "office" in told.what_it_is
    blank = call("asset.identify", ctx, {"target": "203.0.113.31"})
    assert blank.data.what_it_is == "unknown" and "unknown" in blank.summary


def test_identity_resolve_links_a_key_to_its_user_and_says_when_nothing_does(
    ctx, store, config, clean, now
):
    _load(
        store,
        config.tenant_id,
        now,
        [_event("ListBuckets", "carol", "203.0.113.40", key="AKIACAROL")],
    )
    call("graph.refresh", ctx, {"days": 30})
    linked = call("identity.resolve", ctx, {"identity": "key:AKIACAROL"}).data
    assert "user:carol" in {r["entity"] for r in linked.linked} and not linked.unbridged
    alone = call("identity.resolve", ctx, {"identity": "user:nobody-at-all"})
    assert alone.data.unbridged and "Unbridged" in alone.summary
