"""Content checks that need no database: every rule is loadable, typed and covered."""

from __future__ import annotations

from pathlib import Path

import pytest

from shoc.actions import get as get_action
from shoc.actions.base import out_of_scope
from shoc.cases import playbooks
from shoc.detect import hunts
from shoc.detect import rules as ruleset
from shoc.errors import ConfigError
from tests.support import FIXTURES

RULES = ruleset.load()


def test_release_ships_the_full_rule_pack():
    assert len(RULES) >= 50  # DET-2: 20 in v0.1, 50 in v0.3


def test_rules_cover_every_product_we_ingest():
    products = {r.logsource.get("product") for r in RULES}
    assert {"aws", "okta", "github", "entra", "google", "m365", "edr"} <= products


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata_is_complete(rule):
    assert rule.title and rule.description
    assert rule.attack, "every rule maps to at least one ATT&CK technique"
    assert rule.entity, "every rule declares the entity findings are keyed by"
    assert rule.logsource.get("product")
    assert rule.path and rule.path.stem == rule.id
    assert rule.created, "every rule carries its Sigma `date`"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_has_positive_and_negative_fixtures(rule):
    for kind in ("positive", "negative"):
        path: Path = FIXTURES / "rules" / rule.id / f"{kind}.json"
        assert path.exists(), f"{rule.id} is missing its {kind} fixture"


# -- playbooks (RFC 0013) ---------------------------------------------------
BOOKS = playbooks.load()
HUNT_IDS = {f"hunt:{p.id}" for p in hunts.load()}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_belongs_to_exactly_one_playbook(rule):
    owners = [b.id for b in BOOKS if rule.id in b.rules]
    assert len(owners) == 1, f"{rule.id} is answered by {owners or 'no playbook'}"


@pytest.mark.parametrize("book", BOOKS, ids=lambda b: b.id)
def test_playbook_names_real_rules_and_can_be_followed(book):
    known = {r.id for r in RULES} | HUNT_IDS
    assert set(book.rules) <= known, f"unknown: {set(book.rules) - known}"
    assert len(book.questions) >= 2, "a playbook asks the crew at least two questions"
    assert len({q.id for q in book.questions}) == len(book.questions)
    assert book.steps


@pytest.mark.parametrize("book", BOOKS, ids=lambda b: b.id)
def test_playbook_shows_a_worked_answer_to_its_own_questions(book):
    """RFC 0020: the crew is shown what a cited claim and a checked absence look like."""
    assert book.example, f"{book.id} has no worked example"
    assert any(f"({q.id})" in book.example for q in book.questions), (
        "the example answers one of this playbook's questions by its id"
    )
    assert "checked and absent" in book.example and "disposition" in book.example
    assert "<" not in book.example, "an example must not look like a closing tag"


@pytest.mark.parametrize("book", BOOKS, ids=lambda b: b.id)
def test_required_steps_fit_every_rule_the_playbook_answers(book):
    """A required step on another platform makes the playbook never match (D53)."""
    products = {r.id: str(r.logsource.get("product", "")).lower() for r in RULES}
    # A hunt's finding is on its pack's platform, so a hunt-only case is matched too.
    products |= {f"hunt:{p.id}": str(p.logsource.get("product", "")).lower() for p in hunts.load()}
    for rule_id in book.rules:
        for step in book.steps:
            if not step.optional:
                assert not out_of_scope(get_action(step.action), {products[rule_id]}), (
                    f"{book.id}: '{step.name}' cannot run on a {rule_id} case"
                )


# Rules whose playbook has no step, optional included, that can act on the
# platform they fire on: the Detection Engineer's gate refuses a new rule like
# these (D77). A rule joins it only with the reason its platform's API has no
# action for it, and leaves it once one exists.
CANNOT_ACT = {
    "aws_console_login_failure_burst",  # nothing to act on until a login succeeds
    # The same: only the Okta rule pairs the spray with a success. The `idp` step
    # that seemed to answer it read that rule's user and never rendered (RFC 0031).
    "entra_sign_in_failure_burst",
    # Gateway names a WARP device; isolating it needs the EDR device id, and no
    # step can block a domain yet.
    "cloudflare_gateway_threat_domain_lookup",
    # Stripe's API cannot revoke a key, remove a member, change who signs in
    # or turn a protection back on for the account that calls it (D56).
    "stripe_admin_access_granted",
    "stripe_secret_key_created_or_viewed",
    "stripe_defence_disabled",
    "stripe_sign_in_factor_changed",
    # The only Stripe action blocks a card behind a charge. Cancelling a pending
    # manual payout would answer it, with a key that can write payouts.
    "stripe_payout_to_new_destination",
}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_has_a_step_that_can_act_on_its_platform(rule):
    book = next(b for b in BOOKS if rule.id in b.rules)
    why = book.cannot_act_on(str(rule.logsource.get("product", "")).lower())
    if rule.id in CANNOT_ACT:
        assert why, f"{rule.id} can be acted on now; take it out of CANNOT_ACT"
    else:
        assert not why, f"{rule.id}: {why}"


# -- sources: where a rule was taken from, cited with a link -----------------
SIGMA = {
    "name": "Sigma",
    "title": "An example rule",
    "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/example.yml",
    "author": "A. Author",
    "license": "DRL-1.1",
}


def _rule(**kw):
    return ruleset.from_dict(
        {"id": "r", "title": "t", "detection": {"selection": {"status": "Success"}}, **kw}
    )


def test_a_rule_carries_its_sources_to_the_finding():
    assert _rule(sources=[SIGMA]).to_json()["sources"] == [SIGMA]


@pytest.mark.parametrize(
    "bad", [{"name": "Sigma", "title": "x"}, {**SIGMA, "url": "http://example.com/r.yml"}]
)
def test_a_source_needs_a_link_to_cite(bad):
    with pytest.raises(ConfigError, match="source"):
        _rule(sources=[bad])
