"""Research and peer review before a blocking action (RSP-5, RSP-6, RFC 0004).

The rule these tests hold to: a gate may only ever make an action harder to
take. It can turn L1 into L2; it can never turn L2 into L1, and it never
approves anything on a human's behalf.
"""

from __future__ import annotations

import json
from typing import Any, cast

from shoc.agents.llm import ScriptedClient
from shoc.cases import review as peer_review
from shoc.cases.policy import Policy, Research, Review

SHIPPED = Policy.load()

MALICIOUS = Research(
    done=True, verdict="malicious", owner="Example Hosting", summary="on two feeds we pull"
)
APPROVED = Review(done=True, approved=True, reason="IR Commander approved")


def _block(**kw):
    base = {
        "principal_kind": "agent",
        "target_kind": "ip",
        "target": "203.0.113.4",
        "confidence": 0.95,
        "severity": "critical",
        "has_citations": True,
        "research": MALICIOUS,
        "review": APPROVED,
    }
    return SHIPPED.decide("cloudflare.block_ip", **{**base, **kw})


def test_the_shipped_policy_gates_every_automatic_blocking_action():
    for name, rule in SHIPPED.actions.items():
        if rule.get("autonomy") == "L1" and name.endswith(("block_ip", "isolate_host")):
            assert rule.get("research_before_action"), f"{name} may block without research"
            assert rule.get("review_before_action"), f"{name} may block without review"


def test_a_researched_reviewed_block_still_runs_automatically():
    decision = _block()
    assert decision.allowed and decision.autonomy == "L1" and not decision.needs_approval


def test_an_unresearched_target_is_escalated_to_a_human():
    decision = _block(research=None)
    assert decision.autonomy == "L2" and decision.needs_approval
    assert "has not been researched" in decision.reason
    assert "research" in decision.escalated_by


def test_shared_infrastructure_is_never_blocked_automatically():
    decision = _block(
        research=Research(
            done=True, verdict="malicious", owner="Cloudflare", shared_infrastructure=True
        )
    )
    assert decision.autonomy == "L2" and decision.needs_approval
    assert "shared infrastructure" in decision.reason and "Cloudflare" in decision.reason


def test_our_own_egress_is_never_blocked_automatically(tmp_path):
    import yaml

    assert SHIPPED.path is not None
    data = yaml.safe_load(SHIPPED.path.read_text())
    data["guards"]["known_egress"] = ["203.0.113.*"]
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    decision = Policy.from_file(path).decide(
        "cloudflare.block_ip",
        principal_kind="agent",
        target_kind="ip",
        target="203.0.113.4",
        confidence=0.95,
        severity="critical",
        has_citations=True,
        research=MALICIOUS,
        review=APPROVED,
    )
    assert decision.autonomy == "L2" and "our own known egress" in decision.reason


def test_research_that_found_nothing_is_not_enough_to_block():
    for verdict in ("unknown", "benign"):
        decision = _block(research=Research(done=True, verdict=verdict))
        assert decision.autonomy == "L2", f"'{verdict}' must not authorise an automatic block"
        assert verdict in decision.reason


def test_an_unreviewed_block_is_escalated():
    decision = _block(review=None)
    assert decision.autonomy == "L2" and "has not reviewed" in decision.reason


def test_a_reviewer_objection_escalates_and_carries_the_reason():
    decision = _block(
        review=Review(
            done=True,
            approved=False,
            reason="the reviewer did not approve: this is the payment webhook source",
        )
    )
    assert decision.autonomy == "L2" and decision.needs_approval
    assert "payment webhook source" in decision.reason


def test_a_gate_can_never_make_an_action_easier():
    # crowdstrike.isolate_host is L2 in the shipped policy; a glowing review leaves it L2.
    decision = SHIPPED.decide(
        "crowdstrike.isolate_host",
        principal_kind="human",
        target_kind="host",
        target="laptop-7",
        confidence=1.0,
        severity="critical",
        has_citations=True,
        research=MALICIOUS,
        review=APPROVED,
    )
    assert decision.autonomy == "L2" and decision.needs_approval


# -- the review itself ------------------------------------------------------
def _reviewers(commander: dict) -> ScriptedClient:
    return ScriptedClient(replies={"You are IR Commander": json.dumps(commander)})


def _answered(approve: bool, **blast: object) -> dict:
    """A review that answered the blast radius. An unanswered one is a refusal."""
    return {
        "approve": approve,
        "blast_radius": {"principals": 0, **blast},
    }


def _context(**kw) -> peer_review.Context:
    """What the reviewer saw. The default is a target only the attacker is behind."""
    return peer_review.Context(**{"seen": True, "principals": [], **kw})


def _review(client, context=None, **kw):
    return peer_review.review_action(
        cast(Any, None),
        None,
        "t1",
        action_type="cloudflare.block_ip",
        plan="Block 203.0.113.4 at the edge for 120 minutes",
        target_kind="ip",
        target="203.0.113.4",
        rationale="credential stuffing",
        research=None,
        config=_cfg(),
        client=client,
        context=context if context is not None else _context(),
        **{"case": {}, **kw},
    )


def _cfg():
    from shoc.config import Config

    return Config(llm_provider="anthropic", llm_api_key="x", llm_max_tokens=512)


def test_the_reviewer_must_approve():
    """RFC 0012 deleted the Operator, so the Commander answers for its own proposal."""
    said = _review(_reviewers(_answered(True)))
    assert said.done and said.approved
    assert [o.reviewer for o in said.reviewers] == ["IR Commander"]


def test_one_objection_is_enough_to_stop_it():
    said = _review(
        _reviewers(
            {
                "approve": False,
                "blast_radius": {
                    "principals": 40,
                    "shared_infrastructure": "the office VPN egress",
                },
                "objections": ["everyone in the Berlin office loses access"],
            }
        )
    )
    assert said.done and not said.approved
    assert "Berlin office" in said.reason
    assert "office VPN egress" in said.blast_radius


def test_an_unanswered_blast_radius_is_a_refusal():
    """The Commander now reviews its own proposal, so the citation requirement is
    the whole safety: a reviewer that did not count what is behind the target has
    not reviewed it, however confidently it approved."""
    said = _review(_reviewers({"approve": True}))
    assert said.done and not said.approved
    assert any("blast radius" in o for o in said.objections)


def test_a_counted_blast_radius_cites_an_event_of_the_case_it_was_shown(monkeypatch):
    """The brief used to show no event ids, so a count of the principals behind a
    target was refused, or passed on ids nothing checked."""
    monkeypatch.setattr(peer_review, "case_citations", lambda *a, **k: ["E1", "E2"])
    monkeypatch.setattr(peer_review, "_say", lambda *a, **k: None)
    client = _reviewers(_answered(True, principals=1, citations=["E2"]))
    said = _review(client, case={"case_uid": "CASE-1"})
    assert said.approved, said.reason
    assert '"E1"' in client.calls[0], "the case's events are in front of the reviewer"
    invented = _review(
        _reviewers(_answered(True, principals=1, citations=["E-made-up"])),
        case={"case_uid": "CASE-1"},
    )
    assert not invented.approved and "cites no events" in invented.reason


def test_naming_a_better_action_is_not_an_approval():
    said = _review(
        _reviewers(
            {**_answered(True), "safer_alternative": "Disable the leaked access key instead."}
        )
    )
    assert not said.approved and "a better action would do" in said.reason
    assert _review(_reviewers({**_answered(True), "safer_alternative": "None."})).approved


def test_a_reviewer_that_cannot_be_reached_escalates_rather_than_approves():
    class Broken(ScriptedClient):
        def complete(self, system, turns, max_tokens=2048, tools=None):
            raise RuntimeError("upstream is down")

    said = _review(Broken())
    assert said.done and not said.approved
    assert "could not be reached" in said.reason


def test_without_a_model_the_review_escalates_instead_of_approving():
    from shoc.agents.llm import NoLLM

    said = _review(NoLLM())
    assert not said.done and not said.approved
    assert "no model is configured" in said.reason


def test_the_reviewer_is_shown_the_research_as_untrusted_data():
    from shoc.detect.osint import Observation
    from shoc.detect.osint import Research as Found

    client = _reviewers(_answered(True))
    peer_review.review_action(
        cast(Any, None),
        None,
        "t1",
        action_type="cloudflare.block_ip",
        plan="Block it",
        target_kind="ip",
        target="203.0.113.4",
        case={},
        research=Found(
            value="203.0.113.4",
            type="ip",
            verdict="malicious",
            summary="on two feeds",
            observations=[Observation(source="rdap", summary="Example Hosting")],
        ),
        config=_cfg(),
        client=client,
        context=_context(),
    )
    prompt = client.calls[0]
    assert "<untrusted-data" in prompt and "Example Hosting" in prompt


# -- the deterministic guard (RFC 0006) -------------------------------------
def test_shared_infrastructure_escalates_without_asking_a_model():
    """Counting principals is arithmetic. The component that can take the company
    offline must not be reachable by persuasion, so the model is never asked."""
    client = _reviewers(_answered(True))
    said = _review(
        client,
        context=_context(principals=["user:alice", "user:bob", "user:carol", "user:dave"]),
    )
    assert said.done and not said.approved
    assert "shared infrastructure" in said.reason
    assert client.calls == [], "the guard must run before the model, not alongside it"


def test_three_principals_is_still_reviewable():
    said = _review(
        _reviewers(_answered(True)),
        context=_context(principals=["user:alice", "user:bob", "key:AKIAEXAMPLE"]),
    )
    assert said.approved


def test_a_reviewer_that_cannot_see_the_graph_refuses():
    client = _reviewers(_answered(True))
    said = _review(client, context=peer_review.Context(seen=False, error="TimeoutError: gone"))
    assert said.done and not said.approved
    assert "graph could not be read" in said.reason
    assert client.calls == []


def test_the_reviewer_is_shown_the_graph_and_what_we_were_told():
    client = _reviewers(_answered(True))
    _review(
        client,
        context=_context(
            principals=["user:alice"],
            neighbours=[{"node": "user:alice", "kind": "user", "label": "alice", "events": 12}],
            facts=["203.0.113.4 is the office VPN egress"],
        ),
    )
    prompt = client.calls[0]
    assert "office VPN egress" in prompt
    assert "<untrusted-data" in prompt, "memory and the graph reach a model as data"


def test_every_blocking_action_is_researched_and_reviewed_unless_it_says_otherwise():
    """Default-on (RSP-5, RSP-6): a new blocking action cannot forget its gates."""
    from shoc.actions import load

    for action in load().values():
        if action.target_kind in ("ip", "domain", "url", "hash"):
            assert SHIPPED.gated(action.type, action.target_kind) == (True, True), action.type
    assert SHIPPED.gated("aws.disable_access_key", "key") == (False, False)


def test_an_objection_reaches_the_human_deciding_an_l2():
    decision = SHIPPED.decide(
        "crowdstrike.isolate_host",
        principal_kind="agent",
        target_kind="host",
        target="laptop-7",
        confidence=1.0,
        severity="critical",
        has_citations=True,
        review=Review(done=True, approved=False, reason="it is the CEO's laptop mid-board-call"),
    )
    assert decision.autonomy == "L2" and "CEO's laptop" in decision.reason


def test_the_crews_blast_radius_must_be_counted_and_cited():
    """D45: unanswered, uncited or shared infrastructure, and the crew does not act alone."""

    def key(blast):
        return SHIPPED.decide(
            "aws.disable_access_key",
            principal_kind="agent",
            target_kind="key",
            target="AKIAEXAMPLE",
            confidence=0.95,
            severity="critical",
            blast_radius=blast,
        )

    assert key(None).autonomy == "L1", "a playbook step is not asked for one"
    assert key({"principals": 0}).autonomy == "L1"
    assert key({"principals": 1, "citations": ["e1"]}).autonomy == "L1"
    for blast, said in (
        ({}, "unanswered"),
        ({"principals": 2}, "cites no events"),
        ({"principals": 0, "shared_infrastructure": "a NAT"}, "shared"),
    ):
        decision = key(blast)
        assert decision.autonomy == "L2" and said in decision.reason, blast
        assert "blast_radius" in decision.escalated_by


def test_a_review_that_counts_somebody_must_cite_them():
    said = _review(_reviewers(_answered(True, principals=2)))
    assert not said.approved and any("cites no events" in o for o in said.objections)
    cited = _review(
        _reviewers({"approve": True, "blast_radius": {"principals": 2, "citations": ["e1"]}})
    )
    assert cited.approved
