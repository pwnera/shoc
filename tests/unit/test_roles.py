"""The role registry's invariants (AGT-2, RFC 0012).

Nothing here needs a database or a model. What it guards is the shape of the
pool after RFC 0012: who may call whom, what a role may choose as a verdict, and
that a tool name is spelled the way the registry spells it — because `tools.specs`
silently skips a capability that does not exist, so a typo would leave a role
quietly short of a tool rather than failing.
"""

from __future__ import annotations

import typing

from shoc.agents import roles


# -- the roster -------------------------------------------------------------
def test_the_deleted_roles_are_gone():
    """RFC 0012 deleted both, and a stale reference should not compile.

    The Operator's knowledge became a Surveyor lookup and its review became a
    cited field on the Commander's proposal; the Orchestrator's job was to decide
    a round had converged, and there are no rounds.
    """
    assert "Operator" not in roles.ALL
    assert "Orchestrator" not in roles.ALL
    assert not hasattr(roles, "OPERATOR")
    assert not hasattr(roles, "ORCHESTRATOR")
    assert not hasattr(roles, "Request"), "a request is a peer call now"
    assert not hasattr(roles, "interested"), "nothing routes by keyword"


def test_the_pool_is_the_ten_crew_roles():
    assert set(roles.ALL) == {
        "Sentinel",
        "Investigator",
        "Challenger",
        "IR Commander",
        "CTI",
        "Hunter",
        "Surveyor",
        "Detection Engineer",
        "Ops",
        "Manager",
    }


def test_every_role_that_takes_part_in_a_case_is_in_the_pool():
    """`IN_CASE` is what "which specialist never spoke" is counted against."""
    assert set(roles.IN_CASE) <= set(roles.ALL)


# -- the verdict taxonomy ---------------------------------------------------
def test_no_role_may_choose_needs_human():
    """It is reachable without being chosen, and the column keeps it (D42).

    A disposition whose own handling is "tell the case nobody is coming and send
    the crew back" should not be something a role can select.
    """
    hints = typing.get_type_hints(roles.InvestigatorOutput)
    assert set(typing.get_args(hints["verdict"])) == set(roles.DISPOSITIONS)
    assert "needs_human" not in roles.DISPOSITIONS
    assert "needs_human" in roles.VERDICTS


def test_the_investigator_always_sets_a_severity():
    """Severity decides whether the one technical person is woken, so it has a
    value rather than an empty "keep what the rule guessed"."""
    hints = typing.get_type_hints(roles.InvestigatorOutput)
    assert "" not in typing.get_args(hints["severity"])


# -- who may call whom ------------------------------------------------------
def test_the_investigator_may_ask_cti_and_the_surveyor():
    assert roles.peer("Investigator", "CTI") is roles.CTI
    assert roles.peer("Investigator", "Surveyor") is roles.SURVEYOR


def test_a_role_may_not_call_one_it_did_not_declare():
    assert roles.peer("Investigator", "Hunter") is None
    assert roles.peer("Challenger", "CTI") is None, "the Challenger argues from evidence"


def test_the_manager_asks_the_crew_and_nobody_asks_the_manager():
    """RFC 0015: the operator's one contact reads from the crew; it is not a
    dispatcher the crew reports to."""
    assert roles.peer("Manager", "Investigator") is roles.INVESTIGATOR
    assert all("Manager" not in role.peers for role in roles.ALL.values())


def test_a_role_may_not_call_itself():
    """A loop with a model in it, and the one cycle worth refusing outright."""
    for name in roles.ALL:
        assert roles.peer(name, name) is None


def test_the_peer_graph_comes_from_the_roles_themselves():
    """So the graph cannot drift from what the prompts tell each role it may do."""
    assert {name: role.peers for name, role in roles.ALL.items()} == roles.PEERS


def test_every_peer_named_is_a_role_that_exists():
    for name, peers in roles.PEERS.items():
        missing = [p for p in peers if p not in roles.ALL]
        assert not missing, f"{name} declares {missing}"


# -- tools ------------------------------------------------------------------
def test_every_tool_a_role_names_is_spelled_the_way_the_registry_spells_it():
    """A capability that does not exist is skipped, not refused, so a typo would
    leave a role quietly short of a tool. Either it is built, or it is on the
    list of things RFC 0012 named and did not build."""
    from shoc.capabilities.registry import load

    known = set(load())
    for role in roles.ALL.values():
        unknown = [name for name in role.tools if name not in known and name not in roles.NOT_BUILT]
        assert not unknown, f"{role.name} asks for {unknown}"


def test_nothing_on_the_not_built_list_has_quietly_been_built():
    """When one lands, it comes off the list — otherwise the list stops catching
    typos in the names that are still outstanding."""
    from shoc.capabilities.registry import load

    built = sorted(roles.NOT_BUILT & set(load()))
    assert not built, f"remove from NOT_BUILT: {built}"


def test_the_not_built_list_names_nothing_nobody_asks_for():
    """A capability that no role wants is not outstanding work, it is a leftover."""
    wanted = {name for role in roles.ALL.values() for name in role.tools}
    assert not roles.NOT_BUILT - wanted, f"nobody asks for {sorted(roles.NOT_BUILT - wanted)}"


def test_a_peer_answers_in_its_own_contract():
    """CTI owes a provenance on every claim, and the Surveyor owes what it knows
    an address from. A plain `body` field would have dropped both."""
    assert roles.CTI.answers is roles.CtiOpinionOutput
    assert roles.SURVEYOR.answers is roles.AssetAnswer
    assert roles.CHALLENGER.answers is roles.RemarkOutput, "the default is a plain answer"


# -- prompts that match what the model is given (RFC 0020) ------------------
def test_a_role_is_told_which_of_its_tools_are_not_built():
    missing = [t for t in roles.INVESTIGATOR.tools if t in roles.NOT_BUILT]
    assert missing, "the Investigator declares tools nobody has built yet"
    assert "Not built yet" in roles.INVESTIGATOR.prompt
    assert all(t in roles.INVESTIGATOR.prompt.split("Not built yet", 1)[1] for t in missing)
    assert "Not built yet" not in roles.SENTINEL.prompt, "Sentinel's tools all exist"


def test_the_investigator_writes_its_evidence_before_its_verdict():
    """A model writes fields in schema order; a verdict written first is argued for."""
    import dataclasses

    names = [f.name for f in dataclasses.fields(roles.InvestigatorOutput)]
    assert names.index("claims") < names.index("verdict")
    assert names.index("checked_and_absent") < names.index("confidence")
    review = [f.name for f in dataclasses.fields(roles.ReviewOutput)]
    assert review.index("objections") < review.index("approve")


def test_the_commander_reads_no_raw_logs():
    assert "events.query" not in roles.COMMANDER.tools
    assert "platform.lookup" in roles.COMMANDER.tools, "it still finds ids and verifies"


def test_prompts_carry_no_bold_emphasis():
    assert all("**" not in role.prompt for role in roles.ALL.values())
