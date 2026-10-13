"""The agent and model-use guidelines, checked on the code (AGT-G1 to AGT-G6).

No database, no model. The walks read shoc/ with `ast`. A rule the code breaks
today is listed in a test's KNOWN with why it is allowed for now; the test fails
on a break that is not listed and on a listed one that no longer breaks, so each
list only shrinks.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import httpx

from shoc.agents import checks, roles, tools
from shoc.agents.llm import ScriptedClient, Turn
from tests.support import ROOT

SHOC = ROOT / "shoc"


@dataclass
class Site:
    """One call in shoc/: where it is, the function around it, and the node."""

    path: str
    scope: str
    call: ast.Call
    # Inside `with limit(...)`, which caps every model call under it.
    limited: bool = False

    @property
    def key(self) -> str:
        return f"{self.path}:{self.scope}"

    @property
    def where(self) -> str:
        return f"{self.path}:{self.call.lineno} in {self.scope or '<module>'}"


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _receiver(call: ast.Call) -> str:
    """`policy` in `policy.decide(...)`, or "" for a bare name."""
    func = call.func
    return _name(func.value) if isinstance(func, ast.Attribute) else ""


def _walk(node: ast.AST, path: str, scope: str, limited: bool) -> Iterator[Site]:
    for child in ast.iter_child_nodes(node):
        inner, bounded = scope, limited
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            inner = f"{scope}.{child.name}" if scope else child.name
        if isinstance(child, ast.With):
            bounded = limited or any(
                isinstance(item.context_expr, ast.Call) and _name(item.context_expr.func) == "limit"
                for item in child.items
            )
        if isinstance(child, ast.Call):
            yield Site(path, inner, child, bounded)
        yield from _walk(child, path, inner, bounded)


def _sites(*callees: str, under: Path = SHOC) -> list[Site]:
    """Every call in `under` whose callee's last name is one of `callees`."""
    out: list[Site] = []
    for file in sorted(under.rglob("*.py")):
        rel = file.relative_to(ROOT).as_posix()
        tree = ast.parse(file.read_text(), rel)
        out += [s for s in _walk(tree, rel, "", False) if _name(s.call.func) in callees]
    return out


def _keywords(call: ast.Call) -> set[str]:
    return {k.arg for k in call.keywords if k.arg}


def _ratchet(rule: str, found: dict[str, str], known: dict[str, str]) -> None:
    """Fail on a break KNOWN does not list, and on a KNOWN entry that no longer breaks."""
    new = sorted(found[k] for k in found if k not in known)
    assert not new, f"{rule} broken at:\n" + "\n".join(new)
    fixed = sorted(set(known) - set(found))
    assert not fixed, f"{rule} now holds for {', '.join(fixed)}: take it out of KNOWN"


# -- AGT-G1 a role is offered reads and its named merges ---------------------
CREW_WRITES = {"graph.refresh", "detection.merge", "detection.revert", "hunt.merge"}


def test_the_crews_writes_are_the_four_named_merges():
    """AGT-G1: the crew is offered no write but the four content merges its specs name.

    A proposal, a state change, a notice or a suppression leaves a role through
    its typed output, where the loop applies the gates; never as a tool.
    """
    named = set().union(*tools.WRITES.values())
    assert named == CREW_WRITES, f"tools.WRITES names {sorted(named ^ CREW_WRITES)} too"
    lists = [(r.tools, r.name) for r in roles.ALL.values()]
    lists.append((roles.HUNTER_PACK_TOOLS, "Hunter"))
    offered = {
        cap.name
        for names, who in lists
        for cap in tools.allowed(names, who)
        if not tools.is_read(cap)
    }
    assert offered == CREW_WRITES, f"the crew is offered the writes {sorted(offered)}"


def _tool_list(call: ast.Call) -> ast.expr | None:
    """The `names` a call to tools.specs, tools.allowed or tools.invoker passes."""
    at = 2 if _name(call.func) == "invoker" else 0
    named = next((k.value for k in call.keywords if k.arg == "names"), None)
    return named or (call.args[at] if len(call.args) > at else None)


def test_a_role_is_offered_only_its_own_tool_lists():
    """AGT-G1: every list handed to a model is a role's `tools` or the Hunter's backlog
    list, so the write-set check above sees every tool a role can call."""
    stray = [
        s.where
        for s in _sites("specs", "invoker", "allowed")
        if _receiver(s.call) == "tools"
        and _name(_tool_list(s.call) or ast.Name("")) not in ("tools", "HUNTER_PACK_TOOLS")
    ]
    assert not stray, "a tool list that is no role's:\n" + "\n".join(stray)


# -- AGT-G2 quieting needs the checks behind it ------------------------------
# Who may call each of the functions that quiet a rule or teach the crew.
QUIETING = {
    "_suppress": {"shoc/cases/routing.py:route"},
    "_remember": {"shoc/cases/routing.py:route"},
    "suppress_draft": {"shoc/cases/routing.py:_suppress", "shoc/agents/loop.py:_suppression"},
    "_suppression": {"shoc/agents/loop.py:run_case"},
}


def _crew_memory(call: ast.Call) -> bool:
    """`memory.add(..., source="crew")`, by keyword or as the sixth argument."""
    if _name(call.func) != "add" or _receiver(call) != "memory":
        return False
    source = next((k.value for k in call.keywords if k.arg == "source"), None)
    if source is None and len(call.args) > 5:
        source = call.args[5]
    return isinstance(source, ast.Constant) and source.value == "crew"


def test_quieting_is_called_only_from_the_gated_paths():
    """AGT-G2: a suppression or a crew memory note is written only behind the floor."""
    stray = [
        s.where
        for s in _sites(*QUIETING)
        if s.key not in QUIETING[_name(s.call.func)] and _receiver(s.call) != "self"
    ]
    stray += [
        f"{s.where}: memory.add(source='crew')"
        for s in _sites("add")
        if _crew_memory(s.call) and s.key != "shoc/cases/routing.py:_remember"
    ]
    for file in sorted(SHOC.rglob("*.py")):
        for no, line in enumerate(file.read_text().splitlines(), 1):
            if "INSERT INTO shoc.suppressions" in line and file.name != "routing.py":
                stray.append(f"{file.relative_to(ROOT).as_posix()}:{no}: writes a suppression")
    assert not stray, "quieting outside the gated paths:\n" + "\n".join(stray)


def test_route_quiets_only_past_the_floor():
    """AGT-G2: `routing.route` calls `_suppress` and `_remember` only under a test of
    `BENIGN_CLOSE_FLOOR`, so a crew close the checks do not back quiets nothing."""
    tree = ast.parse((SHOC / "cases" / "routing.py").read_text())
    route = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "route")
    gated: set[str] = set()
    for node in ast.walk(route):
        if isinstance(node, ast.If) and "BENIGN_CLOSE_FLOOR" in ast.unparse(node.test):
            gated |= {
                _name(c.func)
                for stmt in node.body
                for c in ast.walk(stmt)
                if isinstance(c, ast.Call)
            }
    assert {"_suppress", "_remember"} <= gated, "route quiets without testing the floor"


# -- AGT-G4 independent reads see only the case ------------------------------
class _ReadsTimeOut(ScriptedClient):
    """Every independent read times out; the claim check answers."""

    def complete(self, system, turns: list[Turn], max_tokens=2048, tools=None):
        if any("Read this case on your own" in t.content for t in turns):
            raise httpx.ReadTimeout("no answer")
        return super().complete(system, turns, max_tokens, tools)


# Behaviour the code still has, each with the finding that tracks it.
FAILED_READ_KNOWN = {
    "shoc/agents/checks.py:reads": "ai-8: a failed read is dropped (RFC 0020 not yet amended)",
}


def test_a_failed_read_counts_against_agreement(monkeypatch):
    """AGT-G4: a read that failed counts in the denominator, as a vote that did not agree.

    Two timeouts left agreement at 1 of 1, so a verdict no independent read had
    checked cleared the benign floor.
    """
    from shoc.agents import dossier

    monkeypatch.setattr(
        dossier, "_events", lambda *_a, **_k: [{"event_uid": "e1", "message": "backup ran"}]
    )
    client = _ReadsTimeOut(
        replies={"You check claims": json.dumps({"checks": [{"claim": 0, "support": "supported"}]})}
    )
    investigation = SimpleNamespace(
        verdict="benign_expected",
        confidence=0.9,
        claims=[roles.Claim(says="The nightly backup used the key.", citations=["e1"])],
    )
    config = SimpleNamespace(crew_samples=2, llm_max_tokens=1000, llm_model_cheap="")
    measured = checks.derive(client, None, "t", "the dossier", investigation, [], config)
    assert measured.checked == 1 and measured.supported == 1, "the claim check ran"
    found: dict[str, str] = {}
    if measured.reads != 3 or measured.agree != 1 or not measured.unsettled():
        found["shoc/agents/checks.py:reads"] = (
            f"shoc/agents/checks.py: two failed reads leave agreement at "
            f"{measured.agree} of {measured.reads}, unsettled={measured.unsettled()!r}"
        )
    _ratchet("AGT-G4", found, FAILED_READ_KNOWN)


# -- AGT-G5 citations and targets are checked against what the agent saw ------
# Calls that check citations against the whole tenant, each with why.
CITATION_ALLOWED = {
    "shoc/agents/openspace.py:post": "the store check every author gets, a person's and an "
    "outside assistant's included; the crew's citations are checked against its Evidence "
    "before it posts",
}


def test_citations_are_checked_against_the_evidence_shown():
    """AGT-G5: every `validate_citations` call passes what that agent was shown."""
    found: dict[str, str] = {}
    for s in _sites("validate_citations"):
        evidence = s.call.args[3] if len(s.call.args) > 3 else None
        evidence = next((k.value for k in s.call.keywords if k.arg == "evidence"), evidence)
        if evidence is None or (isinstance(evidence, ast.Constant) and evidence.value is None):
            found[s.key] = f"{s.where}: citations checked against the whole tenant"
    _ratchet("AGT-G5", found, CITATION_ALLOWED)


DECIDE_KNOWN = {
    "shoc/agents/manager.py:_page": "AGT-G5 gap: the Manager's notify.page leaves "
    "grounded=True and blast_radius=None to the defaults",
    "shoc/cases/playbooks.py:advance": "AGT-G5 gap: a playbook step leaves grounded=True and "
    "blast_radius=None to the defaults, which the policy reads as a playbook step",
}


def test_decide_and_proposals_name_their_measurements():
    """AGT-G5: `Policy.decide`, `Proposal` and `CrewProposal` are given `grounded` and
    `blast_radius`, and decide its `confidence`, never the defaults."""
    found: dict[str, str] = {}
    for s in _sites("decide", "Proposal", "CrewProposal"):
        callee = _name(s.call.func)
        if callee == "decide" and "policy" not in _receiver(s.call).lower():
            continue  # a backlog's decide, not the policy's
        if callee != "decide" and _receiver(s.call) == "roles":
            continue  # the model's output schema, not a proposal to act on
        wanted = {"grounded", "blast_radius"} | ({"confidence"} if callee == "decide" else set())
        missing = wanted - _keywords(s.call)
        if missing:
            found[s.key] = f"{s.where}: {callee} without {', '.join(sorted(missing))}"
    _ratchet("AGT-G5", found, DECIDE_KNOWN)


GROUNDING_KNOWN = {
    "shoc/agents/loop.py:_grounded": "ai-14: targets still match by substring of the "
    "evidence text (RFC 0020 not yet amended)",
}


def test_grounding_matches_whole_values():
    """AGT-G5: a target is grounded by the same value in the evidence, not by a longer one
    that contains it. `admin` was grounded by `administrator` and unlocked an L1."""
    from shoc.agents.loop import _grounded

    assert _grounded("192.0.2.1", "sourceIPAddress 192.0.2.1 user deploy-ci")
    assert not _grounded("192.0.2.77", "sourceIPAddress 192.0.2.1 user deploy-ci")
    loose = [
        f"{target!r} in {evidence!r}"
        for target, evidence in (
            ("admin", "userName administrator"),
            ("192.0.2.1", "sourceIPAddress 192.0.2.10"),
        )
        if _grounded(target, evidence)
    ]
    found: dict[str, str] = {"shoc/agents/loop.py:_grounded": "; ".join(loose)} if loose else {}
    _ratchet("AGT-G5", found, GROUNDING_KNOWN)


# -- AGT-G6 every model call has a deadline and a ceiling ---------------------
_TURN = "one turn bounded only by llm.CALL_SECONDS, not by its job's deadline"
DEADLINE_KNOWN = {
    "shoc/agents/checks.py:reads": f"AGT-G6 open: {_TURN}",
    "shoc/agents/checks.py:check_claims": f"AGT-G6 open: {_TURN}",
    "shoc/agents/detection_engineer.py:_work_one": f"token_budget only; {_TURN}",
    "shoc/agents/hunter.py:triaged": f"token_budget only; {_TURN}",
    "shoc/agents/hunter.py:_work_item": f"token_budget only; {_TURN}",
    "shoc/agents/integrator.py:repair": _TURN,
    "shoc/agents/ops.py:review": _TURN,
    "shoc/agents/reporter.py:narrate": _TURN,
    "shoc/agents/sentinel.py:_shape": _TURN,
    "shoc/agents/surveyor.py:read": _TURN,
    "shoc/capabilities/intel.py:_triage": _TURN,
    "shoc/capabilities/intel.py:_read": _TURN,
    "shoc/cases/review.py:review_action": _TURN,
}


def _bounded(site: Site) -> bool:
    """A model call given its job's time: `deadline=` or `timeout=` to complete_typed,
    `budget=` to loop._ask, or a call made under `with limit(...)`."""
    passed = _keywords(site.call)
    if _name(site.call.func) == "_ask":
        return site.limited or "budget" in passed
    return site.limited or bool({"deadline", "timeout"} & passed)


def test_every_model_call_has_a_deadline():
    """AGT-G6: every model call site takes the deadline of the job it runs in."""
    found = {
        s.key: f"{s.where}: {_name(s.call.func)} with no deadline"
        for s in _sites("complete_typed", "_ask")
        # `self._ask` is a peer's question, which calls loop._ask with a budget.
        if _receiver(s.call) != "self" and not _bounded(s)
    }
    _ratchet("AGT-G6", found, DEADLINE_KNOWN)


WATCHDOG_KNOWN = {
    "shoc/worker.py:HUNG_AFTER_SECONDS": "AGT-G6 open: derive's reads and claim check run "
    "after the budget with no deadline, and the formula's 10 minutes cover one call",
}


def test_the_watchdog_formula_covers_derives_calls(monkeypatch):
    """AGT-G6: a worker is not killed while a case's crew is still inside its bounds.

    Once the run's budget is checked before the Challenger, the CTI question,
    the Challenger and the rebuttal each still answer, one turn of at most
    `CALL_SECONDS` apiece; then `checks.derive` runs its reads and claim check.
    The watchdog must outlast all of them, unless derive's calls are held to
    the run's deadline (`timeout=` or `with limit(...)`).
    """
    from shoc import worker
    from shoc.agents.llm import CALL_SECONDS
    from shoc.agents.openspace import Budget
    from shoc.cases.engine import SEVERITY_ORDER
    from shoc.config import Config

    monkeypatch.delenv("SHOC_CREW_SAMPLES", raising=False)
    longest = max(Budget.for_case(s, reports=1).max_seconds for s in SEVERITY_ORDER)
    derive = [s for s in _sites("complete_typed") if s.path == "shoc/agents/checks.py"]
    assert derive, "checks.py makes the reads and the claim check"
    held = all(s.limited or "timeout" in _keywords(s.call) for s in derive)
    turns = 3 + (0 if held else Config().crew_samples + 1)
    margin = worker.HUNG_AFTER_SECONDS - longest
    found: dict[str, str] = {}
    if margin < turns * CALL_SECONDS:
        found["shoc/worker.py:HUNG_AFTER_SECONDS"] = (
            f"shoc/worker.py: {margin:.0f}s past the longest budget, where {turns} calls "
            f"may take {turns * CALL_SECONDS:.0f}s"
        )
    _ratchet("AGT-G6", found, WATCHDOG_KNOWN)
