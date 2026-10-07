"""What an agent may look up while it is thinking (AGT-1, AGT-2).

An agent used to be handed one dossier and asked for a verdict. Everything it
might have wanted to check — whether this address appeared last month, what else
the account did in the hour before, whether the hash is in any report we have
read — was either in that dossier or unreachable, and an analyst who cannot
pivot is not investigating, they are guessing about a sample.

So the registry becomes the tool list. A role names the capabilities it may
call, the call goes through `Capability.invoke` like every other caller's, and
the same checks apply: principal, scope, autonomy, typed input. A role is
offered reads, plus the writes its spec in `docs/agent-specs.md` names
(`WRITES`), and an L2 capability refuses an agent principal anyway (D8). Reads
run on the read-only database role when `SHOC_READONLY_DSN` is set (D22), so a
read that tried to write would fail in the database, not only in review.

What comes back is evidence written by whoever we are investigating, so it is
quoted as data (SEC-2) and trimmed: one query that returns a thousand rows must
not become the whole context window.

A role may also call another role this way (RFC 0012). Asking a colleague a
question used to go through the scheduler — post a `request`, wait for somebody
to be granted a turn — while querying eight capabilities did not, so the cheap
path was the one that skipped the colleague. A peer is now a tool like any other,
except that it runs with its own principal and its own capability list rather
than the caller's, so it is not a way to borrow scopes. When the work began
with somebody's request (`ask`), every role it reaches is offered only what that
caller may call too (`on_behalf`), so a question cannot end in a proposal.
"""

from __future__ import annotations

from typing import Any

from shoc.agents import safety
from shoc.agents.llm import ToolCall, ToolSpec

# The writes a role's spec names (docs/agent-specs.md, tool access matrix). A
# role is offered any read on its list and, of the rest, only these.
# CTI writes nothing when it answers: a URL in a case's logs is the attacker's
# to choose, and reading it from the case stored its values as indicators. A
# report reaches CTI's reading through a feed, a person, or `queue_read` (DET-7).
WRITES: dict[str, tuple[str, ...]] = {
    "IR Commander": ("action.propose",),
    "Surveyor": ("graph.refresh",),
    "Detection Engineer": ("detection.merge", "detection.revert"),
    # Only on its backlog turn's list; triage is offered reads alone (RFC 0032).
    "Hunter": ("hunt.merge",),
}
# Scope verbs that change nothing in shoc. `platforms:lookup` reads a platform
# with the action credentials and issues reads only (D56).
READ_VERBS = ("read", "lookup")

# One tool answer, at most. A query is allowed to be wrong about how much it
# asked for without costing the case its context, and a turn may make twelve.
MAX_RESULT = 8_000

# A peer call is a model call, so it is not free and it is not unbounded. The
# round structure used to bound a case by construction; this is what replaces it.
PEER_PREFIX = "ask_"


def peer_specs(peers: tuple[str, ...] = ()) -> list[ToolSpec]:
    """The roles this one may call, as tools it can call while it is thinking."""
    return [
        ToolSpec(
            name=f"{PEER_PREFIX}{name.lower().replace(' ', '_')}",
            description=(
                f"Ask {name} a question about this case and get an answer back "
                "before you conclude. Use it rather than inferring what they know."
            ),
            schema={
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "What you need from them, in one sentence",
                    }
                },
                "required": ["question"],
            },
        )
        for name in peers
    ]


def peer_name(tool: str, peers: tuple[str, ...]) -> str:
    """The role a peer tool name refers to, or an empty string."""
    for name in peers:
        if tool == f"{PEER_PREFIX}{name.lower().replace(' ', '_')}":
            return name
    return ""


def _capability(name: str) -> Any:
    from shoc.capabilities.registry import get

    return get(name)


def is_read(cap: Any) -> bool:
    return cap.scope.rpartition(":")[2] in READ_VERBS


def allowed(names: tuple[str, ...], who: str = "", on_behalf: Any = None) -> list[Any]:
    """The capabilities on `names` a role is offered (AGT-10, AGT-14).

    Its reads and the writes its spec names, and, when the work runs on behalf
    of a caller, only those that caller may call itself. A capability that is
    not built yet is simply not offered.
    """
    out = []
    for name in names:
        try:
            cap = _capability(name)
        except Exception:
            continue
        if not (is_read(cap) or name in WRITES.get(who, ())):
            continue
        if on_behalf is not None and not cap.permits(on_behalf):
            continue
        out.append(cap)
    return out


def specs(names: tuple[str, ...], who: str = "", on_behalf: Any = None) -> list[ToolSpec]:
    """The capabilities a role is offered, as tool definitions a model can call."""
    return [
        ToolSpec(name=cap.mcp_name, description=cap.summary, schema=cap.input_schema())
        for cap in allowed(names, who, on_behalf)
    ]


def invoker(
    tenant_id: str,
    config: Any = None,
    names: tuple[str, ...] = (),
    who: str = "agent",
    db: Any = None,
    store: Any = None,
    peers: tuple[str, ...] = (),
    ask: Any = None,
    on_behalf: Any = None,
) -> Any:
    """A function that runs one tool call and returns what to show the agent.

    The caller holds exactly the scopes of the capabilities on offer, so a role
    given three tools cannot reach a fourth. A call that fails answers with the
    error rather than raising: "src_ip must be an address" is something an agent
    can act on, and losing the whole turn to a bad argument is not.

    A read runs on the read-only role's connection when one is configured (D22);
    a write, and a read that is audited, on `db`.
    """
    from shoc.capabilities.registry import Caller, Context
    from shoc.db.pool import connect_readonly

    offered = {cap.mcp_name: cap for cap in allowed(names, who, on_behalf)}
    caller = Caller(
        kind="agent",
        id=f"agent:{who}",
        scopes=tuple(sorted({cap.scope for cap in offered.values()})),
    )
    acts = Context(tenant_id=tenant_id, caller=caller, config=config, _db=db, _store=store)
    reads = Context(
        tenant_id=tenant_id,
        caller=caller,
        config=config,
        _db=connect_readonly(config) or db,
        _store=store,
    )

    def run(call: ToolCall) -> str:
        wanted = peer_name(call.name, peers) if peers else ""
        if wanted:
            if ask is None:
                return f"{wanted} cannot be reached from here. Answer without them."
            question = str(call.arguments.get("question") or "").strip()
            if not question:
                return f"Ask {wanted} something: the question was empty."
            return ask(wanted, question)
        cap = offered.get(call.name)
        if cap is None:
            available = [*offered, *(spec.name for spec in peer_specs(peers))]
            return f"There is no tool called '{call.name}'. Use one of: {', '.join(available)}."
        try:
            result = cap.invoke(reads if is_read(cap) and not cap.audit else acts, call.arguments)
        except Exception as exc:
            # An error can repeat what it was given, and that came from a log.
            return f"{call.name} failed:\n" + safety.quote(
                f"error:{call.name}", f"{type(exc).__name__}: {exc}", limit=2_000
            )
        payload = result.to_json()
        rows = payload["data"].get("rows") if isinstance(payload["data"], dict) else None
        if rows and all(isinstance(r, dict) and r.get("event_uid") for r in rows):
            # Events read the way the dossier shows them: near-identical rows once,
            # with every id, so the ids need no second list beside them.
            payload["data"]["rows"] = safety.compact(rows)
            payload.pop("citations")
        return safety.quote(f"tool:{call.name}", payload, limit=MAX_RESULT)

    return run


def describe(used: list[str]) -> str:
    """What an agent looked up, for the openspace message that records its turn."""
    if not used:
        return ""
    counted: dict[str, int] = {}
    for name in used:
        counted[name] = counted.get(name, 0) + 1
    return "Looked up: " + ", ".join(
        f"{name}{f' x{n}' if n > 1 else ''}" for name, n in counted.items()
    )
