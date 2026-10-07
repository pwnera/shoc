"""The dossier: everything an agent may see about a case (AGT-1, SEC-2).

One place assembles what the openspace looks at, so that no role has a private
view of the case and every section is bounded. A busy day is the shape that
matters: 406 findings on one case is real, and the prompt has to stay readable,
so each part says how much it left out rather than growing without limit.

Log content is quoted as data, never as instruction (principle 6). The graph and
the posture are labelled as scope rather than evidence, because an entity next to
a case is not an accusation. Any section whose lookup fails contributes nothing:
a missing world graph is better than a blocked investigation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.agents import memory, observables, safety
from shoc.db.pool import Conn, fetch_all
from shoc.store.base import EventStore

MAX_EVIDENCE_EVENTS = 40
# A busy case can carry hundreds of findings. The dossier takes the worst of
# them and says how many it left out, so a prompt (and a Slack message) stays a
# readable size however loud the day is.
MAX_DOSSIER_FINDINGS = 25
# Scoping is a question about the entities in the case, not a tour of the
# company: one hop from each of a handful of roots is what stays meaningful.
MAX_SCOPE_ROOTS = 5
MAX_SCOPE_NODES = 40


def findings(
    conn: Conn, tenant_id: str, case: dict[str, Any], limit: int | None = None
) -> list[dict[str, Any]]:
    """The case's findings, worst first. `limit` caps what reaches a prompt."""
    return fetch_all(
        conn,
        """SELECT finding_uid, rule_id, title, severity, entity_key, event_count,
                  first_seen, last_seen, event_uids, attack, evidence
           FROM shoc.findings WHERE tenant_id = %s AND finding_uid = ANY(%s)
           ORDER BY
             array_position(ARRAY['critical','high','medium','low','informational'], severity),
             last_seen DESC
           LIMIT %s""",
        (tenant_id, list(case["finding_uids"] or []), limit or 1000),
    )


def finding_count(conn: Conn, tenant_id: str, case: dict[str, Any]) -> int:
    return len(case["finding_uids"] or [])


def _events(
    store: EventStore,
    tenant_id: str,
    uids: list[str],
    raw: bool = False,
    limit: int = MAX_EVIDENCE_EVENTS,
) -> list[dict[str, Any]]:
    """The cited events. With `raw`, each carries its original record as flat,
    capped fields: the scope, the client id and the permission names that make
    a claim checkable often exist only there."""
    from shoc.capabilities.events import EventQuery, build_query

    wanted = list(dict.fromkeys(uids))[:limit]
    if not wanted:
        return []
    sql, params, limit = build_query(
        EventQuery(event_uids=wanted, limit=len(wanted), include_raw=raw), tenant_id
    )
    rows = store.query(sql, params, limit).rows
    if raw:
        for row in rows:
            row.pop("unmapped", None)
            row.pop("observables", None)
            row["raw"] = flatten(row.get("raw"))
    return rows


RAW_FIELDS = 60
RAW_FIELD_CHARS = 200


def flatten(value: Any, prefix: str = "raw") -> dict[str, str]:
    """A record as dotted leaf paths, each value capped, at most RAW_FIELDS of them.

    Google's named parameters (`[{name, value}]`) read as `parameters.<name>`,
    the way the mappings address them.
    """
    import json as _json

    out: dict[str, str] = {}

    def walk(node: Any, path: str) -> None:
        if len(out) >= RAW_FIELDS:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                walk(child, f"{path}.{key}")
        elif isinstance(node, list):
            named = all(isinstance(i, dict) and "name" in i for i in node) and node
            for i, child in enumerate(node):
                if named:
                    rest = {k: v for k, v in child.items() if k != "name"}
                    walk(
                        rest if len(rest) != 1 else next(iter(rest.values())),
                        f"{path}.{child['name']}",
                    )
                else:
                    walk(child, f"{path}[{i}]")
        elif node not in (None, ""):
            text = node if isinstance(node, str) else _json.dumps(node, default=str)
            out[path] = text[:RAW_FIELD_CHARS]

    if isinstance(value, str):
        try:
            value = _json.loads(value)
        except ValueError:
            return {prefix: value[:RAW_FIELD_CHARS]}
    walk(value, prefix)
    return out


@dataclass
class Dossier:
    """What everybody in the openspace is looking at."""

    text: str = ""
    evidence_uids: list[str] = field(default_factory=list)
    observables: list[observables.Observable] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)


def build_dossier(conn: Conn, store: EventStore, tenant_id: str, case: dict[str, Any]) -> Dossier:
    """Everything an agent may see about a case, with log content quoted as data."""
    total = finding_count(conn, tenant_id, case)
    worst = findings(conn, tenant_id, case, MAX_DOSSIER_FINDINGS)
    uids = [u for f in worst for u in (f["event_uids"] or [])]
    events = _events(store, tenant_id, uids, raw=True)
    facts = memory.context_for(conn, tenant_id, case["entity_key"])
    around = _neighbourhood(conn, tenant_id, case)
    standing = _posture(conn, tenant_id, case)
    contains = observables.of_case(worst, events, list(case.get("attack") or []))
    held = _best_effort(observables.known, conn, tenant_id, contains)
    published = _best_effort(observables.reports, conn, tenant_id, contains)
    guides = _best_effort(_guides, conn, tenant_id, case)
    summary = {
        "case_uid": case["case_uid"],
        "entity": case["entity_key"],
        "severity": case["severity"],
        "attack": list(case["attack"] or []),
        "findings": [
            {
                "rule_id": f["rule_id"],
                "title": f["title"],
                "severity": f["severity"],
                "events": f["event_count"],
                "first_seen": str(f["first_seen"]),
                "last_seen": str(f["last_seen"]),
            }
            for f in worst
        ],
        "findings_total": total,
        "findings_shown": len(worst),
    }
    parts = [
        "Case under discussion (the entity name comes from the logs, so this is quoted too):",
        safety.quote("case", summary),
        "",
        "Evidence (log records; cite the event_uid values you rely on):",
        safety.quote_events(events),
    ]
    for guide in guides:
        parts += [
            "",
            f"Questions this case has to answer ({guide['playbook']}). Answer each "
            "with the event_uid values that settle it, or say that no event does:",
            *(f"- {q['id']}: {q['ask']}" for q in guide["questions"]),
        ]
        if guide["benign_when"]:
            parts += [
                "It is benign when one of these holds, and the evidence shows it:",
                *(f"- {b}" for b in guide["benign_when"]),
            ]
        if guide["example"]:
            parts += [
                "What a good answer looks like, from an invented case rather than this one:",
                f"<example>\n{guide['example']}\n</example>",
            ]
    # Who wrote a memory decides what it can prove. A person's statement can rule
    # an explanation in or out; the crew's own earlier conclusion cannot, or one
    # case talked into "benign" becomes the written fact that clears the next.
    told, concluded = memory.split(facts)
    if told:
        parts += [
            "",
            "What people at this company have told us:",
            safety.quote("tenant-memory", told),
        ]
    if concluded:
        parts += [
            "",
            "What earlier cases and hunts concluded. This is the system's own reading, "
            "which no person confirmed, so it is not a written fact and it proves "
            "nothing here:",
            safety.quote("crew-memory", concluded),
        ]
    if around:
        parts += [
            "",
            "What else these entities touch, from the world graph (for scoping — "
            "an entity here is not itself evidence of anything):",
            safety.quote("world-graph", around),
        ]
    if standing:
        parts += [
            "",
            "What the Surveyor knows about the entities in this case — whether they "
            "are privileged, exposed or stale, observed from events rather than "
            "declared anywhere:",
            safety.quote("posture", standing),
        ]
    if contains:
        parts += [
            "",
            "What the evidence contains that somebody could research — this is "
            "extracted from the events above, so an entry here is not itself a "
            "verdict on anything:",
            safety.quote("observables", [o.to_json() for o in contains]),
        ]
    if held:
        parts += [
            "",
            "What our feeds and our own past lookups already say about those:",
            safety.quote("indicator-store", held),
        ]
    if published:
        parts += [
            "",
            "Reports we have already read that describe this technique, this "
            "command-line shape or this malware:",
            safety.quote("intel-reports", published),
        ]
    return Dossier(
        text="\n".join(parts),
        evidence_uids=[str(e["event_uid"]) for e in events],
        observables=contains,
        reports=published,
    )


def _guides(conn: Conn, tenant_id: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    """The analysis half of each playbook that answers this case's rules (RFC 0013)."""
    from shoc.cases import playbooks

    fired = playbooks.rules_of_case(conn, tenant_id, case["case_uid"])
    return [
        {
            "playbook": b.id,
            "questions": [{"id": q.id, "ask": q.ask} for q in b.questions],
            "benign_when": b.benign_when,
            "example": b.example,
        }
        for b in playbooks.for_rules(fired, None, conn, tenant_id)
    ]


def _best_effort(ask: Any, *args: Any) -> list[dict[str, Any]]:
    """What a lookup found, or nothing. A dossier is never blocked on one section."""
    import contextlib

    with contextlib.suppress(Exception):
        return ask(*args)
    return []


def _posture(conn: Conn, tenant_id: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    """The Surveyor's answer on this case's entities (AGT-3, RFC 0006 §3).

    Whether the account in front of you can attach a policy changes what the
    same events mean, and until the Surveyor existed the Investigator and the
    Commander both guessed at it. A posture that has never been taken gives
    nothing rather than blocking the case.
    """
    import contextlib

    from shoc.agents import surveyor

    out: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        rows = fetch_all(
            conn,
            "SELECT entity FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, case["case_uid"]),
        )
        for row in rows[:MAX_SCOPE_ROOTS]:
            answer = surveyor.exposure_of(conn, tenant_id, str(row["entity"]))
            out.append(
                {
                    "entity": answer.get("entity"),
                    "known": answer.get("known"),
                    "privileged": bool(answer.get("privileged")),
                    "exposed": bool(answer.get("exposed")),
                    "stale": bool(answer.get("stale")),
                    "answer": answer.get("answer"),
                }
            )
    return out


def _neighbourhood(conn: Conn, tenant_id: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    """The entities around this case, so a verdict can say how far it spread.

    The graph is a description of what happened, not an accusation: it is shown
    for scope and labelled as such. A graph that has never been refreshed simply
    gives nothing, which is better than blocking the investigation.
    """
    import contextlib

    from shoc.agents import graph

    entity = str(case.get("entity_key") or "")
    if not entity:
        return []
    out: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        rows = fetch_all(
            conn,
            "SELECT entity FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, case["case_uid"]),
        )
        for row in rows[:MAX_SCOPE_ROOTS]:
            walk = graph.neighbours(
                conn, tenant_id, str(row["entity"]), hops=1, limit=MAX_SCOPE_NODES
            )
            out += [
                {"root": walk.root, "node": n["node_id"], "kind": n["kind"], "events": n["events"]}
                for n in walk.nodes
                if n["node_id"] != walk.root
            ]
    return out[:MAX_SCOPE_NODES]
