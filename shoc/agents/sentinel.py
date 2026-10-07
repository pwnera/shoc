"""Sentinel: what case each finding is part of (AGT-13, D43, RFC 0012).

Code groups a cycle's findings by the entities they share
(`engine.open_for_findings`), and that grouping is the floor: it runs with no
model, and a case it opens is a case. Sentinel then reads each case the cycle
touched and reshapes it where shared entities cannot see: it attaches a finding
to the open case it shares a graph path or a campaign with, splits off findings
that have become a different case, and rewrites what the case is about. It
takes no finding out of the crew's sight (D145): what is already settled is set
aside by code at intake, on exactly its rule and entity. It posts nothing in the
openspace and cannot be asked anything; each decision is kept on the finding it
moved (`evidence.sentinel`). A closed case stays closed (D78), so it reopens
nothing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from shoc.agents import roles, safety
from shoc.cases import engine
from shoc.db.pool import Conn, execute, fetch_all

log = logging.getLogger("shoc.sentinel")

# The open cases Sentinel is shown as places a finding could belong.
OPEN_CASES = 20


def shape(
    conn: Conn, store: Any, tenant_id: str, case_uids: list[str], client: Any, config: Any = None
) -> list[str]:
    """Reshape the cases a cycle touched. Returns the open cases left to investigate.

    A model that fails leaves the grouping code made: a case shaped by entity
    is still a case, and the next cycle's findings bring Sentinel back.
    """
    out: list[str] = []
    for case_uid in case_uids:
        try:
            out += _shape(conn, store, tenant_id, case_uid, client, config)
        except Exception as exc:  # the grouping stands without Sentinel
            log.warning("sentinel: %s kept as grouped: %s", case_uid, exc)
            out.append(case_uid)
    open_ = {
        str(r["case_uid"])
        for r in fetch_all(
            conn,
            "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s AND case_uid = ANY(%s) "
            "AND state <> 'closed'",
            (tenant_id, out),
        )
    }
    return [u for u in dict.fromkeys(out) if u in open_]


def _shape(
    conn: Conn, store: Any, tenant_id: str, case_uid: str, client: Any, config: Any
) -> list[str]:
    from shoc.agents import loop

    case = engine.get(conn, tenant_id, case_uid)
    if case is None or case["state"] == "closed":
        return []
    new = fetch_all(
        conn,
        """SELECT finding_uid, rule_id, title, severity, entity_key, entities, attack,
                  first_seen, last_seen, event_count
           FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s AND NOT (evidence ? 'sentinel')
           ORDER BY last_seen""",
        (tenant_id, case_uid),
    )
    if not new:
        return [case_uid]
    others = fetch_all(
        conn,
        """SELECT c.case_uid, c.title, c.severity, c.attack,
                  array_agg(e.entity) FILTER (WHERE e.entity IS NOT NULL) AS entities
           FROM shoc.cases c
           LEFT JOIN shoc.case_entities e ON e.tenant_id = c.tenant_id AND e.case_uid = c.case_uid
           WHERE c.tenant_id = %s AND c.state <> 'closed' AND c.case_uid <> %s
           GROUP BY c.case_uid ORDER BY c.updated_at DESC LIMIT %s""",
        (tenant_id, case_uid, OPEN_CASES),
    )
    prompt = "\n".join(
        [
            "The case these findings were grouped into, by the entities they share:",
            safety.quote(
                "case",
                {
                    "case_uid": case_uid,
                    "title": case["title"],
                    "entity": case["entity_key"],
                    "findings": len(case["finding_uids"] or []),
                },
            ),
            "",
            "The findings to place:",
            safety.quote("findings", new),
            "",
            "The other open cases:",
            safety.quote("open_cases", others),
            "",
            "Give every finding a decision. Attach only on a link you name, and split "
            "off what has become a different case.",
        ]
    )
    answer, usage = loop._ask(
        client, roles.SENTINEL, prompt, roles.SentinelOutput, config, conn, tenant_id, store
    )
    loop._charge(conn, tenant_id, usage)
    return apply(conn, tenant_id, case_uid, new, answer, {str(o["case_uid"]) for o in others})


def apply(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    new: list[dict[str, Any]],
    answer: roles.SentinelOutput,
    open_cases: set[str],
) -> list[str]:
    """Carry out Sentinel's decisions. Returns the cases they touched.

    A decision that does not hold is not carried out: an attach to a case it was
    not shown or with no named link, a split that would take every finding. The
    finding stays where code put it.
    """
    touched = [case_uid]
    placed = {str(f["finding_uid"]) for f in new}
    for g in answer.groupings:
        uid = str(g.finding_uid)
        if uid not in placed:
            continue
        kept = "open"
        if (
            g.decision == "attach"
            and g.case_uid in open_cases
            and g.basis != "none"
            and g.because.strip()
        ):
            touched.append(engine.move(conn, tenant_id, [uid], into=g.case_uid))
            kept = "attach"
        _mark(
            conn,
            tenant_id,
            uid,
            {
                "decision": kept,
                "case_uid": g.case_uid if kept == "attach" else "",
                "basis": g.basis,
                "because": g.because[:300],
            },
        )
    for f in new:  # a finding Sentinel was shown and did not place stays where it is
        _mark(conn, tenant_id, str(f["finding_uid"]), {"decision": "open"}, only_if_unmarked=True)
    remaining = [
        str(r["finding_uid"])
        for r in fetch_all(
            conn,
            "SELECT finding_uid FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, case_uid),
        )
    ]
    split = [u for u in dict.fromkeys(answer.split_off) if u in remaining]
    if split and len(split) < len(remaining):
        touched.append(engine.move(conn, tenant_id, split))
    if answer.subject.strip() and remaining:
        execute(
            conn,
            "UPDATE shoc.cases SET title = %s, updated_at = now() WHERE tenant_id = %s AND case_uid = %s",
            (answer.subject.strip()[:200], tenant_id, case_uid),
        )
    if not remaining:
        # Every finding went to another open case: the case was a grouping that
        # did not hold, and its findings are worked where they went.
        engine.transition(
            conn,
            tenant_id,
            case_uid,
            "closed",
            "Sentinel attached every finding to another case",
            by="system",
        )
    return touched


def _mark(
    conn: Conn,
    tenant_id: str,
    finding_uid: str,
    decision: dict[str, Any],
    only_if_unmarked: bool = False,
) -> None:
    execute(
        conn,
        """UPDATE shoc.findings
           SET evidence = coalesce(evidence, '{}'::jsonb) || jsonb_build_object('sentinel', %s::jsonb)
           WHERE tenant_id = %s AND finding_uid = %s"""
        + (" AND NOT (evidence ? 'sentinel')" if only_if_unmarked else ""),
        (json.dumps(decision), tenant_id, finding_uid),
    )
