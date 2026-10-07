"""A weekly second look at what the crew closed as nothing (RFC 0020, AGT-6).

A wrong `benign_expected` is the failure nobody notices: the case is closed, the
activity gets a suppression, and on an install whose operator does not log in,
nothing ever reads it again. So once a week a handful of those closures are read
again, blind, on the strong model. A read that lands on the attack side reopens
the case and sends the crew back with the reason; one that agrees is recorded
and the case stays closed. Either way the case is marked, so it is read once.

It reopens and nothing more: no action, no page. What a reopened case deserves
is the crew's to decide, under the same policy as any other case.
"""

from __future__ import annotations

import contextlib
from typing import Any

from shoc.db.pool import Conn, fetch_all

# How many closures one week's recheck reads. Enough to notice a crew that has
# drifted towards "benign", few enough that a quiet install pays for five reads.
SAMPLE = 5
MARK = "Weekly recheck"
AGREES = "It agrees, and the case stays closed."

# Only shoc's own message counts as the recheck: anybody can post text into a
# case, and a line that starts the same way must not stand in for the read.
_READ = """EXISTS (
    SELECT 1 FROM shoc.openspace_messages m
    WHERE m.tenant_id = c.tenant_id AND m.case_uid = c.case_uid
      AND m.agent = 'shoc' AND m.principal = 'service' AND m.body LIKE 'Weekly recheck%%')"""
_WAITING = """EXISTS (
    SELECT 1 FROM shoc.detection_backlog b
    WHERE b.tenant_id = c.tenant_id AND b.case_uid = c.case_uid AND b.state = 'open')"""


def agreed(conn: Conn, tenant_id: str, case_uid: str) -> bool:
    """Whether the weekly recheck read this closure again and agreed with it."""
    return bool(
        fetch_all(
            conn,
            """SELECT 1 FROM shoc.openspace_messages
           WHERE tenant_id = %s AND case_uid = %s AND agent = 'shoc'
             AND principal = 'service' AND body LIKE %s AND body LIKE %s LIMIT 1""",
            (tenant_id, case_uid, MARK + "%", "%" + AGREES),
        )
    )


def run(conn: Conn, store: Any, tenant_id: str, config: Any, client: Any = None) -> str:
    from shoc.agents import checks, ops
    from shoc.agents.dossier import build_dossier
    from shoc.agents.llm import NoLLM, from_config
    from shoc.agents.openspace import Message, post
    from shoc.cases import engine
    from shoc.db import jobs

    client = client if client is not None else from_config(config, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return "recheck: no model is configured, so nothing was read again"
    # A crew closure waiting to change a rule is read first: the Detection
    # Engineer may not merge on it until this read agrees (D77). A person's
    # closure is theirs and is read again only once a later case follows it.
    rows = fetch_all(
        conn,
        f"""SELECT * FROM shoc.cases c
           WHERE tenant_id = %s AND state = 'closed'
             AND verdict IN ('benign_expected', 'false_positive')
             AND NOT ({_READ})
             AND (c.closed_by IS DISTINCT FROM 'human' OR EXISTS (
                 SELECT 1 FROM shoc.cases n
                 WHERE n.tenant_id = c.tenant_id AND n.related_case_uid = c.case_uid
                   AND n.opened_at > c.closed_at))
             AND (c.closed_at > now() - interval '7 days' OR {_WAITING})
           ORDER BY ({_WAITING}) DESC, random() LIMIT %s""",
        (tenant_id, SAMPLE),
    )
    read = reopened = 0
    for case in rows:
        dossier = build_dossier(conn, store, tenant_id, case)
        verdicts, usage = checks.reads(client, dossier.text, 1, config, hint="strong")
        ops.charge(conn, tenant_id, usage)
        if not verdicts:  # the model could not be read; next week tries again
            continue
        read += 1
        again = verdicts[0]
        disagrees = checks.side(again) != checks.side(str(case["verdict"]))
        body = (
            f"{MARK}: an independent read on {usage.model or 'the model'} reaches "
            f"{again}, where the crew closed this as {case['verdict']}. "
            + ("The case is reopened for the crew to work again." if disagrees else AGREES)
        )
        post(
            conn,
            None,
            tenant_id,
            case["case_uid"],
            Message(agent="shoc", kind="inject", body=body, principal="service"),
        )
        if disagrees:
            with contextlib.suppress(Exception):
                engine.transition(conn, tenant_id, case["case_uid"], "triage", body)
                jobs.enqueue(
                    conn,
                    tenant_id,
                    "case.investigate",
                    {"case_uid": case["case_uid"]},
                    idempotency_key=f"recheck:{case['case_uid']}",
                )
                reopened += 1
    return f"recheck: read {read} closed case(s) again, reopened {reopened}"
