"""The SOC Manager's reports (AGT-3, RFC 0015): the exception report, the
handover, the weekly and the founder's page. Pages are the Manager's too, in
`manager.py`.

A report is assembled from the tables — cases, findings, actions, health, spend
— and only then, if an LLM is configured, given a short narrative. The numbers
never come from a model, so a report is reproducible and citable even when the
crew is switched off.

The artifacts, each for a different reader:

- **The exception report** (D52), sent only when a decision needs a person and
  carrying only those decisions: an L2 nobody approved whose case is still
  open, a credential only somebody with access can grant or replace. Each is
  sent once. Most days there is none, and nothing is sent.
- **The handover**, per shift. A real SOC hands over in three reinforcing
  layers, and so does this — except that here the incoming shift is a person who
  was asleep. **The briefing** goes first because nobody reads the log first;
  **the log** is what happened, in order; **the checklist** is what the human
  has to do, and it is the only part they must not skip.
- **The weekly**: hunts and their outcomes, detections created and updated, gaps
  identified and closed, noisy and silent rules, source quality.
- **The monthly, for a founder**: what we protected, what it cost, and the two
  numbers somebody paying for this actually asks about — what is exposed, and
  what we would not have seen.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.agents import ops
from shoc.db.pool import Conn, execute, fetch_all, fetch_one

KINDS = ("shift", "weekly", "exec", "exception")
PERIODS = {
    "shift": timedelta(hours=12),
    "weekly": timedelta(days=7),
    "exec": timedelta(days=30),
    "exception": timedelta(days=1),
}
# A decision already in an exception report this recently is not sent again.
EXCEPTION_REPEAT_DAYS = 30


@dataclass
class Report:
    report_uid: str
    kind: str
    period_start: datetime
    period_end: datetime
    summary: str = ""
    body: dict[str, Any] = field(default_factory=dict)
    citations: list[str] = field(default_factory=list)


def _uid(tenant_id: str, kind: str, end: datetime) -> str:
    blob = f"{tenant_id}|{kind}|{end.isoformat()}"
    return "REP-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def build(
    conn: Conn,
    store: Any,
    tenant_id: str,
    kind: str = "shift",
    end: datetime | None = None,
    config: Any = None,
) -> Report:
    """Assemble a report for the period ending at `end`."""
    from shoc.errors import ValidationError

    if kind not in KINDS:
        raise ValidationError(f"unknown report kind '{kind}' (use {', '.join(KINDS)})")
    end = end or datetime.now(UTC)
    start = end - PERIODS[kind]
    if kind == "exception":
        items = exceptions(conn, tenant_id)
        return Report(
            report_uid=_uid(tenant_id, kind, end),
            kind=kind,
            period_start=start,
            period_end=end,
            summary=_exception_summary(items),
            body={"items": items},
            citations=[i["case_uid"] or i["reference"] for i in items],
        )

    cases = fetch_all(
        conn,
        """SELECT case_uid, title, severity, state, verdict, confidence, entity_key,
                  finding_uids, updated_at
           FROM shoc.cases
           WHERE tenant_id = %s AND updated_at BETWEEN %s AND %s
           ORDER BY
             array_position(ARRAY['critical','high','medium','low','informational'], severity),
             updated_at DESC""",
        (tenant_id, start, end),
    )
    findings = (
        fetch_one(
            conn,
            """SELECT count(*) FILTER (WHERE status NOT IN ('suppressed', 'self')) AS total,
                  count(*) FILTER (WHERE severity IN ('high','critical')
                                   AND status NOT IN ('suppressed', 'self')) AS serious,
                  count(*) FILTER (WHERE status = 'suppressed') AS suppressed,
                  count(*) FILTER (WHERE status = 'self') AS own
           FROM shoc.findings WHERE tenant_id = %s AND last_seen BETWEEN %s AND %s""",
            (tenant_id, start, end),
        )
        or {}
    )
    actions = fetch_all(
        conn,
        """SELECT type, state, autonomy, count(*) AS n FROM shoc.actions
           WHERE tenant_id = %s AND created_at BETWEEN %s AND %s
           GROUP BY type, state, autonomy ORDER BY n DESC""",
        (tenant_id, start, end),
    )
    waiting = [a for a in actions if a["state"] == "proposed"]
    top_rules = fetch_all(
        conn,
        """SELECT rule_id, count(*) AS n FROM shoc.findings
           WHERE tenant_id = %s AND last_seen BETWEEN %s AND %s
           GROUP BY rule_id ORDER BY n DESC LIMIT 10""",
        (tenant_id, start, end),
    )
    health = [h.__dict__ for h in ops.source_health(conn, tenant_id)]
    alerts = [a.to_json() for a in ops.alerts(conn, tenant_id, store=store)]
    money = ops.spend(conn, tenant_id, days=PERIODS[kind].days or 1)

    needs_human = [c for c in cases if c["verdict"] == "needs_human"]
    malicious = [c for c in cases if c["verdict"] == "malicious"]
    body: dict[str, Any] = {
        "cases": {
            "total": len(cases),
            "malicious": len(malicious),
            "needs_human": len(needs_human),
            "open": len([c for c in cases if c["state"] != "closed"]),
            "rows": cases[:20],
        },
        "findings": findings,
        "actions": {"rows": actions, "waiting_for_approval": len(waiting)},
        "top_rules": top_rules,
        "sources": health,
        "alerts": alerts,
        "spend": {"usd": money["usd_total"], "tokens": money["tokens"]},
    }
    citations = [c["case_uid"] for c in cases[:20]]

    if kind == "shift":
        body["handover"] = _handover(conn, tenant_id, cases, actions, start, end)
    if kind in ("weekly", "exec"):
        body["hunting"] = _hunting(conn, tenant_id, PERIODS[kind].days or 7)
        body["detection"] = _detection(conn, tenant_id)
        body["quality"] = _quality(conn, store, tenant_id)
        body["metrics"] = ops.metrics(conn, tenant_id, PERIODS[kind].days or 7)
        body["held"] = _held(conn, tenant_id, start, end)
    summary = _summary(kind, body, start, end)
    if kind == "exec":
        body["posture"] = _posture(conn, tenant_id, body)
    return Report(
        report_uid=_uid(tenant_id, kind, end),
        kind=kind,
        period_start=start,
        period_end=end,
        summary=summary,
        body=body,
        citations=citations,
    )


def _summary(kind: str, body: dict[str, Any], start: datetime, end: datetime) -> str:
    cases = body["cases"]
    findings = body["findings"]
    label = {"shift": "Handover", "weekly": "Weekly report", "exec": "Executive summary"}[kind]
    handover = body.get("handover") or {}
    parts = [
        f"{label} for {start:%d %b %H:%M} to {end:%d %b %H:%M} UTC.",
        # The briefing comes before the counts, because nobody reads the log first.
        *([handover["briefing"]] if handover.get("briefing") else []),
        f"{cases['total']} case(s): {cases['malicious']} malicious, "
        f"{cases['needs_human']} needing a human, {cases['open']} still open.",
        f"{int(findings.get('total') or 0)} finding(s), "
        f"{int(findings.get('serious') or 0)} high or critical.",
    ]
    if body["actions"]["waiting_for_approval"]:
        parts.append(f"{body['actions']['waiting_for_approval']} action(s) waiting for approval.")
    if body["alerts"]:
        parts.append(
            f"{len(body['alerts'])} pipeline alert(s): "
            + ", ".join(a["subject"] for a in body["alerts"][:3])
            + "."
        )
    else:
        parts.append("Pipeline healthy.")
    if body["spend"]["usd"]:
        parts.append(f"LLM spend ${body['spend']['usd']:.2f}.")
    if handover.get("checklist"):
        parts.append(f"{len(handover['checklist'])} thing(s) need you.")
    hunting = (body.get("hunting") or {}).get("metrics") or {}
    if hunting:
        outcomes = hunting.get("by_outcome") or {}
        parts.append(
            f"Hunts: {sum(outcomes.values())} run across {hunting['packs_hunted']} pack(s), "
            f"{outcomes.get('clear', 0)} clear (that is coverage), "
            f"{hunting['detections_proposed']} detection(s) proposed."
        )
    detection = body.get("detection") or {}
    if detection:
        parts.append(
            f"Detection backlog: {detection['backlog_open']} open, "
            f"{detection['not_observable']} needing data we do not ingest; "
            f"{detection['suppressions_active']} suppression(s) active."
        )
    quality = body.get("quality") or {}
    if quality.get("notes"):
        parts.append("Source quality: " + quality["notes"][0])
    return " ".join(parts)


def _handover(
    conn: Conn,
    tenant_id: str,
    cases: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """The three layers a real shift handover has.

    The incoming shift here is one person who was asleep, so the order matters
    more than it does in a staffed SOC: the briefing is what they read, the
    checklist is what they must not miss, and the log is what they go back to
    when the briefing raises a question.
    """
    log = fetch_all(
        conn,
        """SELECT type, subject, payload, created_at FROM shoc.stream_events
           WHERE tenant_id = %s AND created_at BETWEEN %s AND %s
             AND type IN ('case.opened','case.verdict','case.state_changed',
                          'action.proposed','action.done','ops.alert')
           ORDER BY created_at LIMIT 200""",
        (tenant_id, start, end),
    )
    waiting = fetch_all(
        conn,
        """SELECT action_uid, type, target, created_at, case_uid FROM shoc.actions
           WHERE tenant_id = %s AND state = 'proposed' ORDER BY created_at""",
        (tenant_id,),
    )
    # Backlog items and expiring suppressions are not listed here: the
    # Detection Engineer ends its own items (D48) and a suppression lapses by
    # itself (D77). Neither waits on a person.
    escalated = [c for c in cases if c["verdict"] == "needs_human"]
    bad = [c for c in cases if c["verdict"] in ("malicious", "suspicious")]

    checklist = [
        *(
            {
                "do": f"approve or reject {a['type']} on {a['target']}",
                "why": "an action has been waiting for a human",
                "reference": str(a["action_uid"]),
            }
            for a in waiting
        ),
        *(
            {
                "do": f"read {c['case_uid']}",
                "why": "the crew could not decide it and gathered the evidence for you",
                "reference": str(c["case_uid"]),
            }
            for c in escalated[:10]
        ),
    ]
    briefing = _briefing(bad, escalated, waiting)
    return {
        "briefing": briefing,
        "checklist": checklist,
        "unattended": _unattended(conn, tenant_id, start, end),
        "log": [
            {
                "at": row["created_at"],
                "what": str(row["type"]),
                "subject": str(row["subject"]),
                "detail": row["payload"],
            }
            for row in log
        ],
        "nothing_to_do": not checklist,
    }


def _unattended(conn: Conn, tenant_id: str, start: datetime, end: datetime) -> dict[str, Any]:
    """What happened without anybody, and who never spoke.

    The operator here does not watch the tool, so the useful thing to tell them
    is not only what needs them — the checklist already does that — but what was
    handled while they were away, and what was dropped because nobody came.

    `silent` is the number that catches a whole class of bug. CTI was reachable
    only by keyword for a release and therefore never spoke on any case; nothing
    was broken, nothing failed, and no report said so. A specialist that is
    never asked is now a line in the handover.
    """
    ran = fetch_all(
        conn,
        """SELECT action_uid, type, target, requested_by, dry_run, updated_at
           FROM shoc.actions
           WHERE tenant_id = %s AND state = 'done' AND updated_at BETWEEN %s AND %s
             AND coalesce(approved_by, '') = '' ORDER BY updated_at LIMIT 50""",
        (tenant_id, start, end),
    )
    dropped = fetch_all(
        conn,
        """SELECT action_uid, type, target, error, case_uid FROM shoc.actions
           WHERE tenant_id = %s AND state = 'rejected' AND approved_by = 'unattended'
             AND updated_at BETWEEN %s AND %s ORDER BY updated_at LIMIT 50""",
        (tenant_id, start, end),
    )
    spoke = fetch_all(
        conn,
        """SELECT agent, count(*) AS turns FROM shoc.openspace_messages
           WHERE tenant_id = %s AND created_at BETWEEN %s AND %s
           GROUP BY agent ORDER BY turns DESC""",
        (tenant_id, start, end),
    )
    heard = {str(r["agent"]) for r in spoke}
    from shoc.agents import roles

    return {
        "acted_without_you": [
            {
                "action": f"{r['type']} on {r['target']}",
                "planned_only": bool(r["dry_run"]),
                "reference": str(r["action_uid"]),
            }
            for r in ran
        ],
        "abandoned": [
            {
                "action": f"{r['type']} on {r['target']}",
                "why": str(r["error"] or "nobody decided in time"),
                "case": str(r["case_uid"] or ""),
            }
            for r in dropped
        ],
        "turns_by_agent": {str(r["agent"]): int(r["turns"]) for r in spoke},
        # Only the roles that take part in a case. The Hunter and the Integrator
        # not speaking about a case is them doing their jobs, and listing them
        # made the number that matters — a specialist that never spoke — invisible.
        "silent": sorted(name for name in roles.IN_CASE if name not in heard),
    }


def _briefing(
    bad: list[dict[str, Any]],
    escalated: list[dict[str, Any]],
    waiting: list[dict[str, Any]],
) -> str:
    """The short narrative at the top, assembled from counts rather than written.

    "Nothing needs you" is the most valuable sentence this system can produce
    for a company with no security team, and it must only appear when it is true.
    """
    if not (bad or escalated or waiting):
        return "Nothing from this shift needs you. The pipeline ran and nothing was decided badly."
    parts = []
    if bad:
        worst = bad[0]
        parts.append(
            f"{len(bad)} case(s) look real, worst first: {worst['case_uid']} "
            f"({worst['severity']}, {worst['verdict']}) on {worst['entity_key']}"
        )
    if escalated:
        parts.append(f"{len(escalated)} case(s) the crew would not decide alone")
    if waiting:
        parts.append(f"{len(waiting)} action(s) waiting for your approval")
    return ". ".join(parts) + "."


def _held(conn: Conn, tenant_id: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """What the Manager was told for the weekly: digests, and pages the gate
    turned into digests. A decision a person must make is not here; it is in
    the exception report (D52)."""
    return fetch_all(
        conn,
        """SELECT notice_uid, source, kind, severity, case_uid, body, created_at
           FROM shoc.notices
           WHERE tenant_id = %s AND created_at BETWEEN %s AND %s
             AND (kind = 'digest' OR outcome = 'digest')
           ORDER BY created_at LIMIT 100""",
        (tenant_id, start, end),
    )


def exceptions(conn: Conn, tenant_id: str) -> list[dict[str, Any]]:
    """The decisions only a person can make, each from a query (D52).

    An L2 that waited its window out unapproved while its case is still open:
    the system gave up on the action and the incident is not over. A source
    waiting on a credential, or whose credential its vendor now rejects: only
    somebody with access to that product can make a new one.
    """
    items: list[dict[str, Any]] = []
    for row in fetch_all(
        conn,
        """SELECT a.action_uid, a.type, a.target, a.error, a.case_uid
           FROM shoc.actions a
           JOIN shoc.cases c ON c.tenant_id = a.tenant_id AND c.case_uid = a.case_uid
           WHERE a.tenant_id = %s AND a.state = 'rejected' AND a.approved_by = 'unattended'
             AND c.state <> 'closed'
           ORDER BY a.updated_at LIMIT 20""",
        (tenant_id,),
    ):
        items.append(
            {
                "what": f"Decide on {row['type']} against {row['target']}, or another action, "
                f"for {row['case_uid']}",
                "why_only_a_human": "It needed a person's approval, nobody gave it in time, and the "
                f"case is still open ({row['error'] or 'expired'})",
                "case_uid": str(row["case_uid"]),
                "reference": str(row["action_uid"]),
            }
        )
    for row in fetch_all(
        conn,
        """SELECT source, scopes, click_path FROM shoc.source_onboarding
           WHERE tenant_id = %s AND step = 'credentials' ORDER BY source""",
        (tenant_id,),
    ):
        need = "; ".join(str(s) for s in (row["scopes"] or []) if s)
        items.append(
            {
                "what": f"Give shoc a credential for {row['source']}",
                "why_only_a_human": "Only somebody with access to it can create one"
                + (f": {need}" if need else "")
                + (f". {row['click_path']}" if row["click_path"] else ""),
                "case_uid": "",
                "reference": f"credentials:{row['source']}",
            }
        )
    for row in fetch_all(
        conn,
        """SELECT source, last_error FROM shoc.connector_state
           WHERE tenant_id = %s AND last_error LIKE '%%rejected the credential%%'
           ORDER BY source""",
        (tenant_id,),
    ):
        items.append(
            {
                "what": f"Replace {row['source']}'s credential",
                "why_only_a_human": f"{row['last_error']} Only somebody with access to "
                f"{row['source']} can issue a new one",
                "case_uid": "",
                "reference": f"rejected:{row['source']}",
            }
        )
    return items


def _exception_summary(items: list[dict[str, Any]]) -> str:
    if not items:
        return "Nothing needs you."
    return f"{len(items)} decision(s) need you: " + " ".join(
        f"{i + 1}. {item['what']}." for i, item in enumerate(items[:10])
    )


def send_exceptions(conn: Conn, store: Any, tenant_id: str, config: Any = None) -> str:
    """Send the exception report when a decision needs a person, and only then.

    A decision goes out once: the same action or source is not sent again for
    `EXCEPTION_REPEAT_DAYS`. Every item is a query, so the report is complete
    with no model; with one, the Manager adds a reading (D47).
    """
    from shoc.cases.engine import publish

    told = {
        str(r["reference"])
        for r in fetch_all(
            conn,
            """SELECT item->>'reference' AS reference
               FROM shoc.reports, jsonb_array_elements(body->'items') AS item
               WHERE tenant_id = %s AND kind = 'exception'
                 AND created_at > now() - %s * interval '1 day'""",
            (tenant_id, EXCEPTION_REPEAT_DAYS),
        )
    }
    report = build(conn, store, tenant_id, "exception", config=config)
    fresh = [i for i in report.body["items"] if i["reference"] not in told]
    if not fresh:
        return "exception report: nothing needs a person"
    report.body = {"items": fresh}
    report.summary = _exception_summary(fresh)
    report.citations = [i["case_uid"] or i["reference"] for i in fresh]
    reading = _reading(conn, tenant_id, report, config)
    if reading:
        report.body["reading"] = reading
    save(conn, tenant_id, report)
    publish(
        conn,
        tenant_id,
        "report.ready",
        report.report_uid,
        {"kind": "exception", "summary": report.summary[:1000], "items": len(fresh)},
    )
    from shoc.agents.manager import say_in_slack

    refused = say_in_slack(
        conn, tenant_id, config, text="\n".join([report.summary, *([reading] if reading else [])])
    )
    return f"exception report {report.report_uid}: {len(fresh)} decision(s)" + (
        f"; Slack: {refused}" if refused else ""
    )


def _reading(conn: Conn, tenant_id: str, report: Report, config: Any = None) -> str:
    """The Manager's reading of a report it did not compute, or "" with no model."""
    from shoc.agents.llm import from_config

    try:
        return narrate(report, from_config(config, conn, tenant_id), config, conn, tenant_id)
    except Exception:  # the reading is optional; the report is not
        return ""


def _hunting(conn: Conn, tenant_id: str, days: int) -> dict[str, Any]:
    """What was hunted, and what came of it. A clear hunt is coverage, not a blank."""
    from shoc.agents import hunter

    return {
        "metrics": hunter.metrics(conn, tenant_id, days),
        "runs": hunter.results(conn, tenant_id, days=days, limit=50),
        "backlog": hunter.backlog(conn, tenant_id, limit=20),
    }


def _detection(conn: Conn, tenant_id: str) -> dict[str, Any]:
    """The detection lifecycle as a set of counts, not a feeling."""
    from shoc.agents import detection_engineer as engineer
    from shoc.cases import routing

    backlog = engineer.backlog(conn, tenant_id, limit=100)
    costly = sorted(
        (h for h in ops.rule_health(conn, tenant_id) if h.tokens_30d),
        key=lambda h: -h.tokens_30d,
    )[:5]
    changed = fetch_all(
        conn,
        """SELECT rule_id, state, reason, merged_at, reverted_at, lapses_at FROM shoc.merged_rules
           WHERE tenant_id = %s AND greatest(merged_at, coalesce(reverted_at, merged_at))
                 > now() - interval '7 days'
           ORDER BY greatest(merged_at, coalesce(reverted_at, merged_at)) DESC LIMIT 20""",
        (tenant_id,),
    )
    return {
        "costliest_rules": [
            {"rule_id": h.rule_id, "tokens_30d": h.tokens_30d, "closed_30d": h.closed_30d}
            for h in costly
        ],
        "merges": changed,
        "backlog_open": len(backlog),
        "by_intake": {
            intake: len([i for i in backlog if i["intake"] == intake])
            for intake in sorted({str(i["intake"]) for i in backlog})
        },
        "not_observable": len([i for i in backlog if i["observability"] == "none"]),
        "suppressions_active": len(routing.active_suppressions(conn, tenant_id)),
        "rows": backlog[:20],
    }


def _quality(conn: Conn, store: Any, tenant_id: str) -> dict[str, Any]:
    """Source quality, worst first: the thing a green dashboard hides."""
    import contextlib

    scored: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        scored = [q.to_json() for q in ops.source_quality(conn, store, tenant_id)]
    return {
        "sources": scored,
        "worst": scored[0] if scored else None,
        "notes": [n for q in scored for n in q["notes"]][:10],
    }


def _posture(conn: Conn, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """The numbers a founder actually asks about."""
    graph = (
        fetch_one(
            conn,
            "SELECT count(*) AS nodes FROM shoc.graph_nodes WHERE tenant_id = %s",
            (tenant_id,),
        )
        or {}
    )
    iocs = (
        fetch_one(conn, "SELECT count(*) AS n FROM shoc.iocs WHERE tenant_id = %s", (tenant_id,))
        or {}
    )
    merged = (
        fetch_one(
            conn,
            "SELECT count(*) AS n FROM shoc.merged_rules WHERE tenant_id = %s AND state = 'merged'",
            (tenant_id,),
        )
        or {}
    )
    exposed = (
        fetch_one(
            conn,
            "SELECT count(*) AS n FROM shoc.exposures WHERE tenant_id = %s AND exposed",
            (tenant_id,),
        )
        or {}
    )
    unwatched = ((body.get("quality") or {}).get("worst") or {}).get("product", "")
    gaps = (
        fetch_one(
            conn,
            """SELECT count(*) AS n FROM shoc.detection_backlog
           WHERE tenant_id = %s AND state = 'open' AND kind = 'coverage'""",
            (tenant_id,),
        )
        or {}
    )
    return {
        "entities_watched": int(graph.get("nodes") or 0),
        "indicators_known": int(iocs.get("n") or 0),
        "rules_narrowed_here": int(merged.get("n") or 0),
        "human_actionable_per_day": round(body["cases"]["needs_human"] / 30, 2),
        # The two numbers a founder actually asks about, and the honest caveat
        # underneath them: this is what acted, not everything that exists.
        "exposed_entities": int(exposed.get("n") or 0),
        "what_we_would_not_have_seen": int(gaps.get("n") or 0),
        "weakest_source": unwatched,
        "caveat": (
            "Exposure is derived from ingested events: an asset that did nothing "
            "in the window is not counted."
        ),
    }


def save(conn: Conn, tenant_id: str, report: Report) -> None:
    execute(
        conn,
        """INSERT INTO shoc.reports (report_uid, tenant_id, kind, period_start, period_end,
                                     summary, body)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (report_uid) DO UPDATE SET
               summary = EXCLUDED.summary, body = EXCLUDED.body""",
        (
            report.report_uid,
            tenant_id,
            report.kind,
            report.period_start,
            report.period_end,
            report.summary,
            json.dumps(report.body, default=str),
        ),
    )


def narrate(
    report: Report, client: Any, config: Any = None, conn: Conn | None = None, tenant_id: str = ""
) -> str:
    """Optional: the Manager's reading of numbers already computed (D47).

    The Manager role answers in `ManagerOutput`; only `reading` is kept. The
    figures stay the query's, so a report reads the same without it.
    """
    from shoc.agents import roles
    from shoc.agents.llm import NoLLM, complete_typed, for_hint
    from shoc.agents.safety import quote, system_prompt

    if client is None or isinstance(client, NoLLM) or not getattr(client, "available", True):
        return ""
    said, usage = complete_typed(
        for_hint(client, roles.MANAGER.model_hint, config),
        system_prompt(roles.MANAGER.prompt),
        f"This is the {report.kind} report. In `reading`, say in at most four sentences "
        "what it means for the operator, using only these numbers.\n\n"
        + quote("report", report.body),
        roles.ManagerOutput,
        600,
    )
    if conn is not None:
        ops.charge(conn, tenant_id, usage)
    return (said.reading or "").strip()[:2000]


def send(
    conn: Conn, store: Any, tenant_id: str, kind: str = "weekly", config: Any = None
) -> tuple[Report, str]:
    """Build the weekly or executive report, keep it, and put it where the operator will see it.

    Nothing used to build or send either, so every digest the crew held "for the
    weekly" reached nobody (AGT-14). It goes onto the stream, and to the Slack
    channel as the Manager when one is configured; the console shows the last
    one. Returns the report and why Slack refused it, or "".
    """
    from shoc.agents.manager import say_in_slack
    from shoc.cases.engine import publish

    report = build(conn, store, tenant_id, kind, config=config)
    reading = _reading(conn, tenant_id, report, config)
    if reading:
        report.body["reading"] = reading
    save(conn, tenant_id, report)
    held = report.body.get("held") or []
    publish(
        conn,
        tenant_id,
        "report.ready",
        report.report_uid,
        {"kind": kind, "summary": report.summary[:1000], "held": len(held)},
    )
    lines = [
        report.summary,
        *([reading] if reading else []),
        *(f"• {str(n.get('body') or '')[:300]}" for n in held[:15]),
    ]
    return report, say_in_slack(conn, tenant_id, config, text="\n".join(lines))
