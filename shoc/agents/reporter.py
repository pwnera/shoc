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

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.agents import ops
from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.ids import make_id

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


def build(
    conn: Conn,
    store: Any,
    tenant_id: str,
    kind: str = "shift",
    end: datetime | None = None,
    config: Any = None,
) -> Report:
    """Assemble a report for the period ending at `end`."""
    from shoc.agents.llm import budget
    from shoc.errors import ValidationError

    if kind not in KINDS:
        raise ValidationError(f"unknown report kind '{kind}' (use {', '.join(KINDS)})")
    end = end or datetime.now(UTC)
    start = end - PERIODS[kind]
    if kind == "exception":
        items = exceptions(conn, tenant_id, config)
        return Report(
            report_uid=make_id("REP-", tenant_id, kind, end.isoformat()),
            kind=kind,
            period_start=start,
            period_end=end,
            summary=_exception_summary(items),
            body={"items": items},
            citations=[i["case_uid"] or i["reference"] for i in items],
        )

    cases = fetch_all(
        conn,
        # A case closed once its findings went to another case was a grouping
        # that did not hold, not an incident: those findings count where they went.
        """SELECT case_uid, title, severity, state, verdict, confidence, entity_key,
                  finding_uids, updated_at
           FROM shoc.cases
           WHERE tenant_id = %s AND updated_at BETWEEN %s AND %s
             AND NOT (state = 'closed' AND cardinality(finding_uids) = 0)
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
             AND status NOT IN ('suppressed', 'self')
           GROUP BY rule_id ORDER BY n DESC LIMIT 10""",
        (tenant_id, start, end),
    )
    health = [h.__dict__ for h in ops.source_health(conn, tenant_id)]
    alerts = [
        a.to_json()
        for a in ops.alerts(
            conn,
            tenant_id,
            # The cap llm.configure stored, as `ops.alerts` the capability reads it.
            budget_usd_per_day=budget(conn, tenant_id, "spend_usd_per_day"),
            store=store,
            config=config,
        )
    ]
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
        body["intel"] = _intel(conn, tenant_id, start, end)
        body["held"] = _held(conn, tenant_id, start, end)
    summary = _summary(kind, body, start, end)
    if kind == "exec":
        body["posture"] = _posture(conn, tenant_id, body)
    return Report(
        report_uid=make_id("REP-", tenant_id, kind, end.isoformat()),
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
    intel = body.get("intel") or {}
    if intel:
        parts.append(
            f"Intel: {intel['reports_read']} report(s) read, "
            f"{intel['ioc_match'] + intel['ioc_retrohunt']} indicator finding(s)."
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
             AND coalesce(approved_by, '') = ''
             -- a person's preview: its steps are settled as plans, never run (RSP-7)
             AND NOT (dry_run AND executed_at IS NULL)
           ORDER BY updated_at LIMIT 50""",
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
    the exception report (D52).

    One row per source, kind and group, with its latest body cut where Slack's
    copy cuts it and how many notices it stands for: an hourly Ops digest held
    35 times filled most of a weekly too large for an assistant to read.
    """
    return fetch_all(
        conn,
        """SELECT (array_agg(notice_uid ORDER BY created_at DESC))[1] AS notice_uid,
                  source, kind, group_key,
                  (array_agg(severity ORDER BY created_at DESC))[1] AS severity,
                  (array_agg(case_uid ORDER BY created_at DESC))[1] AS case_uid,
                  left((array_agg(body ORDER BY created_at DESC))[1], 300) AS body,
                  max(created_at) AS created_at, count(*) AS count
           FROM shoc.notices
           WHERE tenant_id = %s AND created_at BETWEEN %s AND %s
             AND (kind = 'digest' OR outcome = 'digest')
           GROUP BY source, kind, group_key
           ORDER BY min(created_at) LIMIT 100""",
        (tenant_id, start, end),
    )


def exceptions(conn: Conn, tenant_id: str, config: Any = None) -> list[dict[str, Any]]:
    """The decisions only a person can make, each from a query (D52).

    An L2 that waited its window out unapproved while its case is still open:
    the system gave up on the action and the incident is not over. The same
    after the crew closed the case, until a person acknowledges it (D152):
    quiet logs do not mean the key was revoked. A source
    waiting on a credential, or whose credential its vendor now rejects: only
    somebody with access to that product can make a new one. A vendor shoc
    reads and holds no response credential for, and dry run left on: either
    way nothing is contained, and only the operator can change it. An indicator
    held as too common here, which only a person's `intel.add` releases.

    First, no way to reach a person at all. The report itself then reaches
    only the console and `report.get`, but those are where it can be read.
    Then a model that stopped answering, and pages that reached nobody.
    """
    from shoc.actions.base import NEEDS
    from shoc.agents.manager import REFUSED, reachable
    from shoc.cases import credentials
    from shoc.cases.engine import CONTAINED, UNACKNOWLEDGED

    items: list[dict[str, Any]] = []
    if not any(reachable(conn, tenant_id, config).values()):
        items.append(
            {
                "what": "Give shoc a way to reach you: a PagerDuty routing key "
                "(credential.configure notify) or a Slack channel (slack.configure)",
                "why_only_a_human": "shoc holds no pager key, Slack channel, mail server with "
                "a signed-in admin or webhook, so every page and report reaches nobody. Only "
                "somebody with access to PagerDuty or Slack can create one",
                "case_uid": "",
                "reference": "notify:unreachable",
            }
        )
    if down := ops.model_down(conn, tenant_id):
        since = f"{down['since']:%Y-%m-%d %H:%M} UTC" if down["since"] else "it was set up"
        said = "has failed every call"
        if down["status"]:
            said = f"{REFUSED[down['status']]} (HTTP {down['status']})"
        # One item per outage: it began after the last answer.
        outage = f"{down['since']:%Y-%m-%dT%H:%M}" if down["since"] else "never"
        items.append(
            {
                "what": f"Fix the model provider: it {said} (llm.configure)",
                "why_only_a_human": f"No model call has come back since {since}, so no case "
                "is investigated. Only somebody with the provider account can renew the key "
                "or the credit",
                "case_uid": "",
                "reference": f"llm:{outage}",
            }
        )
    failed = fetch_one(
        conn,
        # Settled as failed: a page still being retried has no outcome yet.
        """SELECT count(*) AS n, max(delivered_at) AS at,
                  (array_agg(last_error ORDER BY delivered_at DESC))[1] AS error
           FROM shoc.notices
           WHERE tenant_id = %s AND kind = 'page' AND outcome = 'failed'
             AND delivered_at > now() - interval '24 hours'""",
        (tenant_id,),
    )
    if failed and int(failed["n"]):
        items.append(
            {
                "what": f"Make pages reach you: {failed['n']} page(s) in the last 24h reached "
                "nobody",
                "why_only_a_human": f"The last one failed with: {failed['error'] or 'no reason'}. "
                "Only somebody with access to the pager, Slack or the mail server can fix it",
                "case_uid": "",
                "reference": f"page:failed:{failed['at']:%Y-%m-%d}",
            }
        )
    for row in fetch_all(
        conn,
        f"""SELECT a.action_uid, a.type, a.target, a.error, a.case_uid,
                   c.state = 'closed' AS closed
            FROM shoc.actions a
            JOIN shoc.cases c ON c.tenant_id = a.tenant_id AND c.case_uid = a.case_uid
            WHERE a.tenant_id = %s AND a.state = 'rejected' AND a.approved_by = 'unattended'
              AND (c.state <> 'closed'
                   OR ({UNACKNOWLEDGED}
                       AND a.updated_at > coalesce(c.acknowledged_at, '-infinity')))
            ORDER BY a.updated_at LIMIT 20""",
        (tenant_id,),
    ):
        why = "the case closed without it" if row["closed"] else "the case is still open"
        items.append(
            {
                "what": f"Decide on {row['type']} against {row['target']}, or another action, "
                f"for {row['case_uid']}" + (", or acknowledge the case" if row["closed"] else ""),
                "why_only_a_human": "It needed a person's approval, nobody gave it in time, and "
                f"{why} ({row['error'] or 'expired'})",
                "case_uid": str(row["case_uid"]),
                # A new key once the case closes, so the person hears about it again.
                "reference": ("closed:" if row["closed"] else "") + str(row["action_uid"]),
            }
        )
    # A malicious case the crew closed with nothing contained, no action
    # proposed included: with no response credential the crew has none to propose.
    listed = {i["case_uid"] for i in items}
    for row in fetch_all(
        conn,
        f"""SELECT c.case_uid, c.title FROM shoc.cases c
            WHERE c.tenant_id = %s AND c.state = 'closed' AND c.verdict = 'malicious'
              AND c.closed_by IS DISTINCT FROM 'human'
              AND coalesce(c.acknowledged_at, '-infinity') < c.closed_at
              AND NOT {CONTAINED}
            ORDER BY c.updated_at DESC LIMIT 20""",
        (tenant_id,),
    ):
        if row["case_uid"] in listed:
            continue
        items.append(
            {
                "what": f"Act on {row['case_uid']} ({row['title']}), or acknowledge it",
                "why_only_a_human": "The crew found it malicious and closed it, and no response "
                "action ran on it, so nothing contained it",
                "case_uid": str(row["case_uid"]),
                "reference": f"uncontained:{row['case_uid']}",
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
    # An indicator held as too common here opens no finding and is not matched
    # again until a person's intel.add releases it (D166).
    for row in fetch_all(
        conn,
        """SELECT DISTINCT ON (i.type, i.value) i.type, i.value, i.source, n.body
           FROM shoc.iocs i
           JOIN shoc.notices n ON n.tenant_id = i.tenant_id
                AND n.group_key = 'intel:held:' || i.type || ':' || i.value
           WHERE i.tenant_id = %s AND 'prevalent' = ANY(i.tags)
             AND n.created_at > now() - interval '7 days'
           ORDER BY i.type, i.value, n.created_at DESC LIMIT 20""",
        (tenant_id,),
    ):
        # The feed and count the hold notice names: with two feeds listing the
        # value, the row kept above may carry the other one.
        body, lead = str(row["body"]), f"{row['value']}, listed by "
        said = (
            re.match(r"(.+?), touched (\d+) accounts", body[len(lead) :])
            if body.startswith(lead)
            else None
        )
        source, touched = said.groups() if said else (row["source"], "several")
        items.append(
            {
                "what": f"Decide on {row['type']} {row['value']}: release it with intel.add, "
                "or leave it held",
                "why_only_a_human": f"{source} lists it, and its first match touched "
                f"{touched} accounts here, so it was held "
                "as too common to raise: it opens no finding and is not matched again. Only "
                "a person's intel.add releases it",
                "case_uid": "",
                "reference": f"intel:held:{row['type']}:{row['value']}",
            }
        )
    if switch := _dry_run_switch(config):
        items.append(
            {
                "what": f"Turn dry run off ({switch}) once the policy says what may run",
                "why_only_a_human": "While it is on, the response actions it covers are "
                "planned and none runs, so no case is contained with them. It is set where "
                "shoc is deployed",
                "case_uid": "",
                "reference": "dry_run",
            }
        )
    held = {credentials.provider_of(n) for n in credentials.providers(conn, tenant_id)}
    for provider in sorted(credentials.in_use(conn, tenant_id) - held):
        how = NEEDS.get(provider)
        items.append(
            {
                "what": f"Give shoc a {provider} response credential",
                "why_only_a_human": f"shoc reads {provider} and holds no credential to act "
                "there, so nothing it finds there is contained. Only somebody with access "
                "can create one" + (f": {how.where}" if how and how.where else ""),
                "case_uid": "",
                "reference": f"response:{provider}",
            }
        )
    return items


def _dry_run_switch(config: Any = None) -> str:
    """The switch that keeps response a plan, or "" when actions run (RSP-7).

    The same check the policy decides each action with: SHOC_DRY_RUN when it is
    set, either way, else `dry_run` in the policy's defaults or an action's rule.
    """
    from shoc.cases.policy import Policy
    from shoc.config import Config

    cfg = config or Config.load()
    if cfg.dry_run is not None:
        return "SHOC_DRY_RUN=0" if cfg.dry_run else ""
    policy = Policy.load(cfg)
    if policy.dry_run_for():
        return "dry_run: false under defaults in policy.yaml"
    held = sorted(a for a in policy.actions if policy.dry_run_for(a))
    return f"dry_run: false for {', '.join(held)} in policy.yaml" if held else ""


def _exception_summary(items: list[dict[str, Any]]) -> str:
    if not items:
        return "Nothing needs you."
    return f"{len(items)} decision(s) need you: " + " ".join(
        f"{i + 1}. {item['what']}." for i, item in enumerate(items[:10])
    )


def send_exceptions(conn: Conn, store: Any, tenant_id: str, config: Any = None) -> str:
    """Send the exception report when a decision needs a person, and only then.

    A decision goes out once: the same action or source is not sent again for
    `EXCEPTION_REPEAT_DAYS`. A report no channel carried told nobody, so once
    Slack or a webhook is set up its items go out again; until then they are
    kept once, not saved again on every run. Every item is a query, so the
    report is complete with no model; with one, the Manager adds a reading (D47).
    """
    from shoc.agents.manager import reachable, say_in_slack
    from shoc.cases.engine import publish

    ways = reachable(conn, tenant_id, config)
    channel = ways["slack"] or ways["webhook"]
    told = {
        str(r["reference"])
        for r in fetch_all(
            conn,
            """SELECT item->>'reference' AS reference
               FROM shoc.reports, jsonb_array_elements(body->'items') AS item
               WHERE tenant_id = %s AND kind = 'exception'
                 AND created_at > now() - %s * interval '1 day'
                 AND (NOT %s OR coalesce((body->>'delivered')::boolean, true))""",
            (tenant_id, EXCEPTION_REPEAT_DAYS, channel),
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
    report.body["delivered"] = channel
    save(conn, tenant_id, report)
    publish(
        conn,
        tenant_id,
        "report.ready",
        report.report_uid,
        {"kind": "exception", "summary": report.summary[:1000], "items": len(fresh)},
    )
    refused = say_in_slack(
        conn, tenant_id, config, text="\n".join([report.summary, *([reading] if reading else [])])
    )
    return (
        f"exception report {report.report_uid}: {len(fresh)} decision(s)"
        + (f"; Slack: {refused}" if refused else "")
        + _undelivered(conn, tenant_id, config)
    )


def _undelivered(conn: Conn, tenant_id: str, config: Any = None) -> str:
    """What a report's summary adds when no Slack channel or webhook carries it.

    A report goes to Slack and onto the stream; a pager and mail do not carry
    one, so `say_in_slack` taking nothing used to read as a report sent.
    """
    from shoc.agents.manager import reachable

    ways = reachable(conn, tenant_id, config)
    return "" if ways["slack"] or ways["webhook"] else "; not delivered: no channel"


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


def _intel(conn: Conn, tenant_id: str, start: datetime, end: datetime) -> dict[str, Any]:
    """What CTI read in the period and what its indicators found (AGT-14, DET-7).

    A feed that stopped is an ops alert, and reports dropped for budget are
    `intel.budget_short`, so both reach the report through its alerts.
    """
    read = fetch_all(
        conn,
        """SELECT report_uid, title, left(relevance, 300) AS relevance, techniques,
                  count(*) OVER () AS total
           FROM shoc.intel_reports
           WHERE tenant_id = %s AND digested_at BETWEEN %s AND %s
           ORDER BY digested_at DESC LIMIT 20""",
        (tenant_id, start, end),
    )
    found = (
        fetch_one(
            conn,
            """SELECT count(*) FILTER (WHERE rule_id LIKE 'ioc_match:%%') AS ioc_match,
                      count(*) FILTER (WHERE rule_id LIKE 'ioc_retrohunt:%%') AS ioc_retrohunt
               FROM shoc.findings
               WHERE tenant_id = %s AND last_seen BETWEEN %s AND %s
                 AND status NOT IN ('suppressed', 'self')""",
            (tenant_id, start, end),
        )
        or {}
    )
    return {
        "reports_read": int(read[0]["total"]) if read else 0,
        "reports": [{k: v for k, v in r.items() if k != "total"} for r in read],
        "ioc_match": int(found.get("ioc_match") or 0),
        "ioc_retrohunt": int(found.get("ioc_retrohunt") or 0),
    }


def _posture(conn: Conn, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """The numbers a founder actually asks about."""
    from shoc.detect.intel import MATCHED

    graph = (
        fetch_one(
            conn,
            "SELECT count(*) AS nodes FROM shoc.graph_nodes WHERE tenant_id = %s",
            (tenant_id,),
        )
        or {}
    )
    iocs = (
        fetch_one(
            conn,
            # What `intel.indicators_for` would match: not expired, unverified
            # or held as prevalent.
            """SELECT count(*) AS n FROM shoc.iocs
               WHERE tenant_id = %s AND type = ANY(%s)
                 AND (expires_at IS NULL OR expires_at > now())
                 AND NOT unverified AND NOT ('prevalent' = ANY(tags))""",
            (tenant_id, list(MATCHED)),
        )
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
    one. Returns the report and why Slack refused it, "not delivered: no
    channel" when neither Slack nor a webhook carries it, or "".
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
        {
            "kind": kind,
            "summary": report.summary[:1000],
            "held": sum(int(n.get("count") or 1) for n in held),
        },
    )
    lines = [
        report.summary,
        *([reading] if reading else []),
        *(
            f"• {n.get('body') or ''}"
            + (f" ({n['count']} times)" if int(n.get("count") or 1) > 1 else "")
            for n in held[:15]
        ),
    ]
    refused = say_in_slack(conn, tenant_id, config, text="\n".join(lines))
    return report, refused or _undelivered(conn, tenant_id, config).removeprefix("; ")
