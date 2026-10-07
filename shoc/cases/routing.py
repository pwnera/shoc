"""Where a closed case goes next (AGT-3, AGT-13, docs/agent-specs.md §6, D77).

A disposition that routes nowhere is a SOC that triages the same noise forever.
Closing a case is therefore not the end of it, but each disposition owes
something different, and benign is not "the rule is wrong":

    malicious / suspicious   the IR Commander and the case state machine
    benign_expected          a short suppression per (rule, entity), a note in
                             memory, and a backlog item only when the same rule
                             and entity come back
    false_positive           the Detection Engineer's backlog, as a defect, now
    needs_human              a person, with everything already gathered; nothing
                             is learnt from a case nobody could decide

Routing is deterministic and it never acts. A suppression lasts a week at most
and a repeat never extends it; an operator's own account is never suppressed.
A case that is reopened, or whose verdict turns malicious, takes back what its
closure produced (`undo_closure`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one

# A suppression a closure writes lasts this long at most. Sentinel's in-incident
# exception lasts a day; a week stops the repeat noise of one benign activity
# and is short enough that a stolen copy of it is noticed again.
SUPPRESSION_DAYS = 7
# How long what a closure taught the crew is remembered.
MEMORY_DAYS = 180
# A benign closure is the rule doing its job. The same rule and entity closed
# benign again within this window is a rule that needs narrowing.
RECURRENCE_DAYS = 30
REASON_CHARS = 240
EVIDENCE_REASON_CHARS = 500

# Pseudo-rules whose closures belong to another role: a hunt pack is the
# Hunter's to tune, an indicator match is CTI's.
NOT_DETECTION = ("hunt:", "ioc_match")


@dataclass
class Routed:
    """One thing a closure handed to somebody else."""

    routed_to: str
    reference: str = ""
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"routed_to": self.routed_to, "reference": self.reference, "note": self.note}


@dataclass
class Routing:
    disposition: str = ""
    entries: list[Routed] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "routed": [e.to_json() for e in self.entries],
        }


def _uid(prefix: str, *parts: str) -> str:
    return prefix + hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


def _pairs(conn: Conn, tenant_id: str, case_uid: str) -> list[dict[str, Any]]:
    """Each (rule, entity) the case's findings raised, with what they cited."""
    return fetch_all(
        conn,
        """SELECT rule_id, entity_key, array_agg(finding_uid ORDER BY finding_uid) AS findings
           FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s AND rule_id <> ''
           GROUP BY rule_id, entity_key ORDER BY rule_id, entity_key""",
        (tenant_id, case_uid),
    )


def _detection(rule_id: str) -> bool:
    return bool(rule_id) and not rule_id.startswith(NOT_DETECTION)


def route(
    conn: Conn,
    tenant_id: str,
    case: dict[str, Any],
    disposition: str,
    *,
    summary: str = "",
    by: str = "Investigator",
    closer: str = "crew",
) -> Routing:
    """Hand a closed case to whoever its disposition owes something to.

    `closer` comes from the caller's principal kind, never from what anybody
    wrote: a crew closure waits for the weekly recheck before it can change a
    rule, a person's does not.
    """
    from shoc.cases import engine

    disposition = engine.normalise_verdict(disposition)
    out = Routing(disposition=disposition)
    case_uid = str(case.get("case_uid") or "")
    if not case_uid or disposition in ("", "unknown"):
        return out
    pairs = _pairs(conn, tenant_id, case_uid)
    reason = " ".join(summary.split())[:EVIDENCE_REASON_CHARS]

    if disposition in ("malicious", "suspicious"):
        out.entries.append(
            Routed(
                "IR Commander",
                case_uid,
                "response proposed in the openspace, for a human to approve",
            )
        )
    elif disposition == "benign_expected":
        out.entries += _suppress(conn, tenant_id, case_uid, pairs, reason, by)
        out.entries += _remember(conn, tenant_id, case, reason)
        out.entries += _recurring(conn, tenant_id, case, pairs, reason, closer)
    elif disposition == "false_positive":
        out.entries += _backlog(
            conn,
            tenant_id,
            case,
            pairs,
            "defect",
            "closed as a false positive: the rule fired on something it should not fire on",
            reason,
            closer,
        )
    elif disposition == "needs_human":
        out.entries.append(
            Routed("human", case_uid, "escalated with the findings and their evidence attached")
        )

    for entry in out.entries:
        execute(
            conn,
            """INSERT INTO shoc.case_routing
                   (tenant_id, case_uid, disposition, routed_to, reference, note)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, case_uid, routed_to) DO UPDATE SET
                   disposition = EXCLUDED.disposition,
                   reference = EXCLUDED.reference,
                   note = EXCLUDED.note,
                   routed_at = now()""",
            (tenant_id, case_uid, disposition, entry.routed_to, entry.reference, entry.note),
        )
    return out


def _suppress(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    pairs: list[dict[str, Any]],
    reason: str,
    by: str,
) -> list[Routed]:
    """The activity is real and normal here: quieten this exact (rule, entity), briefly."""
    out: list[Routed] = []
    for pair in pairs:
        rule_id, entity = str(pair["rule_id"]), str(pair["entity_key"] or "")
        if not _detection(rule_id) or entity in ("", "-"):
            continue
        uid = suppress_draft(
            conn,
            tenant_id,
            case_uid,
            rule_id,
            entity,
            f"{case_uid} closed as expected activity",
            by=by,
        )
        if uid:
            out.append(Routed(f"suppression:{rule_id}", uid, f"{rule_id} quiet for {entity}"))
    return out


def suppress_draft(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    rule_id: str,
    entity: str,
    reason: str,
    ttl_days: int = SUPPRESSION_DAYS,
    by: str = "Challenger",
) -> str:
    """Record one suppression, scoped and expiring, or '' when it may not exist.

    The expiry only ever moves earlier: a repeat used to push it out again, so a
    benign activity closed every week was never seen again. An operator's own
    account is never suppressed, because that is the account an attacker who
    took it would most like to have quiet.
    """
    from shoc.cases import own

    if own.is_person(conn, tenant_id, entity):
        return ""
    days = ttl_days if 1 <= ttl_days <= SUPPRESSION_DAYS else SUPPRESSION_DAYS
    expires = datetime.now(UTC) + timedelta(days=days)
    uid = _uid("SUP-", tenant_id, rule_id, entity)
    execute(
        conn,
        """INSERT INTO shoc.suppressions
               (suppression_uid, tenant_id, rule_id, entity, reason, case_uid,
                created_by, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (suppression_uid) DO UPDATE SET
               reason = EXCLUDED.reason, case_uid = EXCLUDED.case_uid,
               expires_at = CASE WHEN shoc.suppressions.state = 'active'
                                 THEN LEAST(shoc.suppressions.expires_at, EXCLUDED.expires_at)
                                 ELSE EXCLUDED.expires_at END,
               state = 'active', reviewed_at = NULL""",
        (
            uid,
            tenant_id,
            rule_id,
            entity,
            " ".join((reason or f"{case_uid}: expected activity").split())[:REASON_CHARS],
            case_uid,
            by,
            expires,
        ),
    )
    return uid


def _remember(conn: Conn, tenant_id: str, case: dict[str, Any], reason: str) -> list[Routed]:
    """Write down why it was expected, scoped to the case, so the next one does not relearn it."""
    from shoc.agents import memory

    entity = str(case.get("entity_key") or "")
    if not entity or not reason:
        return []
    memory_id = memory.add(
        conn,
        tenant_id,
        f"{entity}: {reason} (case {case['case_uid']}, closed as expected activity)",
        subject=entity,
        kind="episodic",
        source="crew",
        expires_at=datetime.now(UTC) + timedelta(days=MEMORY_DAYS),
        confidence=0.6,
    )
    return [Routed("memory", memory_id, f"what makes {entity}'s activity ordinary here")]


def _recurring(
    conn: Conn,
    tenant_id: str,
    case: dict[str, Any],
    pairs: list[dict[str, Any]],
    reason: str,
    closer: str,
) -> list[Routed]:
    """A second benign closure of the same rule and entity is a rule to narrow."""
    again = [
        p
        for p in pairs
        if _detection(str(p["rule_id"]))
        and fetch_one(
            conn,
            """SELECT 1 FROM shoc.findings f JOIN shoc.cases c
                 ON c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid
               WHERE f.tenant_id = %s AND f.rule_id = %s AND f.entity_key = %s
                 AND c.case_uid <> %s AND c.state = 'closed'
                 AND c.verdict = 'benign_expected'
                 AND c.closed_at > now() - %s * interval '1 day'
               LIMIT 1""",
            (tenant_id, p["rule_id"], p["entity_key"], case["case_uid"], RECURRENCE_DAYS),
        )
    ]
    return _backlog(
        conn,
        tenant_id,
        case,
        again,
        "defect",
        f"closed as expected activity a second time in {RECURRENCE_DAYS} days for the same "
        "entity: the rule may need narrowing on a value the attacker cannot set",
        reason,
        closer,
    )


def _backlog(
    conn: Conn,
    tenant_id: str,
    case: dict[str, Any],
    pairs: list[dict[str, Any]],
    kind: str,
    why: str,
    reason: str,
    closer: str,
) -> list[Routed]:
    """One item per (rule, case) for the Detection Engineer, with what it needs."""
    from shoc.agents import detection_engineer as engineer

    case_uid = str(case["case_uid"])
    by_rule: dict[str, list[str]] = {}
    for pair in pairs:
        if _detection(str(pair["rule_id"])):
            by_rule.setdefault(str(pair["rule_id"]), []).extend(pair["findings"] or [])
    out: list[Routed] = []
    for rule_id, findings in by_rule.items():
        uid = engineer.add(
            conn,
            tenant_id,
            engineer.BacklogItem(
                item_uid=engineer.item_uid(tenant_id, rule_id, kind, case_uid),
                kind=kind,
                intake="case",
                rule_id=rule_id,
                title=f"{rule_id}: {kind}",
                reason=why,
                priority=engineer.PRIORITY.get(kind, 3),
                observability="have",
                evidence={
                    "case_uid": case_uid,
                    "entity": str(case.get("entity_key") or ""),
                    "finding_uids": sorted(set(findings))[:50],
                    "tokens": int(case.get("tokens_used") or 0),
                    "closer": closer,
                    "reason": reason,
                },
                case_uid=case_uid,
            ),
        )
        out.append(Routed(f"Detection Engineer:{rule_id}", uid, why))
    return out


def recurring_suppressed(conn: Conn, tenant_id: str) -> int:
    """The nightly half of recurrence: a suppression hit on two more days.

    A suppressed finding still lands, marked `suppressed`. The same rule and
    entity suppressed on two distinct days after the suppression was written is
    a benign activity that keeps coming back, and an item for the Detection
    Engineer.
    """
    rows = fetch_all(
        conn,
        """SELECT s.rule_id, s.entity, s.case_uid
           FROM shoc.suppressions s
           JOIN shoc.findings f ON f.tenant_id = s.tenant_id AND f.rule_id = s.rule_id
                AND f.entity_key = s.entity AND f.status = 'suppressed'
                AND f.created_at > s.created_at
           WHERE s.tenant_id = %s AND s.state = 'active' AND s.case_uid <> ''
           GROUP BY s.rule_id, s.entity, s.case_uid
           HAVING count(DISTINCT f.created_at::date) >= 2""",
        (tenant_id,),
    )
    opened = 0
    for row in rows:
        case = fetch_one(
            conn,
            "SELECT * FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, row["case_uid"]),
        )
        if not case:
            continue
        pairs = [
            p
            for p in _pairs(conn, tenant_id, str(row["case_uid"]))
            if p["rule_id"] == row["rule_id"] and p["entity_key"] == row["entity"]
        ]
        opened += len(
            _backlog(
                conn,
                tenant_id,
                case,
                pairs,
                "defect",
                "suppressed on two more days after its benign closure: the activity is "
                "routine and the rule fires on it every time",
                str(case.get("disposition_reason") or case.get("summary") or "")[
                    :EVIDENCE_REASON_CHARS
                ],
                str(case.get("closed_by") or "crew"),
            )
        )
    return opened


def undo_closure(conn: Conn, tenant_id: str, case_uid: str, why: str) -> dict[str, int]:
    """A closure that turned out wrong takes back what it produced (RFC 0020, D77).

    Every merge whose backlog item came from this case is reverted, every
    suppression it wrote is revoked, and its backlog items reopen.
    """
    from shoc.agents import detection_engineer as engineer

    reverted = 0
    for row in fetch_all(
        conn,
        """SELECT m.rule_id FROM shoc.merged_rules m
           JOIN shoc.detection_backlog b ON b.tenant_id = m.tenant_id AND b.item_uid = m.item_uid
           WHERE m.tenant_id = %s AND m.state = 'merged' AND b.case_uid = %s""",
        (tenant_id, case_uid),
    ):
        try:
            engineer.revert(conn, tenant_id, str(row["rule_id"]), why, who="shoc")
            reverted += 1
        except Exception:  # one bad revert must not keep the rest
            continue
    revoked = fetch_all(
        conn,
        """UPDATE shoc.suppressions SET state = 'revoked', reviewed_at = now()
           WHERE tenant_id = %s AND case_uid = %s AND state = 'active'
           RETURNING suppression_uid""",
        (tenant_id, case_uid),
    )
    # Reopened rather than withdrawn: the gate refuses to merge for a case that
    # is not closed false_positive or benign, so an item whose case turned out
    # malicious waits, and comes back to life if a person closes it benign again.
    reopened = fetch_all(
        conn,
        """UPDATE shoc.detection_backlog
              SET state = 'open', decided_at = NULL, decided_by = NULL,
                  evidence = evidence || %s
            WHERE tenant_id = %s AND case_uid = %s AND state <> 'open'
           RETURNING item_uid""",
        (json.dumps({"reopened": why[:EVIDENCE_REASON_CHARS]}), tenant_id, case_uid),
    )
    return {"reverted": reverted, "revoked": len(revoked), "reopened": len(reopened)}


def active_suppressions(
    conn: Conn, tenant_id: str, rule_id: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    """Live suppressions, newest first. An expired one is history, not a filter."""
    where = ["tenant_id = %(tenant_id)s", "state = 'active'", "expires_at > now()"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if rule_id:
        where.append("rule_id = %(rule_id)s")
        params["rule_id"] = rule_id
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.suppressions WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC LIMIT %(limit)s",
        params,
    )


def suppressed(conn: Conn, tenant_id: str, rule_id: str, entity: str) -> str:
    """The live suppression for exactly this rule and entity, or ''."""
    row = fetch_one(
        conn,
        """SELECT suppression_uid FROM shoc.suppressions
           WHERE tenant_id = %s AND rule_id = %s AND entity = %s
             AND state = 'active' AND expires_at > now()""",
        (tenant_id, rule_id, entity),
    )
    return str(row["suppression_uid"]) if row else ""


def expire_suppressions(conn: Conn, tenant_id: str) -> int:
    """Mark what has run out. Coverage comes back on its own, never quietly stays off."""
    rows = fetch_all(
        conn,
        """UPDATE shoc.suppressions SET state = 'expired'
           WHERE tenant_id = %s AND state = 'active' AND expires_at <= now()
           RETURNING suppression_uid""",
        (tenant_id,),
    )
    return len(rows)
