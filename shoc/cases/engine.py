"""The case engine (RSP-1).

A case is what a human is asked about: one entity, one story, the findings that
tell it. States follow NIST 800-61 — triage, analysis, containment,
eradication, recovery, post-incident, closed — and only the transitions in
`ALLOWED` are possible, so a case can never jump from triage to recovery because
a model said so.

Findings are grouped into cases by entity: the same stolen access key producing
five findings is one case, not five pages.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.errors import NotFound, ValidationError

STATES = (
    "triage",
    "analysis",
    "containment",
    "eradication",
    "recovery",
    "post_incident",
    "closed",
)

# A case may move forward, jump straight to closed, or be reopened into triage.
ALLOWED: dict[str, tuple[str, ...]] = {
    "triage": ("analysis", "containment", "closed"),
    "analysis": ("containment", "closed"),
    "containment": ("eradication", "closed"),
    "eradication": ("recovery", "closed"),
    "recovery": ("post_incident", "closed"),
    "post_incident": ("closed",),
    "closed": ("triage",),
}

# The four dispositions a mature SOC uses (docs/agent-specs.md §2). The
# distinction that matters is between the last two: `benign_expected` means the
# activity was real and is normal here, and is repaired with a scoped
# suppression; `false_positive` means the rule fired on something it should
# never fire on, and is repaired in the detection. Different repairs, different
# owners, so they cannot share a name.
DISPOSITIONS = ("malicious", "suspicious", "benign_expected", "false_positive")

# `needs_human` is an escalation rather than a disposition: it says we could not
# decide, not what happened. `unknown` is a case nobody has looked at yet.
VERDICTS = ("unknown", *DISPOSITIONS, "needs_human")

# Cases closed before the split carry the merged verdict. They read as the
# safer half — the environment was unusual, not the detection wrong — because
# reading them the other way would propose rule changes nobody asked for.
LEGACY_VERDICTS = {"benign": "benign_expected"}

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def normalise_verdict(verdict: str) -> str:
    """Accept the pre-split vocabulary from an old row, an eval or an old client."""
    return LEGACY_VERDICTS.get(verdict, verdict)


@dataclass
class Case:
    case_uid: str
    tenant_id: str
    title: str
    severity: str = "medium"
    state: str = "triage"
    verdict: str = "unknown"
    confidence: float = 0.0
    entity_key: str = ""
    summary: str = ""
    finding_uids: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    rounds: int = 0
    tokens_used: int = 0


def make_uid(tenant_id: str, entity_key: str, day: str) -> str:
    blob = f"{tenant_id}|{entity_key}|{day}"
    return "CASE-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def max_severity(values: list[str]) -> str:
    known = [v for v in values if v in SEVERITY_ORDER]
    return max(known, key=SEVERITY_ORDER.index) if known else "medium"


# Entity kinds that name where something happened rather than who did it. A
# cloud account or a tailnet is shared by every finding in it, so linking on it
# put a colleague's server setup into the operator's case (and would put every
# finding of a one-account company into one case). A role is shared by every
# session that assumed it, and a hash by every laptop that ran the file.
NOT_LINKING = ("account:", "role:", "process_hash:", "file_hash:")


def _entities_of(finding: dict[str, Any]) -> set[str]:
    """The typed entity keys a finding touches, with its own key as a fallback."""
    entities = {e for e in (finding.get("entities") or []) if e}
    if not entities and finding.get("entity_key"):
        entities = {f"entity:{finding['entity_key']}"}
    return entities


def _links(entities: set[str]) -> set[str]:
    """The entities two findings may be grouped on."""
    return {e for e in entities if not e.startswith(NOT_LINKING)}


def _cluster(findings: list[dict[str, Any]]) -> list[tuple[set[str], list[dict[str, Any]]]]:
    """Group findings that share any entity — a stolen key and the user behind it.

    Plain union-find over entity keys: five findings that each mention the same
    access key, or the same key and the user it belongs to, become one cluster
    and therefore one case.
    """
    clusters: list[tuple[set[str], list[dict[str, Any]]]] = []
    for finding in findings:
        entities = _entities_of(finding)
        links = _links(entities)
        touching = [c for c in clusters if _links(c[0]) & links] if links else []
        if not touching:
            clusters.append((set(entities), [finding]))
            continue
        merged_entities: set[str] = set(entities)
        merged_findings: list[dict[str, Any]] = [finding]
        for cluster in touching:
            merged_entities |= cluster[0]
            merged_findings = cluster[1] + merged_findings
            clusters.remove(cluster)
        clusters.append((merged_entities, merged_findings))
    return clusters


def _existing_case(conn: Conn, tenant_id: str, entities: set[str]) -> str | None:
    """An open case that already covers any of these entities."""
    entities = _links(entities)
    if not entities:
        return None
    row = fetch_one(
        conn,
        """SELECT c.case_uid
           FROM shoc.case_entities e
           JOIN shoc.cases c ON c.case_uid = e.case_uid
           WHERE e.tenant_id = %s AND e.entity = ANY(%s) AND c.state <> 'closed'
           ORDER BY c.opened_at DESC LIMIT 1""",
        (tenant_id, sorted(entities)),
    )
    return row["case_uid"] if row else None


def intake(
    conn: Conn, store: Any, tenant_id: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The findings that still need a case, after two checks a query can answer.

    Stage 0 (RFC 0021): a finding whose every event is shoc's own credential at
    work is marked `self`. Then a live suppression for exactly this rule and
    entity marks it `suppressed`. Either way the finding stays, with what showed
    it, and is checked again when new events refresh it (which replaces its
    evidence and so its `intake` mark).
    """
    from shoc.cases import own, routing

    out: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("case_uid"):
            continue
        uid = str(finding["finding_uid"])
        verdict = own.classify(conn, store, tenant_id, finding) if store is not None else None
        if verdict is not None and verdict.own:
            own.mark(conn, tenant_id, uid, verdict)
            _intake(conn, tenant_id, uid, "self", verdict.why)
            continue
        rule_id, entity = str(finding.get("rule_id") or ""), str(finding.get("entity_key") or "")
        if rule_id and (sup := routing.suppressed(conn, tenant_id, rule_id, entity)):
            _intake(conn, tenant_id, uid, "suppressed", sup)
            continue
        if finding.get("status") in ("self", "suppressed"):
            execute(
                conn,
                "UPDATE shoc.findings SET status = 'new' WHERE tenant_id = %s AND finding_uid = %s",
                (tenant_id, uid),
            )
        out.append(finding)
    return out


def _intake(conn: Conn, tenant_id: str, finding_uid: str, status: str, because: str) -> None:
    execute(
        conn,
        """UPDATE shoc.findings SET status = %s,
               evidence = coalesce(evidence, '{}'::jsonb) || jsonb_build_object(
                   'intake', jsonb_build_object('status', %s::text, 'because', %s::text, 'at', now()))
           WHERE tenant_id = %s AND finding_uid = %s""",
        (status, status, because[:500], tenant_id, finding_uid),
    )


def open_for_findings(
    conn: Conn, tenant_id: str, findings: list[dict[str, Any]], store: Any = None
) -> list[str]:
    """Group findings into cases by the entities they share.

    Returns the case UIDs touched. Findings already attached to a case are
    skipped, so this is safe to run on every detection cycle. Given the store,
    shoc's own activity and suppressed findings are set aside first (`intake`).
    """
    pending = intake(conn, store, tenant_id, findings)
    touched: list[str] = []

    for entities, group in _cluster(pending):
        day = max(f["last_seen"] for f in group).strftime("%Y-%m-%d")
        label = _label(entities, group)
        existing = _existing_case(conn, tenant_id, entities)
        uid = existing or make_uid(tenant_id, label, day)
        related = ""
        if not existing:
            uid, related = _not_closed(conn, tenant_id, uid, label, day)
        severity = max_severity([f["severity"] for f in group])
        attack = sorted({t for f in group for t in (f.get("attack") or [])})
        uids = [f["finding_uid"] for f in group]
        title = group[0]["title"] if len(group) == 1 else f"{len(group)} findings for {label}"
        execute(
            conn,
            """INSERT INTO shoc.cases
                   (case_uid, tenant_id, title, severity, entity_key, finding_uids, attack,
                    related_case_uid, token_cap)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (case_uid) DO UPDATE SET
                   severity = CASE
                       WHEN array_position(%s::text[], EXCLUDED.severity)
                            > array_position(%s::text[], shoc.cases.severity)
                       THEN EXCLUDED.severity ELSE shoc.cases.severity END,
                   finding_uids = (
                       SELECT array_agg(DISTINCT u)
                       FROM unnest(shoc.cases.finding_uids || EXCLUDED.finding_uids) AS u),
                   attack = (
                       SELECT coalesce(array_agg(DISTINCT a), '{}')
                       FROM unnest(shoc.cases.attack || EXCLUDED.attack) AS a),
                   title = CASE WHEN cardinality(shoc.cases.finding_uids) > 1
                                THEN shoc.cases.title ELSE EXCLUDED.title END,
                   token_cap = CASE WHEN EXCLUDED.token_cap IS NULL THEN NULL
                                    ELSE shoc.cases.token_cap END,
                   updated_at = now()""",
            (
                uid,
                tenant_id,
                title,
                severity,
                label,
                uids,
                attack,
                related or None,
                _token_cap(group),
                list(SEVERITY_ORDER),
                list(SEVERITY_ORDER),
            ),
        )
        for entity in sorted(entities):
            execute(
                conn,
                """INSERT INTO shoc.case_entities (tenant_id, case_uid, entity)
                   VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
                (tenant_id, uid, entity),
            )
        execute(
            conn,
            "UPDATE shoc.findings SET case_uid = %s WHERE tenant_id = %s AND finding_uid = ANY(%s)",
            (uid, tenant_id, uids),
        )
        settle(conn, tenant_id, uid)
        publish(
            conn,
            tenant_id,
            "case.updated" if existing else "case.opened",
            uid,
            {"entity": label, "severity": severity, "findings": len(uids)},
        )
        touched.append(uid)
    return touched


def _token_cap(group: list[dict[str, Any]]) -> int | None:
    """A case only hunts opened is low and gets a lifetime token ceiling (RFC 0022),
    and so does one opened only by indicators below the lead line: a report's or
    an agent's value is a lead, not a warrant (DET-4)."""
    from shoc.agents.hunter import HUNT_CASE_TOKENS
    from shoc.detect.intel import LEAD_BELOW

    rules = [str(f.get("rule_id") or "") for f in group]
    if rules and all(r.startswith("hunt:") for r in rules):
        return HUNT_CASE_TOKENS
    leads = all(
        r.startswith("ioc_") and float(f.get("confidence") or 0) < LEAD_BELOW
        for r, f in zip(rules, group, strict=True)
    )
    return HUNT_CASE_TOKENS if rules and leads else None


def _not_closed(conn: Conn, tenant_id: str, uid: str, label: str, day: str) -> tuple[str, str]:
    """A case id that is not closed, and the closed case it follows when it had to move.

    A case id is derived from its entity and day, so a finding that arrives after
    a person closed that day's case derived the same id and was merged into it,
    reopening nothing and reaching nobody. A closed case stays closed (Defender
    does the same); the new finding opens a case of its own that names it.
    """
    closed = ""
    for n in range(50):
        candidate = uid if n == 0 else make_uid(tenant_id, label, f"{day}#{n}")
        row = fetch_one(
            conn,
            "SELECT state FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, candidate),
        )
        if row is None or row["state"] != "closed":
            return candidate, closed
        closed = candidate
    return make_uid(tenant_id, label, f"{day}#{datetime.now(UTC).isoformat()}"), closed


def move(conn: Conn, tenant_id: str, finding_uids: list[str], into: str = "") -> str:
    """Move findings into an open case, or into a new case of their own (D43).

    Sentinel's attach and split. A closed case takes nothing (D78). Returns the
    case the findings are in now, or "" when there was nothing to move.
    """
    rows = fetch_all(
        conn,
        """SELECT finding_uid, title, severity, entity_key, entities, attack, last_seen, case_uid
           FROM shoc.findings WHERE tenant_id = %s AND finding_uid = ANY(%s)""",
        (tenant_id, finding_uids),
    )
    if not rows:
        return ""
    if into:
        if require(conn, tenant_id, into)["state"] == "closed":
            raise ValidationError(f"{into} is closed; a closed case stays closed")
    else:
        label = _label({e for r in rows for e in _entities_of(r)}, rows)
        day = max(r["last_seen"] for r in rows).strftime("%Y-%m-%d")
        into = make_uid(tenant_id, label, f"{day}#{rows[0]['finding_uid']}")
        title = rows[0]["title"] if len(rows) == 1 else f"{len(rows)} findings for {label}"
        execute(
            conn,
            """INSERT INTO shoc.cases (case_uid, tenant_id, title, severity, entity_key)
               VALUES (%s,%s,%s,%s,%s) ON CONFLICT (case_uid) DO NOTHING""",
            (into, tenant_id, title, max_severity([r["severity"] for r in rows]), label),
        )
        publish(conn, tenant_id, "case.opened", into, {"entity": label, "findings": len(rows)})
    execute(
        conn,
        "UPDATE shoc.findings SET case_uid = %s WHERE tenant_id = %s AND finding_uid = ANY(%s)",
        (into, tenant_id, [r["finding_uid"] for r in rows]),
    )
    settle(conn, tenant_id, into)
    for case_uid in {into, *(str(r["case_uid"]) for r in rows if r["case_uid"])}:
        refresh(conn, tenant_id, case_uid)
    return into


def defer(conn: Conn, tenant_id: str, finding_uid: str, because: str) -> None:
    """Take a finding out of its case and keep it, marked deferred (D43, D44).

    Like a `self` or `suppressed` mark, the deferral is read again when new
    events refresh the finding.
    """
    row = fetch_one(
        conn,
        "SELECT case_uid FROM shoc.findings WHERE tenant_id = %s AND finding_uid = %s",
        (tenant_id, finding_uid),
    )
    execute(
        conn,
        "UPDATE shoc.findings SET case_uid = NULL WHERE tenant_id = %s AND finding_uid = %s",
        (tenant_id, finding_uid),
    )
    _intake(conn, tenant_id, finding_uid, "deferred", because)
    if row and row["case_uid"]:
        refresh(conn, tenant_id, str(row["case_uid"]))


def refresh(conn: Conn, tenant_id: str, case_uid: str) -> None:
    """Make a case's findings, techniques and entities what its findings say.

    Severity only rises: one the Investigator lowered stays lowered.
    """
    rows = fetch_all(
        conn,
        """SELECT finding_uid, severity, attack, entities, entity_key FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s""",
        (tenant_id, case_uid),
    )
    worst = max_severity([r["severity"] for r in rows]) if rows else "informational"
    execute(
        conn,
        """UPDATE shoc.cases SET finding_uids = %s, attack = %s, updated_at = now(),
               severity = CASE
                   WHEN array_position(%s::text[], %s) > array_position(%s::text[], severity)
                   THEN %s ELSE severity END
           WHERE tenant_id = %s AND case_uid = %s""",
        (
            [r["finding_uid"] for r in rows],
            sorted({t for r in rows for t in (r["attack"] or [])}),
            list(SEVERITY_ORDER),
            worst,
            list(SEVERITY_ORDER),
            worst,
            tenant_id,
            case_uid,
        ),
    )
    execute(
        conn,
        "DELETE FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
        (tenant_id, case_uid),
    )
    for entity in sorted({e for r in rows for e in _entities_of(r)}):
        execute(
            conn,
            """INSERT INTO shoc.case_entities (tenant_id, case_uid, entity)
               VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
            (tenant_id, case_uid, entity),
        )


# Which entity kind names a case, most specific first: a stolen key is a better
# title than the account it belongs to.
LABEL_ORDER = (
    "key",
    "user",
    "host",
    "device",
    "resource",
    "role",
    "ip",
    "file_hash",
    "process_hash",
    "account",
    "entity",
)


def _label(entities: set[str], group: list[dict[str, Any]]) -> str:
    for prefix in LABEL_ORDER:
        matches = sorted(e for e in entities if e.startswith(f"{prefix}:"))
        if matches:
            return matches[0].split(":", 1)[1]
    return group[0].get("entity_key") or "-"


def get(conn: Conn, tenant_id: str, case_uid: str) -> dict[str, Any] | None:
    return fetch_one(
        conn,
        "SELECT * FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
        (tenant_id, case_uid),
    )


def products(conn: Conn, tenant_id: str, config: Any = None) -> dict[str, str]:
    """The platform each finding source answers: a rule's `logsource.product`, and
    a hunt pack's under `hunt:<id>`, which is how the Hunter names its findings."""
    from shoc.detect import hunts, rules

    out = {
        f"hunt:{p.id}": str(p.logsource.get("product", "")).lower()
        for p in hunts.load(config, conn, tenant_id)
    }
    out.update(
        {
            r.id: str(r.logsource.get("product", "")).lower()
            for r in rules.load(config, conn, tenant_id)
        }
    )
    return out


def platforms(conn: Conn, tenant_id: str, case_uid: str, config: Any = None) -> set[str]:
    """Where a case was seen: the `logsource.product` of the rules and hunts behind
    its findings. A case a hunt opened is on its pack's platform, or no action
    could ever answer it."""
    ids = {
        r["rule_id"]
        for r in fetch_all(
            conn,
            "SELECT DISTINCT rule_id FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, case_uid),
        )
    }
    known = products(conn, tenant_id, config)
    return {known.get(i, "") for i in ids} - {""}


def require(conn: Conn, tenant_id: str, case_uid: str) -> dict[str, Any]:
    case = get(conn, tenant_id, case_uid)
    if case is None:
        raise NotFound(f"no case '{case_uid}'")
    return case


def settle(conn: Conn, tenant_id: str, case_uid: str) -> None:
    """Make a case's findings say where the case is (D136).

    `triage` while the case is open; once it closes, `false_positive` when the
    rule was wrong and `closed` for every other verdict.
    """
    execute(
        conn,
        """UPDATE shoc.findings f SET status = s.status, updated_at = now()
           FROM (SELECT CASE WHEN state <> 'closed' THEN 'triage'
                             WHEN verdict = 'false_positive' THEN 'false_positive'
                             ELSE 'closed' END AS status
                 FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s) s
           WHERE f.tenant_id = %s AND f.case_uid = %s AND f.status <> s.status""",
        (tenant_id, case_uid, tenant_id, case_uid),
    )


def transition(
    conn: Conn, tenant_id: str, case_uid: str, state: str, note: str = "", by: str = "system"
) -> dict[str, Any]:
    """Move a case to a new state, refusing transitions the process does not allow.

    `by` is who closed it: `human`, `crew` or `system`. A person's close is
    final for the crew (a queued run stops on it) and is not re-read by the
    weekly recheck until a later case follows it.
    """
    if state not in STATES:
        raise ValidationError(f"unknown case state '{state}'")
    case = require(conn, tenant_id, case_uid)
    current = case["state"]
    if state != current and state not in ALLOWED[current]:
        raise ValidationError(
            f"cannot move a case from '{current}' to '{state}' "
            f"(allowed: {', '.join(ALLOWED[current])})"
        )
    row = fetch_one(
        conn,
        """UPDATE shoc.cases
           SET state = %s, updated_at = now(),
               closed_at = CASE WHEN %s = 'closed' THEN now() ELSE NULL END,
               closed_by = CASE WHEN %s = 'closed' THEN %s ELSE NULL END
           WHERE tenant_id = %s AND case_uid = %s RETURNING *""",
        (state, state, state, by, tenant_id, case_uid),
    )
    settle(conn, tenant_id, case_uid)
    publish(
        conn,
        tenant_id,
        "case.state_changed",
        case_uid,
        {"from": current, "to": state, "note": note},
    )
    if current == "closed" and state != "closed":
        from shoc.cases import routing

        routing.undo_closure(conn, tenant_id, case_uid, f"reopened: {note}"[:240])
    return row or {}


def set_severity(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    severity: str,
    reason: str,
    by: str = "Investigator",
) -> dict[str, Any]:
    """Correct the severity a rule guessed at, now that somebody has looked.

    A rule sets severity from a pattern, before any of the case exists: the same
    "impossible travel" finding is a laptop on a train and a session stolen an
    hour ago, and it arrives as `medium` either way. The Investigator has read
    the evidence, so it may raise or lower this — which decides whether the
    on-call human is ever woken, and whether an automatic action clears the
    policy's floor.

    The change is therefore never quiet: it is written with a reason and
    published on the stream, so a severity that moved can be read back and
    argued with. Raising it is not a way to grant an action: the policy still
    wants confidence, citations, reversibility and, for a block, research and a
    peer review.
    """
    severity = (severity or "").strip().lower()
    if severity not in SEVERITY_ORDER:
        raise ValidationError(f"unknown severity '{severity}' (have: {', '.join(SEVERITY_ORDER)})")
    case = require(conn, tenant_id, case_uid)
    was = str(case["severity"])
    if was == severity:
        return case
    row = fetch_one(
        conn,
        """UPDATE shoc.cases SET severity = %s, updated_at = now()
           WHERE tenant_id = %s AND case_uid = %s RETURNING *""",
        (severity, tenant_id, case_uid),
    )
    publish(
        conn,
        tenant_id,
        "case.severity_changed",
        case_uid,
        {"from": was, "to": severity, "by": by, "reason": reason[:500]},
    )
    return row or {}


def set_verdict(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    verdict: str,
    confidence: float,
    summary: str,
    citations: list[str],
) -> dict[str, Any]:
    """Record a disposition. An uncited one becomes `needs_human` (principle 6)."""
    verdict = normalise_verdict(verdict)
    if verdict not in VERDICTS:
        raise ValidationError(f"unknown verdict '{verdict}'")
    # Every disposition is a claim about what happened, including the two that
    # say "nothing did" — a rule declared wrong without evidence is as unsafe as
    # an attack declared without it.
    if verdict in DISPOSITIONS and not citations:
        verdict, confidence = "needs_human", 0.0
        summary = (summary + " [downgraded: the verdict cited no events]").strip()
    was = str(require(conn, tenant_id, case_uid).get("verdict") or "")
    row = fetch_one(
        conn,
        """UPDATE shoc.cases SET verdict = %s, confidence = %s, summary = %s, updated_at = now()
           WHERE tenant_id = %s AND case_uid = %s RETURNING *""",
        (verdict, max(0.0, min(1.0, confidence)), summary, tenant_id, case_uid),
    )
    settle(conn, tenant_id, case_uid)
    if was in ("benign_expected", "false_positive") and verdict in ("malicious", "suspicious"):
        # What the benign closure taught the Detection Engineer is now wrong.
        from shoc.cases import routing

        routing.undo_closure(conn, tenant_id, case_uid, f"verdict moved from {was} to {verdict}")
    if verdict in ("benign_expected", "false_positive"):
        # A response to nothing is still a change to production. Whatever was
        # proposed while the case looked like an attack is answered now; a
        # playbook run stops at its next step (`playbooks.advance`).
        from shoc.cases import actions

        actions.reject_pending(conn, tenant_id, case_uid, "system", f"case is {verdict}")
    publish(
        conn,
        tenant_id,
        "case.verdict",
        case_uid,
        {"verdict": verdict, "confidence": confidence, "citations": citations[:20]},
    )
    if verdict == "malicious":
        # A high one that nothing contains in time pages (RFC 0015).
        from shoc.agents import manager

        manager.uncontained(conn, tenant_id, case_uid)
    return row or {}


def publish(conn: Conn, tenant_id: str, type_: str, subject: str, payload: dict[str, Any]) -> None:
    """Append to the event stream and wake any listener (API-2)."""
    execute(
        conn,
        "INSERT INTO shoc.stream_events (tenant_id, type, subject, payload) VALUES (%s,%s,%s,%s)",
        (tenant_id, type_, subject, json.dumps(payload, default=str)),
    )
    execute(conn, "SELECT pg_notify('shoc_stream', %s)", (f"{tenant_id}:{type_}",))


def recent(conn: Conn, tenant_id: str, limit: int = 50, state: str = "") -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.cases WHERE {' AND '.join(where)} ORDER BY updated_at DESC LIMIT %(limit)s",
        params,
    )
