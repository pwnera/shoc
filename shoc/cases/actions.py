"""The life of a response action (RSP-2, RSP-3, RSP-4).

    proposed ──approve──▶ approved ──run──▶ running ──▶ done ──undo──▶ rolled_back
        │                                       └──▶ failed
        └──reject──▶ rejected

An L1 action is born approved, because the policy already said yes. An L2 action
waits for a human; no agent can move it. Every execution is idempotent by key
and, in dry run, which is the default, changes nothing anywhere. Every change of
state is written to the audit chain in the same transaction, under the principal
that made it, whether that is a capability caller, the worker, the playbook
runner, the Manager or the unattended path (SEC-1).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.actions import get as get_action
from shoc.actions.base import ActionResult, dry_run_result, follows_link, out_of_scope
from shoc.cases import credentials, engine, unattended
from shoc.cases.policy import Decision, Policy
from shoc.db import audit
from shoc.db.pool import Conn, fetch_all, fetch_one
from shoc.errors import ConfigError, Denied, NotFound, ValidationError

TERMINAL = ("done", "failed", "rejected", "rolled_back")

# An action `running` this long was left by a worker that died during the call.
STUCK_AFTER_MINUTES = 15

# How many `action.run` jobs may be parked as failed before the worker stops
# queueing the action again (RSP-7).
RUN_JOBS = 3

PRINCIPAL_KINDS = ("human", "agent", "external_agent", "service")


def _settle(
    conn: Conn,
    tenant_id: str,
    by: str,
    event: str,
    sql: str,
    params: tuple[Any, ...],
    error: str | None = None,
    kind: str = "service",
) -> dict[str, Any]:
    """Change an action's row and write the change to the audit chain, in one transaction (SEC-1).

    `sql` returns the row. `by` is `kind:id` from a capability, or a bare name
    ("unattended", "manager", "playbook-runner") from the worker's own code,
    which runs as `kind`. The output hash commits to the row as it now stands.
    """
    who, sep, ident = by.partition(":")
    if not sep or who not in PRINCIPAL_KINDS:
        who, ident = kind, by
    with conn.transaction():
        row = fetch_one(conn, sql, params) or {}
        if not row:  # a guarded UPDATE that matched nothing changed nothing
            return row
        audit.append(
            conn,
            tenant_id,
            who,
            ident,
            event,
            audit.hash_payload(
                {
                    "action_uid": row.get("action_uid"),
                    "type": row.get("type"),
                    "target": row.get("target"),
                }
            ),
            audit.hash_payload(row),
            error,
        )
    return row


@dataclass
class Proposal:
    action_type: str
    params: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    case_uid: str | None = None
    run_uid: str | None = None
    # The policy's severity when there is no case, as for the Manager's page
    # that a source or the whole schedule has gone dark. A case's own wins.
    severity: str = ""
    # False when the crew named a target that appears nowhere in the case's
    # evidence (RFC 0020). The policy never lets such an action run on its own.
    grounded: bool = True
    # The Commander's L2 terms (D45, RSP-7): the action that runs instead when
    # nobody answers within `window_minutes`, or "expire" to stop waiting.
    fallback: str = ""
    window_minutes: int = 0
    # Who else the action touches, as the Commander counted it. None when
    # nobody was asked (a playbook step, a person); {} when it went unanswered.
    blast_radius: dict[str, Any] | None = None
    # One of the provider's credentials, `aws:staging`, when a person names it.
    # It narrows where shoc may act; it never adds a place (RFC 0025).
    credential: str = ""


def make_uid(tenant_id: str, action_type: str, target: str, case_uid: str | None) -> str:
    blob = f"{tenant_id}|{action_type}|{target}|{case_uid or ''}"
    return "ACT-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def decide(
    conn: Conn,
    tenant_id: str,
    proposal: Proposal,
    principal_kind: str,
    config: Any = None,
    policy: Policy | None = None,
    store: Any = None,
    linked: tuple[bool, str] = (False, ""),
) -> tuple[Decision, dict[str, Any]]:
    """Ask the policy about a proposal, in the context of its case.

    Two gates run before the policy is asked, for a blocking action or one whose
    rule asks for them: the target is researched (RSP-5) and the crew reviews
    the action (RSP-6). Both are best-effort — a gate that cannot run reports
    that it could not run, and the policy escalates to a human rather than
    proceeding. Neither can make an action easier to take.
    """
    from shoc.config import Config

    cfg = config or Config.load()
    policy = policy or Policy.load(cfg)
    action = get_action(proposal.action_type)
    case: dict[str, Any] = {}
    confidence, severity, cited = 0.0, proposal.severity or "medium", True
    if proposal.case_uid:
        case = engine.require(conn, tenant_id, proposal.case_uid)
        confidence = float(case["confidence"])
        severity = case["severity"]
        cited = _case_has_citations(conn, tenant_id, proposal.case_uid)
        # An action is only a response to an incident on the platform it acts on,
        # or to the login the case's user signs in as there (RFC 0027).
        why = out_of_scope(action, engine.platforms(conn, tenant_id, proposal.case_uid, cfg))
        if why and not linked[0]:
            return Decision(allowed=False, reason=linked[1] or why), case
    already = _auto_actions(conn, tenant_id, proposal.case_uid)
    target = (
        str(proposal.params.get(action.required_params[0], "")) if action.required_params else ""
    )
    researched, reviewed = policy.gated(proposal.action_type, action.target_kind)
    research = review = None
    egress: tuple[str, ...] = ()
    if researched or reviewed:
        from shoc.cases import own

        # The addresses shoc has recorded as the company's own count as known
        # egress, so the guard does not depend on a list nobody fills in (RSP-5).
        egress = tuple(own.values(conn, tenant_id, "address"))
        research, review = _gates(
            conn, store, tenant_id, cfg, researched, reviewed, proposal, action, target, case
        )
    decision = policy.decide(
        proposal.action_type,
        principal_kind=principal_kind,
        target_kind=action.target_kind,
        target=target,
        confidence=confidence,
        severity=severity,
        has_citations=cited,
        grounded=proposal.grounded,
        auto_actions_so_far=already,
        dry_run_default=cfg.dry_run or None,
        research=research,
        review=review,
        blast_radius=proposal.blast_radius,
        egress=egress,
    )
    if linked[0]:
        decision.reason = f"{linked[1]}. {decision.reason}".strip()
    if decision.allowed and not decision.needs_approval and principal_kind != "human":
        # shoc's own credentials and addresses, and the operator's accounts, are
        # never acted on without a person: they are not blocked, so a stolen shoc
        # key can still be revoked, but a person says so (RFC 0021).
        from shoc.cases import own

        if own.bare(target).lower() in own.protected(conn, tenant_id):
            decision.autonomy, decision.needs_approval = "L2", True
            decision.reason = (
                f"{target} is shoc's own or the operator's; a person approves. " + decision.reason
            ).strip()
    return decision, case


def _gates(
    conn: Conn,
    store: Any,
    tenant_id: str,
    cfg: Any,
    researched: bool,
    reviewed: bool,
    proposal: Proposal,
    action: Any,
    target: str,
    case: dict[str, Any],
) -> tuple[Any, Any]:
    """Research the target, then have the crew review the action (RSP-5, RSP-6)."""
    from shoc.cases import review as peer_review
    from shoc.detect import osint

    if store is None:
        from shoc.store import open_store

        store = open_store(cfg, tenant_id)

    research = None
    if researched:
        research = osint.research_target(conn, store, tenant_id, action.target_kind, target)

    said = None
    if reviewed:
        said = peer_review.review_action(
            conn,
            store,
            tenant_id,
            action_type=proposal.action_type,
            plan=action.plan(proposal.params),
            target_kind=action.target_kind,
            target=target,
            rationale=proposal.rationale,
            case=case,
            research=research,
            config=cfg,
        )
    return research, said


def _case_has_citations(conn: Conn, tenant_id: str, case_uid: str) -> bool:
    row = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s AND cardinality(event_uids) > 0""",
        (tenant_id, case_uid),
    )
    return bool(row and row["n"])


def _auto_actions(conn: Conn, tenant_id: str, case_uid: str | None) -> int:
    if not case_uid:
        return 0
    row = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.actions
           WHERE tenant_id = %s AND case_uid = %s AND autonomy = 'L1'
             AND type NOT LIKE 'notify.%%'
             AND state IN ('approved','running','done')""",
        (tenant_id, case_uid),
    )
    return int(row["n"]) if row else 0


def propose(
    conn: Conn,
    tenant_id: str,
    proposal: Proposal,
    principal: str,
    principal_kind: str = "agent",
    config: Any = None,
    policy: Policy | None = None,
) -> dict[str, Any]:
    """Record a proposed action, already carrying the policy's decision.

    A parameter the action can find for itself is filled in first, so an action
    is never proposed without every parameter it needs to act (RSP-4).
    """
    action = get_action(proposal.action_type)
    proposal.params = dict(proposal.params)
    linked = _follow_link(conn, tenant_id, action, proposal, config)
    # Which platform, and which tenant of it: from where the target was seen.
    acts_with, gaps = credentials.route(
        conn,
        tenant_id,
        action,
        proposal.params,
        proposal.case_uid or "",
        config=config,
        named=proposal.credential,
    )
    _resolve(conn, tenant_id, action, proposal.params, config, acts_with[:1])
    action.check(proposal.params)
    decision, _case = decide(
        conn, tenant_id, proposal, principal_kind, config, policy, linked=linked
    )
    if gaps and not acts_with and decision.allowed:
        decision.allowed, decision.reason = False, "; ".join(gaps)
    elif gaps:
        # Contained where shoc can act; the rest is said, not skipped in silence.
        decision.reason = "; ".join([*gaps, decision.reason]).strip("; ")
    target = (
        str(proposal.params.get(action.required_params[0], "")) if action.required_params else ""
    )
    uid = make_uid(tenant_id, proposal.action_type, target, proposal.case_uid)
    existing = fetch_one(
        conn, "SELECT * FROM shoc.actions WHERE tenant_id=%s AND action_uid=%s", (tenant_id, uid)
    )
    if existing and existing["state"] not in ("proposed", "blocked", "failed"):
        # Settled, approved or running already. Re-proposing it must not undo a
        # human's rejection or approval, or repeat a completed action. A failed
        # one is decided again, with the parameters it is proposed with now.
        return existing
    state = (
        "blocked"
        if not decision.allowed
        else ("proposed" if decision.needs_approval else "approved")
    )
    params = dict(proposal.params)
    if decision.ttl_minutes and not params.get("ttl_minutes"):
        params["ttl_minutes"] = decision.ttl_minutes  # the policy's expiry (RSP-4)
    # An action that waits for a human needs a point at which waiting stops
    # being the answer: nobody here watches the tool most days, and an approval
    # that never comes used to leave the action `proposed` for ever (017). The
    # Commander may name a shorter window; asking again does not restart it.
    waited = existing and existing["state"] == "proposed" and state == "proposed"
    window = min(
        proposal.window_minutes or 60 * unattended.DECIDE_WITHIN_HOURS,
        60 * unattended.DECIDE_WITHIN_HOURS,
    )
    decide_by = (
        existing["decide_by"]
        if waited and existing
        else datetime.now(UTC) + timedelta(minutes=window)
        if state == "proposed"
        else None
    )
    row = _settle(
        conn,
        tenant_id,
        principal,
        "action.proposed",
        """INSERT INTO shoc.actions
               (action_uid, tenant_id, case_uid, run_uid, type, target, params, autonomy,
                state, reversible, dry_run, rationale, requested_by, idempotency_key,
                decide_by, fallback, blast_radius, grounded, acts_in)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (action_uid) DO UPDATE SET
               case_uid = EXCLUDED.case_uid,
               run_uid = coalesce(EXCLUDED.run_uid, shoc.actions.run_uid),
               params = EXCLUDED.params,
               autonomy = EXCLUDED.autonomy,
               state = EXCLUDED.state,
               dry_run = EXCLUDED.dry_run,
               rationale = EXCLUDED.rationale,
               decide_by = EXCLUDED.decide_by,
               chased_at = CASE WHEN EXCLUDED.decide_by = shoc.actions.decide_by
                                THEN shoc.actions.chased_at END,
               fallback = EXCLUDED.fallback,
               blast_radius = EXCLUDED.blast_radius,
               grounded = EXCLUDED.grounded,
               acts_in = EXCLUDED.acts_in,
               error = NULL,
               updated_at = now()
           RETURNING *""",
        (
            uid,
            tenant_id,
            proposal.case_uid,
            proposal.run_uid,
            proposal.action_type,
            target,
            json.dumps(params),
            decision.autonomy,
            state,
            action.reversible,
            decision.dry_run,
            (proposal.rationale + (f" [{decision.reason}]" if decision.reason else "")).strip(),
            principal,
            f"{uid}:{proposal.run_uid or 'adhoc'}",
            decide_by,
            proposal.fallback.strip(),
            None if proposal.blast_radius is None else json.dumps(proposal.blast_radius),
            proposal.grounded,
            acts_with or None,
        ),
        kind=principal_kind,
    )
    if state == "proposed" and not waited and not proposal.action_type.startswith("notify."):
        from shoc.agents import manager

        # Recorded for the Manager: it rides on a page for the same case, or is
        # listed in the weekly. Its fallback runs either way (RFC 0015, RSP-7).
        manager.tell(
            conn,
            tenant_id,
            principal,
            "decision",
            f"{proposal.action_type} on {target}"
            + (f" in {', '.join(acts_with)}" if acts_with else "")
            + " waits for approval until "
            f"{decide_by:%d %b %H:%M} UTC: {proposal.rationale}",
            case_uid=proposal.case_uid or "",
            deliver=False,
        )
    if proposal.case_uid:
        engine.publish(
            conn,
            tenant_id,
            "action.proposed",
            uid,
            {
                "case_uid": proposal.case_uid,
                "type": proposal.action_type,
                "target": target,
                "autonomy": decision.autonomy,
                "state": state,
                "reason": decision.reason,
            },
        )
    return row or {}


def require(conn: Conn, tenant_id: str, action_uid: str) -> dict[str, Any]:
    row = fetch_one(
        conn,
        "SELECT * FROM shoc.actions WHERE tenant_id=%s AND action_uid=%s",
        (tenant_id, action_uid),
    )
    if not row:
        raise NotFound(f"no action '{action_uid}'")
    return row


def approve(
    conn: Conn, tenant_id: str, action_uid: str, approver: str, principal_kind: str
) -> dict[str, Any]:
    """Approve an action. Only a human may do this (decision D8)."""
    if principal_kind != "human":
        raise Denied("only a human principal may approve an action")
    row = require(conn, tenant_id, action_uid)
    if row["state"] == "blocked":
        raise ValidationError(
            f"{action_uid} was blocked by policy and cannot be approved: {row['rationale']}"
        )
    if row["state"] not in ("proposed", "approved"):
        raise ValidationError(f"{action_uid} is {row['state']} and cannot be approved")
    out = _settle(
        conn,
        tenant_id,
        approver,
        "action.approved",
        """UPDATE shoc.actions SET state='approved', approved_by=%s, approved_at=now(),
               updated_at=now()
           WHERE tenant_id=%s AND action_uid=%s RETURNING *""",
        (approver, tenant_id, action_uid),
        kind=principal_kind,
    )
    engine.publish(
        conn,
        tenant_id,
        "action.approved",
        action_uid,
        {"case_uid": row["case_uid"], "type": row["type"], "target": row["target"], "by": approver},
    )
    return out or {}


def reject(conn: Conn, tenant_id: str, action_uid: str, who: str, note: str = "") -> dict[str, Any]:
    row = require(conn, tenant_id, action_uid)
    if row["state"] in TERMINAL:
        raise ValidationError(f"{action_uid} is already {row['state']}")
    out = _settle(
        conn,
        tenant_id,
        who,
        "action.rejected",
        """UPDATE shoc.actions SET state='rejected', approved_by=%s, updated_at=now(),
               error=%s
           WHERE tenant_id=%s AND action_uid=%s RETURNING *""",
        (who, note or None, tenant_id, action_uid),
    )
    engine.publish(
        conn,
        tenant_id,
        "action.rejected",
        action_uid,
        {"case_uid": row["case_uid"], "by": who, "note": note},
    )
    return out or {}


def reject_pending(conn: Conn, tenant_id: str, case_uid: str, who: str, note: str) -> int:
    """Answer every proposal still waiting on a case. Returns how many."""
    pending = fetch_all(
        conn,
        """SELECT action_uid FROM shoc.actions
           WHERE tenant_id = %s AND case_uid = %s AND state = 'proposed'""",
        (tenant_id, case_uid),
    )
    for row in pending:
        reject(conn, tenant_id, str(row["action_uid"]), who, note[:500])
    return len(pending)


def retry(
    conn: Conn, tenant_id: str, action_uid: str, by: str, run_uid: str | None = None
) -> dict[str, Any]:
    """Put a failed action back to `approved`, under the decision that approved it (RSP-2).

    `run_uid` hands it to that playbook run, so the worker does not also queue it.
    """
    return _settle(
        conn,
        tenant_id,
        by,
        "action.retried",
        """UPDATE shoc.actions SET state='approved', error=NULL, updated_at=now(),
               run_uid = coalesce(%s, run_uid)
           WHERE tenant_id=%s AND action_uid=%s AND state='failed' RETURNING *""",
        (run_uid, tenant_id, action_uid),
    ) or require(conn, tenant_id, action_uid)


def fail_if_stuck(conn: Conn, tenant_id: str, action_uid: str, by: str) -> dict[str, Any]:
    """Settle an action a dead worker left `running` as failed; {} while it may still run."""
    return _settle(
        conn,
        tenant_id,
        by,
        "action.executed",
        """UPDATE shoc.actions SET state='failed', updated_at=now(),
               error='the worker stopped during the call; whether it took effect is unknown'
           WHERE tenant_id=%s AND action_uid=%s AND state='running'
             AND updated_at < now() - %s * interval '1 minute' RETURNING *""",
        (tenant_id, action_uid, STUCK_AFTER_MINUTES),
        "the worker stopped during the call",
    )


def queue_run(conn: Conn, tenant_id: str, action_uid: str) -> bool:
    """Queue an approved action to run. A job parked as failed frees its key (RSP-7).

    The key counts the parked jobs, so a running or pending one is never doubled
    and an action whose job failed can be queued again, up to RUN_JOBS times.
    """
    from shoc.db import jobs

    parked = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.jobs
           WHERE kind = 'action.run' AND state = 'failed' AND payload->>'action_uid' = %s""",
        (action_uid,),
    )
    failed = int(parked["n"]) if parked else 0
    if failed >= RUN_JOBS:
        return False
    return (
        jobs.enqueue(
            conn,
            tenant_id,
            "action.run",
            {"action_uid": action_uid},
            idempotency_key=f"action:{action_uid}" + (f":{failed}" if failed else ""),
        )
        is not None
    )


def execute(
    conn: Conn,
    tenant_id: str,
    action_uid: str,
    master_key: str,
    force_dry_run: bool | None = None,
    *,
    by: str,
) -> tuple[dict[str, Any], ActionResult]:
    """Run an approved action as `by`. Idempotent: a done action is returned as-is."""
    row = require(conn, tenant_id, action_uid)
    if row["state"] == "done":
        return row, ActionResult(ok=True, detail="already done", data=dict(row["result"] or {}))
    if row["state"] != "approved":
        raise ValidationError(f"{action_uid} is {row['state']}, not approved")
    if row["type"] == "notify.page" and row["requested_by"] != "manager":
        return _hand_to_manager(conn, tenant_id, row, by)
    action = get_action(row["type"])
    params = dict(row["params"] or {})
    dry_run = row["dry_run"] if force_dry_run is None else force_dry_run

    acts_with = list(row.get("acts_in") or [])
    execute_sql = """UPDATE shoc.actions SET state=%s, result=%s, undo=%s, error=%s,
                          acts_in=%s, executed_at=now(), updated_at=now()
                     WHERE tenant_id=%s AND action_uid=%s RETURNING *"""
    # On record before the side effect: a worker that dies mid-call leaves
    # `action.started` in the chain and the row `running` (ops alert `action.stuck`).
    _settle(
        conn,
        tenant_id,
        by,
        "action.started",
        """UPDATE shoc.actions SET state='running', updated_at=now()
           WHERE tenant_id=%s AND action_uid=%s RETURNING *""",
        (tenant_id, action_uid),
    )
    state, undo_data, error = "done", {}, None
    if dry_run:
        result = dry_run_result(action, params)
        if acts_with:
            result.detail += f" in {', '.join(acts_with)}"
    else:
        try:
            if not acts_with:
                # Credentials given after the proposal: chosen now, the same way.
                acts_with, gaps = credentials.route(
                    conn, tenant_id, action, params, str(row["case_uid"] or "")
                )
                if gaps and not acts_with:
                    raise ConfigError("; ".join(gaps))
            result = _act(
                conn,
                tenant_id,
                action,
                params,
                acts_with or [action.provider],
                master_key,
                dict(row["result"] or {}),
            )
            undo_data = result.undo
        except Exception as exc:
            result = ActionResult(ok=False, detail=f"{type(exc).__name__}: {exc}")
            state, error = "failed", str(exc)[:2000]
    if not result.ok and state == "done":  # the vendor answered, and said no
        state, error = "failed", result.detail[:2000]
    out = _settle(
        conn,
        tenant_id,
        by,
        "action.executed",
        execute_sql,
        (
            state,
            json.dumps(result.to_json(), default=str),
            json.dumps(undo_data, default=str),
            error,
            acts_with or None,
            tenant_id,
            action_uid,
        ),
        None if result.ok else result.detail,
    )
    engine.publish(
        conn,
        tenant_id,
        "action.executed",
        action_uid,
        {
            "case_uid": row["case_uid"],
            "type": row["type"],
            "target": row["target"],
            "ok": result.ok,
            "dry_run": dry_run,
            "reversible": bool(row["reversible"]),
            "detail": result.detail[:300],
        },
    )
    ttl = int(params.get("ttl_minutes") or 0)
    if result.ok and ttl and row["reversible"]:
        # A block with a lifetime is undone when it runs out (RSP-4).
        from shoc.db import jobs

        jobs.enqueue(
            conn,
            tenant_id,
            "action.expire",
            {"action_uid": action_uid},
            run_at=datetime.now(UTC) + timedelta(minutes=ttl),
            idempotency_key=f"expire:{action_uid}",
        )
    return out or {}, result


def _act(
    conn: Conn,
    tenant_id: str,
    action: Any,
    params: dict[str, Any],
    acts_with: list[str],
    master_key: str,
    before: dict[str, Any],
) -> ActionResult:
    """Act with each credential the action was routed to (RFC 0025).

    One credential keeps the result and undo as the action returns them. With
    several, each is recorded under its name, and one that succeeded on an
    earlier try is not asked again: suspending a user twice is an error at Okta.
    """
    if len(acts_with) == 1:
        return action.execute(credentials.load(conn, tenant_id, acts_with[0], master_key), params)
    done = (before.get("data") or {}).get("acts_in") or {}
    each: dict[str, dict[str, Any]] = {}
    for name in acts_with:
        if (done.get(name) or {}).get("ok"):
            each[name] = done[name]
            continue
        try:
            res = action.execute(credentials.load(conn, tenant_id, name, master_key), params)
        except Exception as exc:
            res = ActionResult(ok=False, detail=f"{type(exc).__name__}: {exc}")
        each[name] = {"ok": res.ok, "detail": res.detail, "data": res.data, "undo": res.undo}
    return ActionResult(
        ok=all(v["ok"] for v in each.values()),
        detail="; ".join(f"{n}: {v['detail']}" for n, v in each.items()),
        data={"acts_in": each},
        undo={"acts_in": {n: v.get("undo") or {} for n, v in each.items()}},
    )


def _undo_one(
    conn: Conn, tenant_id: str, action: Any, name: str, master_key: str, stored: dict[str, Any]
) -> ActionResult:
    """Undo one credential's part, so a failure in one tenant does not leave the others."""
    try:
        creds = credentials.load(conn, tenant_id, name, master_key)
        return action.undo(creds, dict((stored.get("acts_in") or {}).get(name) or {}))
    except Exception as exc:
        return ActionResult(ok=False, detail=f"{type(exc).__name__}: {exc}")


def _hand_to_manager(
    conn: Conn, tenant_id: str, row: dict[str, Any], by: str
) -> tuple[dict[str, Any], ActionResult]:
    """A page from a playbook or the crew goes to the Manager, not to PagerDuty.

    The step succeeds, so a playbook needs no edit. Whether anybody is woken is
    the Manager's gate: a critical case pages, anything else reaches the weekly
    (RFC 0015).
    """
    from shoc.agents import manager

    case_uid = str(row["case_uid"] or "")
    severity = ""
    if case_uid:
        severity = str(engine.require(conn, tenant_id, case_uid)["severity"])
    notice = manager.tell(
        conn,
        tenant_id,
        str(row["requested_by"]),
        "page",
        str((row["params"] or {}).get("summary") or row["rationale"]),
        case_uid=case_uid,
        condition="critical_severity" if severity == "critical" else "",
    )
    result = ActionResult(
        ok=True, detail=f"handed to the SOC Manager as {notice}", data={"notice_uid": notice}
    )
    out = _settle(
        conn,
        tenant_id,
        by,
        "action.executed",
        """UPDATE shoc.actions SET state='done', result=%s, executed_at=now(), updated_at=now()
           WHERE tenant_id=%s AND action_uid=%s RETURNING *""",
        (json.dumps(result.to_json()), tenant_id, str(row["action_uid"])),
    )
    return out or row, result


def undo(
    conn: Conn, tenant_id: str, action_uid: str, master_key: str, *, by: str
) -> tuple[dict[str, Any], ActionResult]:
    """Roll an executed action back as `by`, if it is reversible."""
    row = require(conn, tenant_id, action_uid)
    if row["state"] != "done":
        raise ValidationError(f"{action_uid} is {row['state']}; only a done action can be undone")
    if not row["reversible"]:
        raise ValidationError(f"{row['type']} is not reversible")
    action = get_action(row["type"])
    if row["dry_run"]:
        result = ActionResult(ok=True, detail="[dry run] nothing to undo", dry_run=True)
    else:
        acts_with = list(row.get("acts_in") or []) or [action.provider]
        stored = dict(row["undo"] or {})
        if len(acts_with) == 1:
            creds = credentials.load(conn, tenant_id, acts_with[0], master_key)
            result = action.undo(creds, stored)
        else:
            each = {
                name: _undo_one(conn, tenant_id, action, name, master_key, stored)
                for name in acts_with
            }
            result = ActionResult(
                ok=all(r.ok for r in each.values()),
                detail="; ".join(f"{n}: {r.detail}" for n, r in each.items()),
            )
    out = _settle(
        conn,
        tenant_id,
        by,
        "action.rolled_back",
        """UPDATE shoc.actions SET state=%s, result=%s, updated_at=now()
           WHERE tenant_id=%s AND action_uid=%s RETURNING *""",
        (
            "rolled_back" if result.ok else "done",
            json.dumps(result.to_json(), default=str),
            tenant_id,
            action_uid,
        ),
        None if result.ok else result.detail,
    )
    engine.publish(
        conn,
        tenant_id,
        "action.rolled_back",
        action_uid,
        {"case_uid": row["case_uid"], "ok": result.ok, "detail": result.detail[:300]},
    )
    return out or {}, result


def listing(
    conn: Conn, tenant_id: str, state: str = "", case_uid: str = "", limit: int = 50
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": max(1, min(limit, 500))}
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    if case_uid:
        where.append("case_uid = %(case_uid)s")
        params["case_uid"] = case_uid
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.actions WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC LIMIT %(limit)s",
        params,
    )


# -- the catalogue, and the crew's proposals (RSP-2, RSP-4) -----------------
@dataclass
class CrewProposal:
    """What an agent asked for, before anything has resolved it."""

    action: str
    target: str
    rationale: str = ""
    grounded: bool = True
    # The action's other required parameters, when the Commander knows them.
    params: dict[str, Any] = field(default_factory=dict)
    fallback: str = ""
    window_minutes: int = 0
    blast_radius: dict[str, Any] | None = None


@dataclass
class Taken:
    """What became of one of those proposals."""

    action: str
    target: str
    action_uid: str = ""
    state: str = ""
    autonomy: str = ""
    queued: bool = False
    error: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "action_uid": self.action_uid,
            "state": self.state,
            "autonomy": self.autonomy,
            "queued": self.queued,
            "error": self.error,
        }


def catalogue(
    config: Any = None, policy: Policy | None = None, scope: credentials.Scope | None = None
) -> list[dict[str, Any]]:
    """Every action that exists, and what the policy will do with each one.

    Given where a case was seen, only the actions that answer it: the Commander
    once offered to make a GitHub repository private in answer to a public S3
    bucket, and a SentinelOne alert is not contained in CrowdStrike (RFC 0031).

    The IR Commander used to name actions from memory: `okta.revoke_sessions`
    for an action then called `idp.revoke_sessions`, and twice a name for
    nothing at all. A name nothing can resolve is a sentence in a chat table, so
    the Commander is now shown the list instead of remembering it. An action
    whose provider holds no credential says so in `can_run`.
    """
    from shoc.actions import load

    try:
        policy = policy or Policy.load(config)
    except Exception:  # an install without a policy still gets the names right
        policy = Policy()
    out = []
    for action in load().values():
        if scope is not None and scope.excludes(action):
            continue
        linked = scope is not None and bool(out_of_scope(action, scope.platforms))
        known = action.type in policy.actions
        rule = policy.rule_for(action.type)
        entry: dict[str, Any] = {
            "action": action.type,
            "does": action.summary,
            # RFC 0027: shoc swaps the case's user for the login it signs in as.
            "target": f"{action.target_kind}, for the IdP login identity.resolve links it to"
            if linked
            else action.target_kind,
            "params": list(action.required_params),
            "reversible": action.reversible,
            "autonomy": str(rule.get("autonomy", "L2")) if known else "not in the policy",
        }
        if scope is not None and scope.held is not None and action.provider not in scope.held:
            entry["can_run"] = f"no {action.provider} credential"
        out.append(entry)
    return sorted(out, key=lambda a: str(a["action"]))


def from_crew(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    proposals: list[CrewProposal],
    *,
    principal: str = "IR Commander",
    config: Any = None,
    policy: Policy | None = None,
) -> list[Taken]:
    """Turn the Commander's proposals into actions the policy has ruled on.

    Until this existed, a proposal was only a message: an L1 action the policy
    would have allowed — a leaked key disabled, a session revoked — was written
    into the openspace as JSON and nothing ever read it back. The crew proposes,
    the policy decides, and an action it allows without a human is queued to run.
    Nothing here approves anything: `propose` records the policy's own decision,
    and an L2 action is left waiting for a person exactly as before.
    """
    from shoc.cases.own import bare

    out: list[Taken] = []
    for wanted in proposals:
        # A target written as an entity key (`user:alice@…`) is the account
        # itself: protected targets and earlier rejections match on the bare value.
        name, target = wanted.action.strip(), bare(wanted.target)
        taken = Taken(action=name, target=target)
        out.append(taken)
        if not name or not target:
            taken.error = "the proposal named no action or no target"
            continue
        try:
            action = get_action(name)
            params = {k: str(v).strip() for k, v in wanted.params.items() if str(v).strip()}
            if action.required_params:
                params[action.required_params[0]] = target
            row = propose(
                conn,
                tenant_id,
                Proposal(
                    action_type=name,
                    params=params,
                    rationale=wanted.rationale,
                    case_uid=case_uid,
                    grounded=wanted.grounded,
                    fallback=wanted.fallback,
                    window_minutes=wanted.window_minutes,
                    blast_radius=wanted.blast_radius,
                ),
                principal,
                principal_kind="agent",
                config=config,
                policy=policy,
            )
        except (Denied, NotFound, ValidationError) as exc:
            taken.error = str(exc)
            continue
        except Exception as exc:  # one bad proposal must not lose the others
            taken.error = f"{type(exc).__name__}: {exc}"
            continue
        taken.action_uid = str(row.get("action_uid", ""))
        taken.state = str(row.get("state", ""))
        taken.autonomy = str(row.get("autonomy", ""))
        if taken.state == "approved":
            taken.queued = queue_run(conn, tenant_id, taken.action_uid)
    return out


# A target that can travel inside a `q` search unquoted: an id, a name, an address.
PLAIN = re.compile(r"[\w.@:/+=-]+")


def _follow_link(
    conn: Conn, tenant_id: str, action: Any, proposal: Proposal, config: Any
) -> tuple[bool, str]:
    """Aim an action the case's platforms do not cover at the login its user signs
    in as there, and say how; or say why not (RFC 0027).

    Only an action that names the case's platform in `linked_from`, and only for
    a user of the case or the login one of them is linked to. The name the case
    holds (jdoe on a laptop) is never sent: the target becomes the login, or the
    action is refused. The link reads every identity provider's events; the
    action goes ahead only where its own vendor saw the login sign in (RFC 0031).
    """
    if not proposal.case_uid or not action.required_params:
        return False, ""
    platforms = engine.platforms(conn, tenant_id, proposal.case_uid, config)
    if not out_of_scope(action, platforms) or not follows_link(action, platforms):
        return False, ""
    from shoc.agents import surveyor
    from shoc.cases import own
    from shoc.config import Config
    from shoc.store import open_store

    key = action.required_params[0]
    target = own.bare(str(proposal.params.get(key, ""))).lower()
    users = [
        own.bare(str(r["entity"]))
        for r in fetch_all(
            conn,
            """SELECT entity FROM shoc.case_entities
               WHERE tenant_id = %s AND case_uid = %s AND entity LIKE 'user:%%'
               ORDER BY entity LIMIT 10""",
            (tenant_id, proposal.case_uid),
        )
    ]
    try:
        store = open_store(config or Config.load(), tenant_id)
        try:
            links = {u: surveyor.logins(store, tenant_id, u) for u in users}
        finally:
            store.close()
    except Exception as exc:  # an unread link is no link: refused, never guessed
        return False, f"could not read which login {target} signs in as: {type(exc).__name__}"
    for user, link in links.items():
        if len(link["logins"]) == 1:
            login = link["logins"][0]
            if target in (user.lower(), str(login["login"]).lower()):
                if not credentials.signed_in(
                    tenant_id, tuple(action.platforms), login["login"], config
                ):
                    return False, (
                        f"{user} signs in as {login['login']}, who has not signed in to "
                        f"{action.provider} in 30 days"
                    )
                proposal.params[key] = login["login"]
                cited = ", ".join(login["event_uids"][:3])
                return True, f"{user} signs in as {login['login']} ({login['via']}: {cited})"
    said = [link["why"] for user, link in links.items() if user.lower() == target]
    return False, (
        said[0]
        if said
        else f"{target or 'no user'} is neither a user of this case nor the login one signs in as"
    )


def _resolve(
    conn: Conn,
    tenant_id: str,
    action: Any,
    params: dict[str, Any],
    config: Any,
    acts_with: list[str] | None = None,
) -> None:
    """Fill in the parameters a proposal left out (RSP-4).

    An action declares, per parameter, the event column its target appears in,
    the column that names the value, and the platform lookup that answers when
    our events do not: IAM needs the user a key belongs to, and the Commander
    names only the key. A value the events disagree on is left out, and the
    proposal is then refused for the missing parameter rather than guessed.
    With no column, only the lookup answers, and it is asked with the
    proposal's parameters: which trail is off now, which factor is newest.
    """
    wanted = {k: v for k, v in getattr(action, "resolve", {}).items() if not params.get(k)}
    if not wanted:
        return
    target = str(params.get(action.required_params[0], ""))
    from shoc.capabilities.events import EventQuery, build_query
    from shoc.config import Config
    from shoc.store import open_store

    cfg = config or Config.load()
    for name, (where, column, lookup) in wanted.items():
        if where:
            if not PLAIN.fullmatch(target):
                continue
            try:
                store = open_store(cfg, tenant_id)
                sql, args, limit = build_query(
                    EventQuery(q=f"{where}={target}", since="-30d", limit=50, include_raw=True),
                    tenant_id,
                )
                seen = {str(r.get(column) or "") for r in store.query(sql, args, limit).rows}
                seen -= {""}
                if len(seen) == 1:
                    params[name] = seen.pop()
                    continue
            except Exception:  # an unreadable store falls through to the platform
                pass
        if not lookup:
            continue
        try:
            from shoc.actions import get_lookup

            lk = get_lookup(lookup)
            # The lookup reads where the action will act: the same tenant.
            cred = next(iter(acts_with or []), lk.provider)
            if credentials.provider_of(cred) != lk.provider:
                cred = lk.provider
            creds = credentials.load(conn, tenant_id, cred, cfg.master_key)
            asked = {action.required_params[0]: target} if where else dict(params)
            value = str(lk.run(creds, asked).get(name) or "")
            if value:
                params[name] = value
        except Exception:  # no credentials, or the platform said no: it stays missing
            pass


def approved_unrun(conn: Conn, limit: int = 50) -> list[dict[str, Any]]:
    """Actions the policy or a human has approved that nobody has run.

    An action owned by a playbook (`run_uid`) is the runner's to execute, unless
    the run left it behind as an optional step. This is everything else: a crew
    proposal the policy allowed, and an L2 action a human approved in Slack. Neither used to have anything watching for it. Every
    tenant at once, because the worker's queue is shared and each job scopes
    itself.
    """
    return fetch_all(
        conn,
        """SELECT action_uid, tenant_id, type, target FROM shoc.actions a
           WHERE state = 'approved'
             AND (run_uid IS NULL
                  -- an optional step the run left for a human, who has now said yes
                  OR EXISTS (SELECT 1 FROM shoc.playbook_steps s
                             WHERE s.action_uid = a.action_uid
                               AND s.state = 'awaiting_approval'))
           ORDER BY updated_at LIMIT %s""",
        (limit,),
    )
