"""What shoc does when nobody comes (RSP-3, AGT-1, OPS-1).

The company running this has one technical person and no security team, and most
days they do not open the tool. Anything whose resting state is "a human will
decide this" therefore does not happen at all:

- an L2 action sat `proposed` until the incident was history,
- a `needs_human` case sat in `analysis` with nobody's name on it, and a case in
  `containment` with nothing new to say sat there for ever,
- and the crew ran once per case and was never sent back.

So waiting is given a deadline. Past it, three things can happen and none of
them is waiting:

- **The Commander's fallback runs.** An L2 the crew proposed names a narrower
  reversible action and a window (D45). When the window closes unanswered, the
  L2 is abandoned and the fallback is put to the policy in its place.
- **The critical band gets paged.** A case at `high` or above whose response is
  stuck on an approval is worth the one thing that is scarce here, which is the
  operator's attention. The SOC Manager pages it at most once a day per
  incident (RFC 0015), and a page is never itself something to chase. A page is a second window, not a third state: an
  action still undecided a window after the page, or one whose page could not
  go out, is abandoned like any other.
- **Everything else is decided without them.** A medium case's proposed action
  is abandoned with a reason written into the case, and the crew is sent back
  with the plain fact that nobody is coming — to reach a disposition, or to
  propose something reversible it can do by itself.
- **What is left goes in the weekly**, which is the thing the operator reads
  when they do come back. A case below `high` that passes its deadline twice
  is closed with the reason written into it, rather than paged.

Nothing here raises an action's autonomy or approves anything. An abandoned
action is rejected, not run, and whether a page goes out is the Manager's
gate, not this module's. The one thing this module will not do is leave a case in a state whose
only exit is somebody logging in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from shoc.cases import engine
from shoc.db.pool import Conn, execute, fetch_all

# How long a proposed action waits for a person before this module resolves it.
# Four hours is a working morning: long enough that somebody who does check the
# tool daily gets to decide, short enough that containment still means something.
DECIDE_WITHIN_HOURS = 4

# The severity band worth waking the only technical person in the company for.
PAGE_AT_LEAST = "high"

# How long a case may sit on `needs_human` before the crew is sent back to it.
NUDGE_AFTER_HOURS = 6

# Every open case carries a deadline set by its severity (D51). On the first
# expiry the crew is woken and must close or say what it is waiting for; on the
# second, a case severe enough is paged and any other is closed.
DEADLINE_HOURS = {"critical": 1, "high": 4, "medium": 24, "low": 72, "informational": 72}

# A case pages at most once in this window, however many of its actions stall.
PAGE_AT_MOST_EVERY_HOURS = 24


@dataclass
class Chased:
    """What the deadline produced this cycle."""

    paged: list[str] = field(default_factory=list)
    abandoned: list[str] = field(default_factory=list)
    nudged: list[str] = field(default_factory=list)
    fell_back: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not (self.paged or self.abandoned or self.nudged or self.fell_back or self.closed):
            return "unattended: nothing has been waiting long enough to chase"
        parts = []
        if self.fell_back:
            parts.append(f"fell back on {len(self.fell_back)} unanswered action(s)")
        if self.closed:
            parts.append(f"closed {len(self.closed)} case(s) nobody finished")
        if self.paged:
            parts.append(f"paged for {len(self.paged)} case(s)")
        if self.abandoned:
            parts.append(f"abandoned {len(self.abandoned)} undecided action(s)")
        if self.nudged:
            parts.append(f"sent the crew back to {len(self.nudged)} case(s)")
        return "unattended: " + ", ".join(parts)


def _worth_paging(severity: str) -> bool:
    return engine.SEVERITY_ORDER.index(severity or "medium") >= engine.SEVERITY_ORDER.index(
        PAGE_AT_LEAST
    )


def run(conn: Conn, tenant_id: str, config: Any = None) -> Chased:
    """One pass over everything that is waiting for somebody who is not coming."""
    out = Chased()
    _undecided_actions(conn, tenant_id, config, out)
    _stalled_cases(conn, tenant_id, config, out)
    return out


def _undecided_actions(conn: Conn, tenant_id: str, config: Any, out: Chased) -> None:
    """Actions that have waited past their deadline for an approval."""
    rows = fetch_all(
        conn,
        """SELECT a.action_uid, a.type, a.target, a.case_uid, a.rationale, a.chased_at,
                  a.params, a.fallback, a.blast_radius, a.grounded, c.severity, c.verdict
           FROM shoc.actions a
           LEFT JOIN shoc.cases c
             ON c.tenant_id = a.tenant_id AND c.case_uid = a.case_uid
           WHERE a.tenant_id = %s AND a.state = 'proposed'
             AND a.type NOT LIKE 'notify.%%'
             AND a.decide_by IS NOT NULL AND a.decide_by <= now()
             AND (a.chased_at IS NULL OR a.chased_at <= now() - %s * interval '1 hour')
           ORDER BY a.decide_by
           LIMIT 50""",
        (tenant_id, DECIDE_WITHIN_HOURS),
    )
    for row in rows:
        action_uid = str(row["action_uid"])
        severity = str(row["severity"] or "medium")
        fallback = str(row["fallback"] or "").strip()
        if fallback and fallback != "expire" and row["chased_at"] is None and row["case_uid"]:
            _fall_back(conn, tenant_id, row, fallback, config)
            out.fell_back.append(action_uid)
            continue
        if row["chased_at"] is not None:
            _abandon(
                conn,
                tenant_id,
                row,
                (f"somebody was paged {DECIDE_WITHIN_HOURS}h ago and nobody decided"),
            )
            out.abandoned.append(action_uid)
            continue
        execute(
            conn,
            "UPDATE shoc.actions SET chased_at = now() WHERE tenant_id = %s AND action_uid = %s",
            (tenant_id, action_uid),
        )
        if _worth_paging(severity):
            if _page(
                conn,
                tenant_id,
                str(row["case_uid"] or ""),
                f"{row['type']} on {row['target']} has been waiting "
                f"{DECIDE_WITHIN_HOURS}h for your approval on a {severity} case.",
                config,
            ):
                out.paged.append(action_uid)
                continue
            _abandon(
                conn,
                tenant_id,
                row,
                (f"nobody decided within {DECIDE_WITHIN_HOURS}h, and no page could go out"),
            )
        else:
            _abandon(
                conn,
                tenant_id,
                row,
                (
                    f"nobody decided within {DECIDE_WITHIN_HOURS}h, and a "
                    f"{severity} case is not worth a page"
                ),
            )
        out.abandoned.append(action_uid)


def _fall_back(conn: Conn, tenant_id: str, row: dict[str, Any], fallback: str, config: Any) -> None:
    """Abandon the L2 nobody answered and propose the Commander's fallback instead (D45).

    The fallback acts on the same target and carries the original's blast radius
    and grounding, so a target the evidence never showed cannot run alone by
    becoming somebody's fallback. The policy rules on it like any proposal.
    """
    from shoc.actions import get as get_action
    from shoc.cases import actions as action_store

    _abandon(
        conn,
        tenant_id,
        row,
        f"nobody decided in time, so its fallback {fallback} was proposed instead",
    )
    try:
        needs = set(get_action(fallback).required_params)
    except Exception:
        needs = set()
    taken = action_store.from_crew(
        conn,
        tenant_id,
        str(row["case_uid"]),
        [
            action_store.CrewProposal(
                fallback,
                str(row["target"]),
                rationale=f"the fallback for {row['type']} on {row['target']}, which nobody approved",
                grounded=bool(row["grounded"]),
                params={k: v for k, v in dict(row["params"] or {}).items() if k in needs},
                blast_radius=row["blast_radius"],
            )
        ],
        config=config,
    )[0]
    _say(
        conn,
        tenant_id,
        str(row["case_uid"]),
        (
            f"Fallback {fallback} on {taken.target}: "
            + (taken.error or f"{taken.state} ({taken.autonomy})")
        ),
    )


def _abandon(conn: Conn, tenant_id: str, row: dict[str, Any], note: str) -> None:
    """Write off an action nobody decided, and say so in the case.

    Rejecting it is the honest record. An action left `proposed` reads, months
    later, as something that was about to happen; this reads as what it was — a
    response nobody authorised.
    """
    from shoc.cases import actions as action_store

    action_store.reject(conn, tenant_id, str(row["action_uid"]), "unattended", note)
    case_uid = str(row["case_uid"] or "")
    if case_uid:
        _say(
            conn,
            tenant_id,
            case_uid,
            f"{row['type']} on {row['target']} was proposed and never approved; "
            f"{note}. Nothing was done about it.",
        )


def _stalled_cases(conn: Conn, tenant_id: str, config: Any, out: Chased) -> None:
    """Open cases past their deadline with nothing new to say (D51).

    The deadline runs from the last time anybody worked the case. The first
    expiry wakes the crew with the fact stated; the second, if the crew has
    still not answered, pages a case severe enough to be worth it and closes
    any other with the reason in the case. A `needs_human` case never waits
    longer than `NUDGE_AFTER_HOURS`.

    Only cases with something to do now are taken: one whose nudge is still
    running its window, or that was paged within the day, used to hold one of
    the 25 places on every pass while newer stalled cases waited behind it.
    """
    rows = fetch_all(
        conn,
        """SELECT * FROM (
             SELECT case_uid, severity, verdict, entity_key, deadline, opened_at,
                    (SELECT max(m.created_at) FROM shoc.openspace_messages m
                      WHERE m.tenant_id = c.tenant_id AND m.case_uid = c.case_uid
                        AND m.agent = 'Ops' AND m.kind = 'inject'
                        AND m.created_at > coalesce(c.worked_at, c.opened_at)
                    ) AS nudged_at,
                    now() AS now
             FROM shoc.cases c,
                  LATERAL (SELECT CASE WHEN c.verdict = 'needs_human'
                            THEN least(%s, (%s::jsonb ->> coalesce(c.severity, 'medium'))::int)
                            ELSE (%s::jsonb ->> coalesce(c.severity, 'medium'))::int
                          END * interval '1 hour' AS deadline) d
             WHERE tenant_id = %s AND state <> 'closed'
               AND coalesce(worked_at, opened_at) <= now() - deadline
               AND NOT EXISTS (
                   SELECT 1 FROM shoc.notices n
                   WHERE n.tenant_id = c.tenant_id AND n.case_uid = c.case_uid
                     AND n.source = 'unattended' AND n.condition = 'deadline_expired'
                     AND n.created_at > now() - %s * interval '1 hour')
           ) due
           WHERE nudged_at IS NULL OR now - nudged_at >= deadline
           ORDER BY
             array_position(ARRAY['critical','high','medium','low','informational'], severity),
             opened_at
           LIMIT 25""",
        (
            NUDGE_AFTER_HOURS,
            json.dumps(DEADLINE_HOURS),
            json.dumps(DEADLINE_HOURS),
            tenant_id,
            PAGE_AT_MOST_EVERY_HOURS,
        ),
    )
    for row in rows:
        case_uid = str(row["case_uid"])
        severity = str(row["severity"] or "medium")
        hours = int(row["deadline"].total_seconds() // 3600)
        if row["nudged_at"] is None:
            # The sweep picks the case up because this message is newer than the
            # last time anybody worked it.
            _say(conn, tenant_id, case_uid, _nudge(str(row["verdict"] or ""), severity, hours))
            out.nudged.append(case_uid)
            continue
        # A nudge the crew has not answered yet is not repeated (the query
        # leaves those out): one case collected 37 copies while the crew never
        # came back to read the first. A second expiry is an outcome.
        if not _worth_paging(severity):
            _close(conn, tenant_id, case_uid, severity, hours)
            out.closed.append(case_uid)
            continue
        if _page(
            conn,
            tenant_id,
            case_uid,
            f"{case_uid} ({severity}, {row['entity_key'] or 'this tenant'}) passed its "
            f"{hours}h deadline twice and the crew has not closed it.",
            config,
        ):
            out.paged.append(case_uid)


def _close(conn: Conn, tenant_id: str, case_uid: str, severity: str, hours: int) -> None:
    """Close a case below the paging band that the crew left past two deadlines.

    Its verdict stands, its waiting proposals are rejected, and the reason is in
    the case and in the weekly. A later finding opens a new case that names it.
    """
    import contextlib

    from shoc.agents import manager
    from shoc.cases import actions as action_store

    why = (
        f"passed its {hours}h deadline twice and the crew did not close it; "
        f"a {severity} case is not worth a page, so it was closed unattended"
    )
    action_store.reject_pending(conn, tenant_id, case_uid, "unattended", why)
    _say(conn, tenant_id, case_uid, f"Closing this case: it {why}.")
    with contextlib.suppress(Exception):
        engine.transition(conn, tenant_id, case_uid, "closed", why, by="system")
    manager.tell(
        conn,
        tenant_id,
        "unattended",
        "digest",
        f"{case_uid} {why}.",
        case_uid=case_uid,
        deliver=False,
    )


def _nudge(verdict: str, severity: str, hours: int) -> str:
    if verdict == "needs_human":
        return (
            f"This case has been waiting {hours}h for a person and nobody is coming. "
            "Nobody watches this tool most days. Decide what can be done without "
            "them: reach a disposition on the evidence you have, or propose the "
            "smallest reversible action that would contain this. If the answer "
            "really is that only a human can act, say exactly what you need from "
            "them in one sentence."
        )
    return (
        f"This {severity} case passed its {hours}h deadline with nothing new. "
        "Close it on the evidence you have, or say in one sentence what it is "
        "waiting for."
    )


def _page(conn: Conn, tenant_id: str, case_uid: str, why: str, config: Any) -> bool:
    """Ask the Manager to wake somebody, and say whether anybody was.

    Delivered here rather than queued, because the answer decides what happens
    to the action: a page that went out, or one already sent for this incident,
    buys a second window; one that could not go out does not (RFC 0015).
    """
    from shoc.agents import manager

    notice = manager.tell(
        conn,
        tenant_id,
        "unattended",
        "page",
        why,
        case_uid=case_uid,
        condition="deadline_expired",
        deliver=False,
    )
    manager.deliver(conn, tenant_id, config)
    row = fetch_all(
        conn,
        "SELECT outcome FROM shoc.notices WHERE tenant_id = %s AND notice_uid = %s",
        (tenant_id, notice),
    )
    return bool(row) and row[0]["outcome"] in ("paged", "merged")


def _say(conn: Conn, tenant_id: str, case_uid: str, body: str) -> None:
    """Put a fact into the openspace the way a human would, so the crew reads it."""
    import contextlib

    from shoc.agents.openspace import Message, post

    with contextlib.suppress(Exception):
        post(
            conn,
            None,
            tenant_id,
            case_uid,
            Message(agent="Ops", kind="inject", body=body, principal="service"),
        )
