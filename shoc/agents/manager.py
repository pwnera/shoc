"""The SOC Manager: the operator's one contact (RFC 0015, AGT-13, API-1, API-3).

Every role and every playbook used to reach the operator on its own. A case
posted itself to Slack when it was investigated and again when an approval
waited, every containment playbook ended in a page, the Commander could ask for
one, and `unattended.py` paged on a second deadline. Only the last of those
checked whether somebody had already been woken, so one leaked key could page
twice and post twice before a second rule opened a second case — and a channel
that says everything is a channel somebody mutes.

So nobody else talks to the operator. A role hands the Manager a notice, and
the Manager decides what one person reads:

- **The gate is a query.** Pages are grouped by incident — the same case, or
  cases on the same entity — and a group pages only on one of six typed
  conditions, at most once in `PAGE_AT_MOST_EVERY_HOURS`. A model is never asked
  whether to wake somebody, so a model misled by log content can change a page's
  wording and cannot stop it.
- **The model writes the text.** If there is no model, it fails, or it cites
  something the group does not contain, a fixed template goes out instead. A
  page is never late because of the model.
- **Questions come back through here too.** `ask` hands the Manager the
  question, and it answers by calling the colleague who knows. Without a model
  `ask` answers the way it always did.

The Manager does not assign work, close cases, change verdicts or approve
anything. Approvals and injected facts stay direct capabilities, so a broken
Manager cannot stand between a person and a decision.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.capabilities.registry import Caller
from shoc.cases.unattended import PAGE_AT_MOST_EVERY_HOURS
from shoc.db.pool import Conn, execute, fetch_all, fetch_one

# The only reasons the operator is woken. The Commander names the first two
# (docs/agents.md), Ops the third, `unattended.py` the fourth, the hourly
# audit check the fifth, and `uncontained` below the sixth.
PAGE_CONDITIONS = (
    "critical_severity",
    "uncontainable_and_active",
    "coverage_dark",
    "deadline_expired",
    "audit_broken",
    "malicious_uncontained",
)

# "Active" means a finding on the case was seen this recently.
ACTIVE_WITHIN_HOURS = 1

# How long a malicious case has to be contained before it pages. The verdict is
# recorded before the Commander proposes, and what the policy lets run alone
# runs in its own job after that.
CONTAIN_WITHIN_MINUTES = 15

# An action on the case that ran for real. A page contains nothing, and a dry
# run changed nothing: neither the action's row nor its result may say dry run.
CONTAINED = """EXISTS (
    SELECT 1 FROM shoc.actions a
    WHERE a.tenant_id = c.tenant_id AND a.case_uid = c.case_uid AND a.state = 'done'
      AND a.type NOT LIKE 'notify.%%' AND NOT a.dry_run
      AND coalesce(a.result->>'dry_run', 'false') <> 'true')"""

# A source dark this long is material: a day of an identity provider is a day of
# logins nobody saw.
COVERAGE_DARK_HOURS = 24

CASE_UID = re.compile(r"\bCASE-[0-9a-f]{20}\b")

# How many earlier turns of a conversation `ask` hands the Manager.
HISTORY_TURNS = 12

# The principal the Manager's own pages are requested under. `notify.page` from
# anybody else is handed back to the Manager as a notice (`cases/actions.py`).
PRINCIPAL = "manager"

# Who the Manager is when it calls a capability: Slack is the only one.
CALLER = Caller(kind="agent", id=f"agent:{PRINCIPAL}", scopes=("slack:write",))


def tell(
    conn: Conn,
    tenant_id: str,
    source: str,
    kind: str,
    body: str,
    *,
    case_uid: str = "",
    condition: str = "",
    severity: str = "",
    citations: list[str] | None = None,
    group_key: str = "",
    deliver: bool = True,
) -> str:
    """Hand the Manager something the operator may need to know.

    A page with no condition is not a page: it is recorded as a digest and
    reaches the weekly. The same notice told twice on one day is one row.
    """
    case: dict[str, Any] = {}
    if case_uid:
        case = (
            fetch_one(
                conn,
                "SELECT severity, entity_key FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
                (tenant_id, case_uid),
            )
            or {}
        )
    if kind == "page" and condition not in PAGE_CONDITIONS:
        kind, condition = "digest", ""
    group = group_key or str(case.get("entity_key") or "") or case_uid or source
    day = datetime.now(UTC).date().isoformat()
    uid = (
        "N-"
        + hashlib.sha256(
            f"{tenant_id}|{source}|{kind}|{condition}|{group}|{case_uid}|{body}|{day}".encode()
        ).hexdigest()[:20]
    )
    execute(
        conn,
        """INSERT INTO shoc.notices (tenant_id, notice_uid, source, case_uid, group_key,
                                     kind, severity, condition, body, citations)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, notice_uid) DO NOTHING""",
        (
            tenant_id,
            uid,
            source,
            case_uid or None,
            group,
            kind,
            severity or str(case.get("severity") or "medium"),
            condition,
            body[:4000],
            list(dict.fromkeys(citations or []))[:50],
        ),
    )
    if kind == "page" and deliver:
        from shoc.db import jobs

        jobs.enqueue(conn, tenant_id, "manager.deliver", {}, idempotency_key=f"deliver:{uid}")
    return uid


@dataclass
class Delivered:
    paged: list[str] = field(default_factory=list)
    merged: int = 0
    digest: int = 0
    failed: list[str] = field(default_factory=list)
    # Why a Slack copy of a page did not go out. The page itself still did.
    slack_errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not (self.paged or self.merged or self.digest or self.failed):
            return "manager: nothing to deliver"
        parts = []
        if self.paged:
            parts.append(f"paged {len(self.paged)} time(s)")
        if self.merged:
            parts.append(f"{self.merged} notice(s) already covered by a page")
        if self.digest:
            parts.append(f"{self.digest} held for the weekly")
        if self.failed:
            parts.append(f"{len(self.failed)} page(s) could not be sent")
        if self.slack_errors:
            parts.append(f"Slack refused {len(self.slack_errors)} post(s): {self.slack_errors[0]}")
        return "manager: " + ", ".join(parts)


def deliver(conn: Conn, tenant_id: str, config: Any = None, store: Any = None) -> Delivered:
    """Run the gate over every undelivered page notice, one page per incident."""
    out = Delivered()
    pending = fetch_all(
        conn,
        f"""SELECT n.*, c.severity AS case_severity, c.state AS case_state,
                   c.verdict AS case_verdict, {CONTAINED} AS case_contained,
                   n.created_at > now() - %s * interval '1 minute' AS held,
                   (SELECT max(f.last_seen) FROM shoc.findings f
                     WHERE f.tenant_id = n.tenant_id AND f.case_uid = n.case_uid) AS case_last_seen
            FROM shoc.notices n
            LEFT JOIN shoc.cases c ON c.tenant_id = n.tenant_id AND c.case_uid = n.case_uid
            WHERE n.tenant_id = %s AND n.kind = 'page' AND n.delivered_at IS NULL
            ORDER BY n.created_at LIMIT 200""",
        (CONTAIN_WITHIN_MINUTES, tenant_id),
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    fresh = datetime.now(UTC) - timedelta(hours=ACTIVE_WITHIN_HOURS)
    for row in pending:
        # "Critical" is the case's severity now, not what somebody said it was;
        # a closed case wakes nobody; "still active" means a detection fired
        # within the hour, not that a model said so; and "uncontained" is the
        # case's verdict, severity and actions now. These are queries, so log
        # content can change none of them (RFC 0015).
        stale = (
            (row["condition"] == "critical_severity" and row["case_severity"] != "critical")
            or (row["case_uid"] and row["case_state"] == "closed")
            or (
                row["condition"] == "uncontainable_and_active"
                and not (row["case_last_seen"] and row["case_last_seen"] >= fresh)
            )
            or (
                row["condition"] == "malicious_uncontained"
                and not _malicious_uncontained(
                    row["case_verdict"], row["case_severity"], row["case_contained"]
                )
            )
        )
        if stale:
            _settle(conn, tenant_id, [row], "digest")
            out.digest += 1
            continue
        if row["condition"] == "malicious_uncontained" and row["held"]:
            continue  # containment gets its chance; the job `uncontained` queued comes back
        groups.setdefault(str(row["group_key"]), []).append(row)

    for key, rows in groups.items():
        earlier = fetch_one(
            conn,
            """SELECT delivered_uid FROM shoc.notices
               WHERE tenant_id = %s AND group_key = %s AND outcome = 'paged'
                 AND delivered_at > now() - %s * interval '1 hour'
               ORDER BY delivered_at DESC LIMIT 1""",
            (tenant_id, key, PAGE_AT_MOST_EVERY_HOURS),
        )
        if earlier:
            _settle(conn, tenant_id, rows, "merged", str(earlier["delivered_uid"]))
            out.merged += len(rows)
            continue
        message = word(conn, tenant_id, rows, config, store)
        action_uid, sent = _page(conn, tenant_id, rows, message, config)
        _settle(conn, tenant_id, rows, "paged" if sent else "failed", action_uid)
        (out.paged if sent else out.failed).append(key)
        out.slack_errors += _mirror(conn, tenant_id, rows, message, config)
    return out


def _settle(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], outcome: str, action_uid: str = ""
) -> None:
    """Record what the gate did, and let the page carry its cases' pending decisions."""
    uids = [str(r["notice_uid"]) for r in rows]
    execute(
        conn,
        """UPDATE shoc.notices SET delivered_at = now(), outcome = %s, delivered_uid = %s
           WHERE tenant_id = %s AND notice_uid = ANY(%s)""",
        (outcome, action_uid or None, tenant_id, uids),
    )
    cases = sorted({str(r["case_uid"]) for r in rows if r["case_uid"]})
    if outcome == "paged" and cases:
        execute(
            conn,
            """UPDATE shoc.notices SET delivered_at = now(), outcome = 'paged',
                                       delivered_uid = %s
               WHERE tenant_id = %s AND kind = 'decision' AND delivered_at IS NULL
                 AND case_uid = ANY(%s)""",
            (action_uid, tenant_id, cases),
        )


def template(rows: list[dict[str, Any]]) -> str:
    """The page that goes out when no model writes one. It must be enough alone."""
    from shoc.cases.engine import SEVERITY_ORDER

    worst = max(
        (str(r["severity"]) for r in rows),
        key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 2,
    )
    cases = sorted({str(r["case_uid"]) for r in rows if r["case_uid"]})
    reasons = sorted({str(r["condition"]).replace("_", " ") for r in rows})
    lines = list(dict.fromkeys(str(r["body"]).strip() for r in rows))
    return (
        f"{worst.upper()} ({', '.join(reasons)}): "
        + " ".join(lines)[:900]
        + (f" Cases: {', '.join(cases)}." if cases else "")
    )


def word(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], config: Any = None, store: Any = None
) -> str:
    """The Manager's wording of one page, or the template when it cannot be trusted."""
    from shoc.agents import roles, safety
    from shoc.agents.llm import NoLLM, complete_typed, for_hint, from_config
    from shoc.agents.ops import charge

    fallback = template(rows)
    try:
        client = from_config(config, conn, tenant_id)
        if isinstance(client, NoLLM) or not getattr(client, "available", True):
            return fallback
        allowed = {
            *(str(r["case_uid"]) for r in rows if r["case_uid"]),
            *(c for r in rows for c in (r["citations"] or [])),
        }
        notices = [
            {
                "from": r["source"],
                "condition": r["condition"],
                "severity": r["severity"],
                "case": r["case_uid"],
                "said": r["body"],
                "citations": list(r["citations"] or []),
            }
            for r in rows
        ]
        said, usage = complete_typed(
            for_hint(client, roles.MANAGER.model_hint, config),
            safety.system_prompt(roles.MANAGER.prompt),
            "The gate has decided to page the operator for this incident. Write "
            "the one message they will read.\n\n" + safety.quote("notices", notices),
            roles.ManagerOutput,
            getattr(config, "llm_max_tokens", 1024) if config else 1024,
        )
        charge(conn, tenant_id, usage)
    except Exception:  # the model is optional; the page is not
        return fallback
    message = (said.message or "").strip()
    cited = set(said.citations or [])
    if not message or len(message) > 1200 or not cited or not cited <= allowed:
        return fallback
    return message


def _page(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], message: str, config: Any
) -> tuple[str, bool]:
    """Send one page through the `notify.page` action, so it is audited like any other."""
    from shoc.cases import actions as action_store
    from shoc.cases.engine import max_severity

    case_uid = next((str(r["case_uid"]) for r in rows if r["case_uid"]), "")
    critical = any(r["severity"] == "critical" for r in rows)
    try:
        row = action_store.propose(
            conn,
            tenant_id,
            action_store.Proposal(
                action_type="notify.page",
                params={
                    "summary": message,
                    "dedup_key": f"shoc:{tenant_id}:{rows[0]['group_key']}"[:255],
                    "severity": "critical" if critical else "error",
                    "details": {"notices": [str(r["notice_uid"]) for r in rows]},
                },
                rationale="; ".join(sorted({str(r["condition"]) for r in rows})),
                case_uid=case_uid or None,
                severity=max_severity([str(r["severity"]) for r in rows]),
            ),
            PRINCIPAL,
            principal_kind="agent",
            config=config,
        )
    except Exception:  # no pager configured, or the policy refuses
        return "", False
    uid = str(row.get("action_uid") or "")
    if str(row.get("state")) == "proposed":
        # Nobody approves a page; one left waiting wakes nobody.
        action_store.reject(conn, tenant_id, uid, PRINCIPAL, "a page that waits wakes nobody")
        return uid, False
    if str(row.get("state")) != "approved":
        return uid, False
    try:
        _done, result = action_store.execute(
            conn,
            tenant_id,
            uid,
            getattr(config, "master_key", "") if config else "",
            by=PRINCIPAL,
        )
    except Exception:
        return uid, False
    return uid, bool(result.ok)


def _mirror(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], message: str, config: Any
) -> list[str]:
    """Put the page in Slack too, with Approve buttons for what its cases wait on."""
    from shoc.cases import actions as action_store

    errors = [say_in_slack(conn, tenant_id, config, text=message)]
    for case_uid in sorted({str(r["case_uid"]) for r in rows if r["case_uid"]}):
        if action_store.listing(conn, tenant_id, "proposed", case_uid):
            errors.append(say_in_slack(conn, tenant_id, config, case_uid=case_uid))
    return [e for e in errors if e]


def say_in_slack(conn: Conn, tenant_id: str, config: Any, **post: str) -> str:
    """Post to the channel as the Manager, through the audited `slack.notify`.

    Returns why Slack refused, or "" when it took the post or no channel is set.
    The audit log holds the error too, so a channel that stopped working shows
    up in `health.audit` and the job's summary, not nowhere.
    """
    from shoc.api import slack
    from shoc.capabilities.registry import Context, call
    from shoc.errors import ShocError

    if config is None:
        return ""
    app = slack.load_app(conn, tenant_id, config.master_key)
    if not app.configured or not app.channel:
        return ""
    try:
        call("slack.notify", Context(tenant_id=tenant_id, caller=CALLER, config=config), dict(post))
    except ShocError as exc:
        return str(exc)
    return ""


def coverage(conn: Conn, tenant_id: str) -> int:
    """Tell the Manager about every source dark long enough to matter (OPS-1).

    Whether it pages is this query. What Ops' model said about the outage
    (`ops.review`), when it is about this outage, goes with it (D47).
    """
    from shoc.agents import ops

    said = {
        str(r["source"]): str(r["diagnosis"])
        for r in fetch_all(
            conn,
            """SELECT source, diagnosis FROM shoc.connector_state
               WHERE tenant_id = %s AND diagnosis <> ''
                 AND (last_ok_at IS NULL OR diagnosed_at > last_ok_at)""",
            (tenant_id,),
        )
    }
    told = 0
    for source in ops.source_health(conn, tenant_id):
        minutes = source.minutes_since
        if not (source.error or source.stale) or minutes is None:
            continue
        if minutes < COVERAGE_DARK_HOURS * 60:
            continue
        tell(
            conn,
            tenant_id,
            "Ops",
            "page",
            # Worded the same all day, so an hourly check tells it once a day.
            f"{source.source} has been dark for more than {COVERAGE_DARK_HOURS}h. "
            "Detections on it are not running, and cases do not see it."
            + (f" Ops: {said[source.source]}" if source.source in said else ""),
            condition="coverage_dark",
            severity="high",
            group_key=f"source:{source.source}",
        )
        told += 1
    return told


def _malicious_uncontained(verdict: Any, severity: Any, contained: Any) -> bool:
    return verdict == "malicious" and severity in ("high", "critical") and not contained


def uncontained(conn: Conn, tenant_id: str, case_uid: str) -> bool:
    """Page for a malicious high or critical case that nothing has contained.

    Called when a malicious verdict is recorded and when a playbook run on the
    case ends. Below critical, a playbook's page step reaches the weekly, and
    `uncontainable_and_active` wants a finding within the hour, so a case that
    dry run or a missing credential left alone woke nobody. Told once per case,
    and delivered after `CONTAIN_WITHIN_MINUTES`; the gate asks again then.
    Returns whether this was news.
    """
    case = fetch_one(
        conn,
        f"""SELECT c.verdict, c.severity, c.state, {CONTAINED} AS contained
            FROM shoc.cases c WHERE c.tenant_id = %s AND c.case_uid = %s""",
        (tenant_id, case_uid),
    )
    if not case or case["state"] == "closed":
        return False
    if not _malicious_uncontained(case["verdict"], case["severity"], case["contained"]):
        return False
    if fetch_one(
        conn,
        """SELECT 1 AS told FROM shoc.notices WHERE tenant_id = %s AND case_uid = %s
             AND condition = 'malicious_uncontained' LIMIT 1""",
        (tenant_id, case_uid),
    ):
        return False
    from shoc.db import jobs

    uid = tell(
        conn,
        tenant_id,
        "shoc",
        "page",
        "This case is malicious and no response action has run on it for real, "
        "so nothing has contained it.",
        case_uid=case_uid,
        condition="malicious_uncontained",
        deliver=False,
    )
    jobs.enqueue(
        conn,
        tenant_id,
        "manager.deliver",
        {},
        # A minute past the hold: with this host's clock a little behind the
        # database's, the job would otherwise come while the gate still holds it.
        run_at=datetime.now(UTC) + timedelta(minutes=CONTAIN_WITHIN_MINUTES + 1),
        idempotency_key=f"deliver:{uid}",
    )
    return True


def audit_broken(conn: Conn, tenant_id: str, detail: str) -> bool:
    """Page once for each new way the audit chain fails to verify (SEC-1).

    `detail` from `verify` stays the same until another row breaks, so the
    hourly check finds the same break every hour and pages for it once.
    Returns whether this was news.
    """
    group = "audit:" + hashlib.sha256(detail.encode()).hexdigest()[:16]
    if fetch_one(
        conn,
        "SELECT 1 AS told FROM shoc.notices WHERE tenant_id = %s AND group_key = %s LIMIT 1",
        (tenant_id, group),
    ):
        return False
    tell(
        conn,
        tenant_id,
        "Ops",
        "page",
        f"The audit log no longer verifies ({detail}). Somebody with write access to "
        "the database changed or removed those rows; compare them with a backup.",
        condition="audit_broken",
        severity="critical",
        group_key=group,
    )
    return True


def scheduler(conn: Conn, tenant_id: str, config: Any = None) -> bool:
    """Page when no worker has ticked the schedule for over an hour (OPS-1).

    `serve` calls this every few minutes. `ops.check` cannot: it is one of the
    schedules that stopped. The page is delivered here rather than queued,
    because no worker may be left to claim the delivery job.
    """
    from shoc.db import jobs

    if not jobs.overdue_schedules(conn, tenant_id):
        return False
    tell(
        conn,
        tenant_id,
        "Ops",
        "page",
        "No shoc worker has run the schedule for over an hour, so detections, "
        "response actions and case work have stopped. Check the worker containers.",
        condition="coverage_dark",
        severity="high",
        group_key="scheduler",
        deliver=False,
    )
    deliver(conn, tenant_id, config)
    return True


# -- questions ---------------------------------------------------------------
@dataclass
class Reply:
    answer: str
    citations: list[str]
    consulted: list[str]


def answer(
    conn: Conn,
    store: Any,
    tenant_id: str,
    question: str,
    config: Any = None,
    history: list[dict[str, str]] | None = None,
    caller: Any = None,
) -> Reply | None:
    """Answer the operator by asking the crew, or None to fall back to the query path.

    A question that names a case, or follows a turn that did, is asked in that
    case, so the peer calls are written to its openspace. Earlier turns reach the
    model as quoted data like the question itself. A question about a case, or
    one that names a key, an address, an account or a finding, is answered only
    with events that survive the store (D25). One about the deployment itself
    (rules, sources, health, cost) is answered from the Manager's lookups and
    needs none, so it is not swapped for a list of findings (D135). Invented
    citations are dropped either way. The Manager and every colleague
    it asks are offered only the tools `caller` may call itself, so a question
    from a client holding `ask:read` cannot end in a proposal (AGT-10, AGT-14).
    """
    from shoc.agents import loop, roles
    from shoc.agents.dossier import build_dossier
    from shoc.agents.llm import NoLLM, from_config
    from shoc.agents.openspace import Budget, Evidence, validate_citations
    from shoc.agents.safety import quote
    from shoc.capabilities.ask import entities_in
    from shoc.capabilities.registry import Caller

    client = from_config(config, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return None
    case_uid, case = "", None
    turns = [
        {"role": str(t.get("role", "")), "text": str(t.get("text", ""))}
        for t in (history or [])[-HISTORY_TURNS:]
    ]
    named = None
    for text in [question, *(t["text"] for t in reversed(turns))]:
        if named := CASE_UID.search(text):
            break
    if named:
        case = fetch_one(
            conn,
            "SELECT * FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, named.group(0)),
        )
        case_uid = named.group(0) if case else ""
    built = build_dossier(conn, store, tenant_id, case) if case else None
    dossier = built.text if built else "No case is named."
    report = loop.RunReport(case_uid=case_uid)
    # Nobody named is the least anybody can be: a client holding `ask:read`.
    on_behalf = caller or Caller(kind="external_agent", id="ask", scopes=("ask:read",))
    peers = loop._Peers(
        conn,
        store,
        tenant_id,
        case_uid,
        report,
        client,
        config,
        dossier,
        Budget.for_severity(str((case or {}).get("severity") or "medium")),
        datetime.now(UTC),
        on_behalf=on_behalf,
    )
    try:
        said, usage = loop._ask(
            client,
            roles.MANAGER,
            f"{dossier}\n\n"
            + (f"The conversation so far:\n{quote('conversation', turns)}\n\n" if turns else "")
            + f"The operator asks:\n{quote('question', question)}\n"
            "Answer in at most four sentences, and cite the events behind anything "
            "you say happened.",
            roles.RemarkOutput,
            config,
            conn,
            tenant_id,
            store,
            ask=peers.ask_for(roles.MANAGER.name),
            on_behalf=on_behalf,
        )
    except Exception:
        return None
    loop._charge(conn, tenant_id, usage)
    # Only what the answer was built from: the case's events and what the
    # Manager's lookups and colleagues returned (SEC-2).
    cited = validate_citations(
        store,
        tenant_id,
        list(said.citations or []),
        Evidence(set(built.evidence_uids if built else []), usage.seen),
    )
    needs_events = case is not None or bool(entities_in(question))
    if not said.body.strip() or (needs_events and not cited):
        return None
    return Reply(
        answer=said.body.strip(),
        citations=cited,
        consulted=sorted({name for (_caller, name, _q) in peers.asked}),
    )
