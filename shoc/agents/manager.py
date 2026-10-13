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
  whether to wake somebody. The gate reads a case's severity as the higher of
  its own and its worst finding's, whatever the Investigator set it to, so a
  model misled by log content can change a page's wording and the case's
  display severity, and cannot lower a page below what its findings say.
- **The model writes the text.** If there is no model, it fails, takes longer
  than `WORDING_SECONDS`, or cites something the group does not contain, a
  fixed template goes out instead. Either way the page opens with its severity,
  conditions and cases, which no model writes. A page is never late because of
  the model.
- **A page is delivered when anybody could read it.** PagerDuty, the Slack
  channel, or failing the pager an email to every enabled admin and operator.
  When none took it and the pager failed on the way, it is tried again
  (`RETRY_MINUTES`); a pager nobody configured is not waited for.
- **Questions come back through here too.** `ask` hands the Manager the
  question, and it answers by calling the colleague who knows. Without a model
  `ask` answers the way it always did.

The Manager does not assign work, close cases, change verdicts or approve
anything. Approvals and injected facts stay direct capabilities, so a broken
Manager cannot stand between a person and a decision.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import psycopg

from shoc.capabilities.registry import Caller
from shoc.cases.engine import CONTAINED, FLOORED
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

# A source dark this long is material: a day of an identity provider is a day of
# logins nobody saw.
COVERAGE_DARK_HOURS = 24

# A page no channel took, after the pager failed on the way (a 5xx, a timeout),
# is tried again this many minutes later, then settled as failed. A pager
# nobody configured, or a page the policy refuses, is settled at once.
RETRY_MINUTES = (1, 5, 15)

# How long the model may take to word a page. The client retries a slow
# provider for minutes, and the template is enough alone.
WORDING_SECONDS = 20

CASE_UID = re.compile(r"\bCASE-[0-9a-f]{20}\b")

# How many earlier turns of a conversation `ask` hands the Manager.
HISTORY_TURNS = 12

# How long `ask` keeps looking things up, its colleagues included, before it
# answers: inside the minute an HTTP or MCP client waits, so the server does
# not go on working for a caller that gave up. Every model call of the answer,
# its colleagues' and its own last one included, gives up `ANSWER_SECONDS`
# after that (`llm.limit`), so `ask` answers within about a minute.
ASK_SECONDS = 45
ANSWER_SECONDS = 15

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
        # A page about a case says its worst finding's severity, whatever a
        # model lowered the case to (ai-3).
        case = (
            fetch_one(
                conn,
                f"""SELECT {FLOORED} AS severity, c.entity_key FROM shoc.cases c
                    WHERE c.tenant_id = %s AND c.case_uid = %s""",
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
    # Incidents whose page no channel took this time, to be tried again.
    retrying: list[str] = field(default_factory=list)
    # Why a Slack copy of a page did not go out. The page may still have.
    slack_errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not (self.paged or self.merged or self.digest or self.failed or self.retrying):
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
        if self.retrying:
            parts.append(f"{len(self.retrying)} page(s) to be tried again")
        if self.slack_errors:
            parts.append(f"Slack refused {len(self.slack_errors)} post(s): {self.slack_errors[0]}")
        return "manager: " + ", ".join(parts)


def deliver(conn: Conn, tenant_id: str, config: Any = None, store: Any = None) -> Delivered:
    """Run the gate over every undelivered page notice, one page per incident."""
    out = Delivered()
    pending = fetch_all(
        conn,
        f"""SELECT n.*, {FLOORED} AS case_severity, c.state AS case_state,
                   c.closed_by AS case_closed_by,
                   c.verdict AS case_verdict, {CONTAINED} AS case_contained,
                   n.created_at > now() - %s * interval '1 minute' AS held,
                   (SELECT max(f.last_seen) FROM shoc.findings f
                     WHERE f.tenant_id = n.tenant_id AND f.case_uid = n.case_uid) AS case_last_seen
            FROM shoc.notices n
            LEFT JOIN shoc.cases c ON c.tenant_id = n.tenant_id AND c.case_uid = n.case_uid
            WHERE n.tenant_id = %s AND n.kind = 'page' AND n.delivered_at IS NULL
              AND (n.retry_at IS NULL OR n.retry_at <= now())
            ORDER BY n.created_at LIMIT 200""",
        (CONTAIN_WITHIN_MINUTES, tenant_id),
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    fresh = datetime.now(UTC) - timedelta(hours=ACTIVE_WITHIN_HOURS)
    for row in pending:
        # "Critical" is the case's severity now, not what somebody said it was,
        # and never below its worst finding's: a model lowering the case does
        # not lower the page (ai-3); a closed case wakes nobody; "still active"
        # means a detection fired within the hour, not that a model said so;
        # and "uncontained" is the case's verdict, severity and actions now.
        # These are queries, so log content can change none of them (RFC 0015).
        # The crew closing a malicious case contains nothing: it often closes
        # in the run that recorded the verdict, inside the hold, so only a
        # person's close settles that page.
        containment = row["condition"] == "malicious_uncontained"
        stale = (
            (row["condition"] == "critical_severity" and row["case_severity"] != "critical")
            or (row["case_uid"] and row["case_state"] == "closed" and not containment)
            or (
                row["condition"] == "uncontainable_and_active"
                and not (row["case_last_seen"] and row["case_last_seen"] >= fresh)
            )
            or (
                containment
                and (
                    row["case_closed_by"] == "human"
                    or not _malicious_uncontained(
                        row["case_verdict"], row["case_severity"], row["case_contained"]
                    )
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
            _settle(conn, tenant_id, rows, "merged", str(earlier["delivered_uid"] or ""))
            out.merged += len(rows)
            continue
        message = word(conn, tenant_id, rows, config, store)
        action_uid, error, transient = _page(conn, tenant_id, rows, message, config)
        slack_errors, in_slack = _mirror(conn, tenant_id, rows, message, config)
        out.slack_errors += slack_errors
        mailed = False
        if error:
            mailed, mail_error = _mail(conn, tenant_id, message, config)
            error = "; ".join(e for e in (error, mail_error) if e)
        tried = max(int(r["attempts"] or 0) for r in rows)
        if not error or in_slack or mailed:
            _settle(conn, tenant_id, rows, "paged", action_uid, error)
            out.paged.append(key)
        elif transient and tried < len(RETRY_MINUTES):
            _again(conn, tenant_id, rows, error, RETRY_MINUTES[tried])
            out.retrying.append(key)
        else:
            _settle(conn, tenant_id, rows, "failed", action_uid, error)
            out.failed.append(key)
    return out


def _settle(
    conn: Conn,
    tenant_id: str,
    rows: list[dict[str, Any]],
    outcome: str,
    action_uid: str = "",
    error: str = "",
) -> None:
    """Record what the gate did, and let the page carry its cases' pending decisions.

    `error` is why a channel did not take the page, kept even when another did.
    """
    uids = [str(r["notice_uid"]) for r in rows]
    execute(
        conn,
        """UPDATE shoc.notices SET delivered_at = now(), outcome = %s, delivered_uid = %s,
                  last_error = coalesce(%s, last_error),
                  attempts = attempts + %s
           WHERE tenant_id = %s AND notice_uid = ANY(%s)""",
        (
            outcome,
            action_uid or None,
            error[:2000] or None,
            int(outcome in ("paged", "failed")),
            tenant_id,
            uids,
        ),
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


def _again(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], error: str, minutes: int
) -> None:
    """Leave the notices undelivered and come back for them in `minutes` (RSP-4).

    The job runs at the database's `retry_at`, so a host clock behind it cannot
    bring the job before the gate would take the notices. It is keyed on that
    time too: the group's notices can each have tried a different number of times.
    """
    from shoc.db import jobs

    uids = [str(r["notice_uid"]) for r in rows]
    row = fetch_one(
        conn,
        """UPDATE shoc.notices SET attempts = attempts + 1, last_error = %s,
                  retry_at = now() + %s * interval '1 minute'
           WHERE tenant_id = %s AND notice_uid = ANY(%s)
           RETURNING retry_at""",
        (error[:2000], minutes, tenant_id, uids),
    )
    if row:
        jobs.enqueue(
            conn,
            tenant_id,
            "manager.deliver",
            {},
            run_at=row["retry_at"],
            idempotency_key=f"deliver:{uids[0]}@{row['retry_at'].isoformat()}",
        )


def _head(rows: list[dict[str, Any]]) -> str:
    """What every page opens with, whoever words the rest: how bad, why, which cases."""
    from shoc.cases.engine import SEVERITY_ORDER

    worst = max(
        (str(r["severity"]) for r in rows),
        key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 2,
    )
    cases = sorted({str(r["case_uid"]) for r in rows if r["case_uid"]})
    reasons = sorted({str(r["condition"]).replace("_", " ") for r in rows})
    return f"{worst.upper()} ({', '.join(reasons)})" + (f" {', '.join(cases)}" if cases else "")


def template(rows: list[dict[str, Any]]) -> str:
    """The page that goes out when no model writes one. It must be enough alone."""
    lines = list(dict.fromkeys(str(r["body"]).strip() for r in rows))
    return f"{_head(rows)}: " + " ".join(lines)[:900]


def word(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], config: Any = None, store: Any = None
) -> str:
    """The Manager's wording of one page, or the template when it cannot be trusted."""
    from shoc.agents import roles, safety
    from shoc.agents.llm import NoLLM, complete_typed, for_hint, from_config
    from shoc.agents.ops import charge, record_failure

    fallback = template(rows)
    client: Any = None
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
        # Bounded on every try, so a stalled provider costs the page
        # `WORDING_SECONDS` and no call is left running behind it.
        said, usage = complete_typed(
            for_hint(client, roles.MANAGER.model_hint, config),
            safety.system_prompt(roles.MANAGER.prompt),
            "The gate has decided to page the operator for this incident. Write "
            "the one message they will read.\n\n" + safety.quote("notices", notices),
            roles.ManagerOutput,
            getattr(config, "llm_max_tokens", 1024) if config else 1024,
            timeout=WORDING_SECONDS,
        )
        charge(conn, tenant_id, usage)
    except Exception as exc:  # the model is optional; the page is not
        # Running out of `WORDING_SECONDS` is shoc's own cut-off, not the
        # provider failing: counted, it stood the case sweep down (ai-4).
        if client is not None and not isinstance(exc, TimeoutError | httpx.TimeoutException):
            with contextlib.suppress(Exception):
                record_failure(
                    conn,
                    tenant_id,
                    getattr(client, "model", "none"),
                    f"Manager: {type(exc).__name__}: {exc}",
                )
        return fallback
    message = (said.message or "").strip()
    cited = set(said.citations or [])
    if not message or len(message) > 1200 or not cited or not cited <= allowed:
        return fallback
    # Log content can steer the wording, so it never decides how the page opens.
    return f"{_head(rows)}: {message}"


def _page(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], message: str, config: Any
) -> tuple[str, str, bool]:
    """Send one page through the `notify.page` action, so it is audited like any other.

    Returns the action, why the page did not go out ("" when it did), and
    whether trying again could change that: a failed post can, a missing pager,
    a credential that is not complete or the policy's refusal cannot. A page
    changes nothing in the company's systems, so it is proposed with dry run
    off whatever SHOC_DRY_RUN says, and its record says it was sent for real
    (RSP-4, RSP-7).
    """
    from shoc.cases import actions as action_store
    from shoc.cases import credentials
    from shoc.cases.engine import max_severity
    from shoc.config import Config
    from shoc.errors import ConfigError

    if not credentials.instances(conn, tenant_id, "notify"):
        return "", "no pager is configured: set a notify credential", False
    cfg = config if config is not None else Config.load()
    live = replace(cfg, dry_run=False) if isinstance(cfg, Config) else cfg
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
            config=live,
        )
    except Exception as exc:  # the policy refuses
        return "", f"the policy refused the page: {exc}"[:500], False
    uid = str(row.get("action_uid") or "")
    if str(row.get("state")) == "proposed":
        # Nobody approves a page; one left waiting wakes nobody.
        action_store.reject(conn, tenant_id, uid, PRINCIPAL, "a page that waits wakes nobody")
        return uid, "the policy wants the page approved", False
    if str(row.get("state")) != "approved":
        return uid, f"the page is {row.get('state')}", False
    try:
        _done, result = action_store.execute(
            conn,
            tenant_id,
            uid,
            getattr(config, "master_key", "") if config else "",
            by=PRINCIPAL,
        )
    except Exception as exc:
        return uid, f"{type(exc).__name__}: {exc}"[:500], not isinstance(exc, ConfigError)
    if result.dry_run:
        return uid, "the page was only a dry run", False
    if not result.ok:
        # `execute` keeps the exception's name: a ConfigError (no routing key,
        # a region PagerDuty does not have) is the same on every try.
        return uid, result.detail[:500], "ConfigError" not in result.detail
    return uid, "", True


def _mirror(
    conn: Conn, tenant_id: str, rows: list[dict[str, Any]], message: str, config: Any
) -> tuple[list[str], bool]:
    """Put the page in Slack too, with Approve buttons for what its cases wait on.

    Returns why Slack refused posts, and whether the page itself reached a channel.
    """
    from shoc.api import slack
    from shoc.cases import actions as action_store

    if config is None:
        return [], False
    app = slack.load_app(conn, tenant_id, config.master_key)
    if not app.configured or not app.channel:
        return [], False
    errors = [say_in_slack(conn, tenant_id, config, text=message)]
    for case_uid in sorted({str(r["case_uid"]) for r in rows if r["case_uid"]}):
        if action_store.listing(conn, tenant_id, "proposed", case_uid):
            errors.append(say_in_slack(conn, tenant_id, config, case_uid=case_uid))
    return [e for e in errors if e], not errors[0]


def _mail(conn: Conn, tenant_id: str, message: str, config: Any) -> tuple[bool, str]:
    """Email a page the pager did not take to every enabled admin and operator
    who has signed in once: a mistyped invitation never reads case titles.

    Sent before the gate settles, so it knows whether anybody got it. Audited
    as the Manager, like the page. Returns whether one mail went out, and why
    any did not.
    """
    from shoc import mail
    from shoc.db import audit

    if config is None or not mail.configured(config):
        return False, ""
    to = _mail_to(conn, tenant_id)
    if not to:
        return False, "no enabled admin or operator who has signed in to email"
    subject, body = mail.page(config, message)
    sent: list[str] = []
    errors: list[str] = []
    for address in to:
        try:
            mail.send(config, address, subject, body)
            sent.append(address)
        except Exception as exc:
            errors.append(f"{address}: {type(exc).__name__}: {exc}")
    problem = "; ".join(errors)[:500]
    audit.append(
        conn,
        tenant_id,
        "agent",
        PRINCIPAL,
        "notify.mail",
        audit.hash_payload({"to": to, "message": message}),
        audit.hash_payload({"sent": sent}) if sent else None,
        problem or None,
    )
    return bool(sent), problem


def _mail_to(conn: Conn, tenant_id: str) -> list[str]:
    return [
        str(r["email"])
        for r in fetch_all(
            conn,
            """SELECT email FROM shoc.users WHERE tenant_id = %s AND disabled_at IS NULL
                 AND role IN ('admin', 'operator')
                 AND (password_hash IS NOT NULL OR sso_subject IS NOT NULL)
               ORDER BY email""",
            (tenant_id,),
        )
    ]


def reachable(conn: Conn, tenant_id: str, config: Any = None) -> dict[str, bool]:
    """The ways shoc has to reach a person now (OPS-1, RSP-4).

    A pager, a Slack channel, mail to an admin or operator who has signed in,
    and a webhook a monitor reads. With none of them every page, exception
    report and weekly is built, kept and read by nobody, while each job says it
    ran. `say_in_slack` still answers "" with no channel; this is the check.
    """
    from shoc import mail
    from shoc.api import slack
    from shoc.cases import credentials
    from shoc.config import Config

    cfg = config if config is not None else Config.load()
    try:
        app = slack.load_app(conn, tenant_id, cfg.master_key)
        in_slack = bool(app.configured and app.channel)
    except Exception:  # a secret this key cannot open posts nothing either
        in_slack = False
    in_mail = mail.configured(cfg)
    if in_mail:
        # The agents' read-only role cannot read shoc.users (D22); the server
        # being set is then the most it can tell.
        with contextlib.suppress(psycopg.errors.InsufficientPrivilege):
            in_mail = bool(_mail_to(conn, tenant_id))
    return {
        "pager": bool(credentials.instances(conn, tenant_id, "notify")),
        "slack": in_slack,
        "mail": in_mail,
        # A hook filtered to other types never carries the weekly or exceptions.
        "webhook": bool(
            fetch_one(
                conn,
                """SELECT 1 AS hooked FROM shoc.webhooks
                   WHERE tenant_id = %s AND enabled
                     AND (cardinality(types) = 0 OR 'report.ready' = ANY(types))
                   LIMIT 1""",
                (tenant_id,),
            )
        ),
    }


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


def coverage(conn: Conn, tenant_id: str, config: Any = None) -> int:
    """Tell the Manager about every source dark long enough to matter, about
    detection that stopped, about a disk about to stop everything, and about a
    model that stopped answering (OPS-1).

    Whether it pages is this query. What Ops' model said about the outage
    (`ops.review`), when it is about this outage, goes with it (D47). A source
    that never succeeded is dark since it was set up: a wrong credential on day
    one is the worst state a connector can be in, and it used to page never.
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
    set_up = {
        str(r["source"]): r["created_at"]
        for r in fetch_all(
            conn,
            "SELECT source, created_at FROM shoc.connector_config WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    told = 0
    for source in ops.source_health(conn, tenant_id):
        if not (source.error or source.stale):
            continue
        minutes = source.minutes_since
        # Worded the same all day, so an hourly check tells it once a day.
        dark = f"{source.source} has been dark for more than {COVERAGE_DARK_HOURS}h."
        if minutes is None:
            if source.source not in set_up:
                continue
            minutes = (datetime.now(UTC) - set_up[source.source]).total_seconds() / 60
            dark = (
                f"{source.source} has never succeeded since it was set up, "
                f"over {COVERAGE_DARK_HOURS}h ago."
            )
        if minutes < COVERAGE_DARK_HOURS * 60:
            continue
        tell(
            conn,
            tenant_id,
            "Ops",
            "page",
            f"{dark} Detections on it are not running, and cases do not see it."
            + (f" Ops: {said[source.source]}" if source.source in said else ""),
            condition="coverage_dark",
            severity="high",
            group_key=f"source:{source.source}",
        )
        told += 1
    return (
        told
        + _detection_stopped(conn, tenant_id)
        + _disk_full(conn, tenant_id, config)
        + _model_dark(conn, tenant_id)
    )


# What a provider that refuses every call is telling the operator to fix.
REFUSED = {"401": "rejected the API key", "402": "says the credit is spent", "403": "refused"}


def _model_dark(conn: Conn, tenant_id: str) -> int:
    """Page when no model call has come back for hours, or the provider refuses
    the key or the credit (ai-4).

    Ops' own model cannot diagnose it, the sweep stands down and `unattended`
    holds the cases nobody read, so this one page names the cause instead of a
    page per case. Worded the same while it lasts, so an hourly check tells it
    once a day.
    """
    from shoc.agents import ops

    down = ops.model_down(conn, tenant_id)
    if not down:
        return 0
    since = f"{down['since']:%Y-%m-%d %H:%M} UTC" if down["since"] else "it was set up"
    why = (
        f"The model provider {REFUSED[down['status']]} (HTTP {down['status']})"
        if down["status"]
        else "The model provider has failed every call"
    )
    tell(
        conn,
        tenant_id,
        "Ops",
        "page",
        f"{why}; no model call has come back since {since}. No case is investigated and "
        "no hunt or report is read until it does: fix the key or the credit (llm.configure).",
        condition="coverage_dark",
        severity="high",
        group_key="llm",
    )
    return 1


def _disk_full(conn: Conn, tenant_id: str, config: Any = None) -> int:
    """Page while Postgres is past `ops.DISK_PAGE` of SHOC_DISK_BUDGET_GB.

    On a full disk Postgres refuses writes, the notice a page is sent from
    included, so this is the last page that can still be written.
    """
    from shoc.agents import ops

    if not getattr(config, "disk_budget_gb", 0):
        return 0
    room = ops.disk(conn, config)
    if room["used"] < ops.DISK_PAGE:
        return 0
    tell(
        conn,
        tenant_id,
        "Ops",
        "page",
        # Worded the same all day, so an hourly check tells it once a day.
        f"The database is past {ops.DISK_PAGE:.0%} of SHOC_DISK_BUDGET_GB "
        f"({room['budget_gb']:g} GB). On a full disk Postgres refuses every write and "
        "shoc stops: grow the disk, lower SHOC_RETENTION_DAYS or move events to a warehouse.",
        condition="coverage_dark",
        severity="high",
        group_key="store:size",
    )
    return 1


def _detection_stopped(conn: Conn, tenant_id: str) -> int:
    """Page when no detection run has finished in three cycles, an hour at least.

    Sources can load while every `detect.run` fails: on a bug, a statement
    timeout, or a store that takes writes and refuses reads. Only dark sources
    paged, so rules could stop for weeks with nothing but a stream alert.
    A tenant with no enabled source, or whose first run is younger than the
    window, has nothing to say yet; a schedule nobody ticks is `scheduler`'s.
    """
    row = fetch_one(
        conn,
        """WITH s AS (
               SELECT tenant_id, greatest(3 * interval_seconds, 3600) AS seconds
               FROM shoc.schedules
               WHERE tenant_id = %s AND kind = 'detect.run' AND enabled LIMIT 1)
           SELECT s.seconds,
                  (SELECT j.last_error FROM shoc.jobs j
                    WHERE j.tenant_id = s.tenant_id AND j.kind = 'detect.run'
                      AND j.last_error IS NOT NULL
                    ORDER BY j.job_id DESC LIMIT 1) AS error
           FROM s
           WHERE EXISTS (SELECT 1 FROM shoc.connector_config c
                          WHERE c.tenant_id = s.tenant_id AND c.enabled
                            AND c.source NOT IN ('slack', 'llm'))
             AND EXISTS (SELECT 1 FROM shoc.jobs j
                          WHERE j.tenant_id = s.tenant_id AND j.kind = 'detect.run'
                            AND j.created_at < now() - s.seconds * interval '1 second')
             AND NOT EXISTS (SELECT 1 FROM shoc.jobs j
                              WHERE j.tenant_id = s.tenant_id AND j.kind = 'detect.run'
                                AND j.state = 'done'
                                AND j.finished_at > now() - s.seconds * interval '1 second')""",
        (tenant_id,),
    )
    if not row:
        return 0
    error = " ".join(str(row["error"] or "").split())[:300]
    tell(
        conn,
        tenant_id,
        "Ops",
        "page",
        f"No detection run has finished for over {int(row['seconds']) // 3600}h, so no rule "
        "has read the events that arrived since."
        + (f" The last run failed with: {error}" if error else ""),
        condition="coverage_dark",
        severity="high",
        group_key="detection",
    )
    return 1


def _malicious_uncontained(verdict: Any, severity: Any, contained: Any) -> bool:
    return verdict == "malicious" and severity in ("high", "critical") and not contained


def uncontained(conn: Conn, tenant_id: str, case_uid: str) -> bool:
    """Page for a malicious high or critical case that nothing has contained.

    Called when a malicious verdict is recorded and when a playbook run on the
    case ends. Below critical, a playbook's page step reaches the weekly, and
    `uncontainable_and_active` wants a finding within the hour, so a case that
    dry run or a missing credential left alone woke nobody. Told once per case,
    or again when that page failed, and delivered after `CONTAIN_WITHIN_MINUTES`;
    the gate asks again then.
    Returns whether this was news.
    """
    case = fetch_one(
        conn,
        f"""SELECT c.verdict, {FLOORED} AS severity, c.state, {CONTAINED} AS contained
            FROM shoc.cases c WHERE c.tenant_id = %s AND c.case_uid = %s""",
        (tenant_id, case_uid),
    )
    if not case or case["state"] == "closed":
        return False
    if not _malicious_uncontained(case["verdict"], case["severity"], case["contained"]):
        return False
    if fetch_one(
        conn,
        # A page that could not be sent is not a page told.
        """SELECT 1 AS told FROM shoc.notices WHERE tenant_id = %s AND case_uid = %s
             AND condition = 'malicious_uncontained' AND outcome IS DISTINCT FROM 'failed'
           LIMIT 1""",
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
    # The same day it is the same row, so the one that failed is opened again
    # and sent again, with its own retries.
    execute(
        conn,
        """UPDATE shoc.notices SET delivered_at = NULL, outcome = NULL, retry_at = NULL,
                  attempts = 0
           WHERE tenant_id = %s AND notice_uid = %s AND outcome = 'failed'""",
        (tenant_id, uid),
    )
    # A minute past the hold: with this host's clock a little behind the
    # database's, the job would otherwise come while the gate still holds it.
    run_at = datetime.now(UTC) + timedelta(minutes=CONTAIN_WITHIN_MINUTES + 1)
    jobs.enqueue(
        conn,
        tenant_id,
        "manager.deliver",
        {},
        run_at=run_at,
        idempotency_key=f"deliver:{uid}@{run_at.isoformat()}",
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
    from shoc.agents.llm import NoLLM, from_config, limit
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
    # Started, so the Manager's own turn stops at the budget's time as its peers do.
    started = datetime.now(UTC)
    report = loop.RunReport(case_uid=case_uid, started=started)
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
        replace(
            Budget.for_severity(str((case or {}).get("severity") or "medium")),
            max_seconds=ASK_SECONDS,
        ),
        started,
        on_behalf=on_behalf,
    )
    left = ASK_SECONDS - (datetime.now(UTC) - started).total_seconds()
    try:
        with limit(left + ANSWER_SECONDS):
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
                # Its own turn and the colleagues it asks share one budget (OPS-1).
                budget=loop._turn(report, peers.budget, 0.5),
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
