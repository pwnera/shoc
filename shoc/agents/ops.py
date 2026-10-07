"""Operations: is the pipeline actually working, and what is it costing? (OPS-1)

Ops is the SRE of the SOC, and it believes a detection you are not ingesting for
is worse than no detection, because it looks like coverage. Four things, all
queries and none of them a model's job:

- **Freshness.** A source silent beyond its own interval is an outage, not a
  quiet day.
- **Quality.** Freshness is not enough. DeTT&CT exists because coverage claims
  are usually lies, so a source is scored on completeness, retention,
  timeliness and field fidelity — a rule keyed on a field that is null half the
  time is not a detection, and until now nothing would have told us.
- **The metrics.** MTTD and MTTR per incident type, split into time to triage,
  contain and close, plus the false-positive rate by rule. Per type, because an
  aggregate hides everything.
- **Spend, and anything stuck.** An approval nobody answered is an incident
  that is still running.

This is what the Ops role acts on and what the Manager writes up.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one

# Rough per-million-token prices, only for a running estimate. Override with
# SHOC_LLM_PRICE_IN / SHOC_LLM_PRICE_OUT when yours differ.
DEFAULT_PRICES = {
    "claude-opus-5": (15.0, 75.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (0.8, 4.0),
    "gpt-4o-mini": (0.15, 0.6),
    "scripted": (0.0, 0.0),
    "none": (0.0, 0.0),
}


def price_for(model: str) -> tuple[float, float] | None:
    """USD per million tokens in and out, or None for a model nobody priced."""
    import os

    override_in = os.environ.get("SHOC_LLM_PRICE_IN")
    override_out = os.environ.get("SHOC_LLM_PRICE_OUT")
    if override_in and override_out:
        return float(override_in), float(override_out)
    for name, price in DEFAULT_PRICES.items():
        if model.startswith(name):
            return price
    return None


def record_spend(conn: Conn, tenant_id: str, model: str, tokens_in: int, tokens_out: int) -> float:
    """Add one model call to today's running total. Returns the estimated cost;
    an unpriced model counts $0 here and is an Ops alert (`cost.unpriced`)."""
    price_in, price_out = price_for(model or "none") or (0.0, 0.0)
    usd = (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out
    execute(
        conn,
        """INSERT INTO shoc.llm_spend (tenant_id, day, model, calls, tokens_in, tokens_out, usd)
           VALUES (%s, current_date, %s, 1, %s, %s, %s)
           ON CONFLICT (tenant_id, day, model) DO UPDATE SET
               calls = shoc.llm_spend.calls + 1,
               tokens_in = shoc.llm_spend.tokens_in + EXCLUDED.tokens_in,
               tokens_out = shoc.llm_spend.tokens_out + EXCLUDED.tokens_out,
               usd = shoc.llm_spend.usd + EXCLUDED.usd""",
        (tenant_id, model or "none", tokens_in, tokens_out, round(usd, 6)),
    )
    return usd


def charge(conn: Conn, tenant_id: str, completion: Any) -> None:
    """Record one model call's spend. Accounting never breaks the work."""
    with contextlib.suppress(Exception):
        record_spend(conn, tenant_id, completion.model, completion.tokens_in, completion.tokens_out)


def record_failure(conn: Conn, tenant_id: str, model: str, reason: str) -> None:
    """Count one model call that did not come back, with what it said (OPS-1).

    A failure costs nothing and so records no tokens; without this row a dead
    provider is invisible, which is how a critical case sat unworked for hours.
    """
    execute(
        conn,
        """INSERT INTO shoc.llm_spend
             (tenant_id, day, model, calls, failures, last_error, last_error_at)
           VALUES (%s, current_date, %s, 0, 1, %s, now())
           ON CONFLICT (tenant_id, day, model) DO UPDATE SET
               failures = shoc.llm_spend.failures + 1,
               last_error = EXCLUDED.last_error,
               last_error_at = EXCLUDED.last_error_at""",
        (tenant_id, model or "none", reason[:500]),
    )


@dataclass
class SourceHealth:
    source: str
    last_ok_at: datetime | None = None
    minutes_since: float | None = None
    stale: bool = False
    error: str | None = None
    events_seen: int = 0


def source_health(conn: Conn, tenant_id: str, stale_after_minutes: int = 60) -> list[SourceHealth]:
    rows = fetch_all(
        conn,
        """SELECT s.source, s.last_ok_at, s.last_error, s.events_seen, c.interval_seconds
           FROM shoc.connector_state s
           LEFT JOIN shoc.connector_config c
             ON c.tenant_id = s.tenant_id AND c.source = s.source
           -- A disabled source is not polled, so it is not late either.
           WHERE s.tenant_id = %s AND c.enabled IS NOT FALSE ORDER BY s.source""",
        (tenant_id,),
    )
    now = datetime.now(UTC)
    out = []
    for row in rows:
        # A source is late when it has missed several of its own cycles, not on
        # a fixed clock: a five-minute connector and a daily one differ.
        window = max(stale_after_minutes, int((row["interval_seconds"] or 300) * 3 / 60))
        minutes = ((now - row["last_ok_at"]).total_seconds() / 60) if row["last_ok_at"] else None
        out.append(
            SourceHealth(
                source=row["source"],
                last_ok_at=row["last_ok_at"],
                minutes_since=round(minutes, 1) if minutes is not None else None,
                stale=minutes is None or minutes > window,
                error=row["last_error"],
                events_seen=int(row["events_seen"] or 0),
            )
        )
    return out


@dataclass
class RuleHealth:
    """One rule, measured from what its cases were closed as (AGT-3, D77).

    Findings marked `suppressed` or `self` are counted apart and never as noise:
    the first are a benign activity already answered, the second shoc's own
    credentials at work. The verdict counts are over closed cases in 30 days,
    and `tokens_30d` is the crew's spend on those cases, split across the rules
    that shared each one.
    """

    rule_id: str
    findings_7d: int = 0
    cases_7d: int = 0
    suppressed_7d: int = 0
    self_7d: int = 0
    false_positives_7d: int = 0
    closed_30d: dict[str, int] = field(default_factory=dict)
    tokens_30d: int = 0
    last_fired: datetime | None = None
    error: str | None = None
    noisy: bool = False
    silent: bool = False
    silent_reason: str = ""


VERDICT_COUNTS = ("malicious", "suspicious", "benign_expected", "false_positive", "needs_human")


def rule_health(
    conn: Conn,
    tenant_id: str,
    noisy_threshold: int = 25,
    silent_days: int = 30,
    config: Any = None,
    store: Any = None,
) -> list[RuleHealth]:
    """Every loaded rule's health. With the store, a silent rule says why."""
    from shoc.detect import rules as ruleset

    loaded = {r.id: r for r in ruleset.load(config, conn, tenant_id)}
    states = {
        str(r["rule_id"]): r
        for r in fetch_all(
            conn,
            "SELECT rule_id, last_error FROM shoc.rule_state WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    ids = sorted(set(loaded) | {i for i in states if not i.startswith(("hunt:", "ioc"))})
    rows = {
        str(r["rule_id"]): r
        for r in fetch_all(
            conn,
            """WITH c AS (
                   SELECT case_uid, verdict, state, closed_at FROM shoc.cases
                   WHERE tenant_id = %(t)s)
               SELECT f.rule_id,
                 count(*) FILTER (WHERE f.last_seen > now() - interval '7 days'
                                  AND f.status NOT IN ('suppressed', 'self')) AS findings,
                 count(DISTINCT f.case_uid) FILTER (
                     WHERE f.last_seen > now() - interval '7 days') AS cases,
                 count(*) FILTER (WHERE f.last_seen > now() - interval '7 days'
                                  AND f.status = 'suppressed') AS suppressed,
                 count(*) FILTER (WHERE f.last_seen > now() - interval '7 days'
                                  AND f.status = 'self') AS own,
                 count(DISTINCT f.case_uid) FILTER (
                     WHERE c.verdict = 'false_positive' AND c.state = 'closed'
                       AND c.closed_at > now() - interval '7 days') AS fp7,
                 max(f.last_seen) FILTER (WHERE f.status NOT IN ('self')) AS last_fired
               FROM shoc.findings f LEFT JOIN c ON c.case_uid = f.case_uid
               WHERE f.tenant_id = %(t)s AND f.rule_id = ANY(%(ids)s)
               GROUP BY f.rule_id""",
            {"t": tenant_id, "ids": ids},
        )
    }
    closed: dict[str, dict[str, int]] = {}
    tokens: dict[str, int] = {}
    for r in fetch_all(
        conn,
        """WITH pairs AS (
               SELECT DISTINCT f.rule_id, c.case_uid, c.verdict, c.tokens_used
               FROM shoc.findings f JOIN shoc.cases c
                 ON c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid
               WHERE f.tenant_id = %(t)s AND f.rule_id = ANY(%(ids)s)
                 AND c.state = 'closed' AND c.closed_at > now() - interval '30 days'),
           shared AS (SELECT case_uid, count(*) AS rules FROM pairs GROUP BY case_uid)
           SELECT p.rule_id, p.verdict, count(*) AS n,
                  sum(p.tokens_used / s.rules)::bigint AS tokens
           FROM pairs p JOIN shared s ON s.case_uid = p.case_uid
           GROUP BY p.rule_id, p.verdict""",
        {"t": tenant_id, "ids": ids},
    ):
        rule_id = str(r["rule_id"])
        closed.setdefault(rule_id, {})[str(r["verdict"])] = int(r["n"])
        tokens[rule_id] = tokens.get(rule_id, 0) + int(r["tokens"] or 0)
    now = datetime.now(UTC)
    out = []
    for rule_id in ids:
        row = rows.get(rule_id, {})
        last = row.get("last_fired")
        findings = int(row.get("findings") or 0)
        out.append(
            RuleHealth(
                rule_id=rule_id,
                findings_7d=findings,
                cases_7d=int(row.get("cases") or 0),
                suppressed_7d=int(row.get("suppressed") or 0),
                self_7d=int(row.get("own") or 0),
                false_positives_7d=int(row.get("fp7") or 0),
                closed_30d=closed.get(rule_id, {}),
                tokens_30d=tokens.get(rule_id, 0),
                last_fired=last,
                error=(states.get(rule_id) or {}).get("last_error"),
                noisy=findings >= noisy_threshold,
                silent=last is None or (now - last) > timedelta(days=silent_days),
            )
        )
    out.sort(key=lambda h: (-h.findings_7d, h.rule_id))
    if store is not None:
        silent = [h for h in out if h.silent and h.rule_id in loaded]
        for h, why in zip(
            silent,
            silent_reasons(conn, store, tenant_id, [loaded[h.rule_id] for h in silent]),
            strict=True,
        ):
            h.silent_reason = why
    return out


def silent_reasons(conn: Conn, store: Any, tenant_id: str, rules: list[Any]) -> list[str]:
    """Why each silent rule is silent (AGT-3, ING-3): silent is not healthy.

    `not_ingested`  no connected product delivers what the rule reads;
    `field_empty:<f>` a column it needs is empty in most of the product's events
                    (the Integrator's classifier, `integrator.coverage`);
    `value_absent:<v>` none of the operations it selects appears in the
                    product's last 30 days, so it is looking for a name the
                    vendor does not send;
    `quiet`         it could fire and has not.
    """
    from shoc.store import ocsf as layout

    if not rules:
        return []
    quality = {q.product: q for q in source_quality(conn, store, tenant_id)}
    seen_ops: dict[str, set[str]] = {}
    out: list[str] = []
    for rule in rules:
        products = [
            p
            for p in layout.products_for(
                str(rule.logsource.get("product", "")), str(rule.logsource.get("service", ""))
            )
            if p in quality and quality[p].events
        ]
        if not products:
            out.append("not_ingested")
            continue
        blind = next(
            (
                col
                for p in products
                for col, readers in quality[p].readers.items()
                if rule.id in readers and quality[p].fields.get(col, 1.0) < FIDELITY_FLOOR
            ),
            "",
        )
        if blind:
            out.append(f"field_empty:{blind}")
            continue
        wanted = _selected_operations(rule)
        if wanted:
            have: set[str] = set()
            for product in products:
                if product not in seen_ops:
                    seen_ops[product] = {
                        str(r["op"]).lower()
                        for r in store.query(
                            f"SELECT DISTINCT api_operation AS op FROM {layout.EVENTS_TABLE} "
                            "WHERE tenant_id = :tenant_id AND metadata_product = :product "
                            "AND time > :since AND api_operation IS NOT NULL",
                            {
                                "tenant_id": tenant_id,
                                "product": product,
                                "since": datetime.now(UTC) - timedelta(days=30),
                            },
                            2000,
                        ).rows
                    }
                have |= seen_ops[product]
            if not any(w.lower() in have for w in wanted):
                out.append(f"value_absent:{sorted(wanted)[0]}")
                continue
        out.append("quiet")
    return out


def _selected_operations(rule: Any) -> set[str]:
    """The exact `api.operation` values a rule's selections name, if it names any."""
    found: set[str] = set()
    for name, block in (rule.detection.blocks or {}).items():
        if name.startswith("filter") or not isinstance(block, dict):
            continue
        for key, value in block.items():
            field_name, _, modifier = str(key).partition("|")
            if field_name != "api.operation" or modifier not in ("", "in"):
                continue
            found |= {str(v) for v in (value if isinstance(value, list) else [value])}
    return found


def spend(conn: Conn, tenant_id: str, days: int = 30) -> dict[str, Any]:
    rows = fetch_all(
        conn,
        """SELECT day, model, calls, tokens_in, tokens_out, usd
           FROM shoc.llm_spend
           WHERE tenant_id = %s AND day > current_date - %s
           ORDER BY day DESC, usd DESC""",
        (tenant_id, days),
    )
    total = sum(float(r["usd"]) for r in rows)
    today = sum(float(r["usd"]) for r in rows if r["day"] == datetime.now(UTC).date())
    return {
        "rows": rows,
        "usd_total": round(total, 4),
        "usd_today": round(today, 4),
        "tokens": sum(int(r["tokens_in"]) + int(r["tokens_out"]) for r in rows),
        "days": days,
    }


def volume(conn: Conn, store: Any, tenant_id: str, days: int = 7) -> dict[str, Any]:
    """Event volume per day and per product — the other half of what this costs."""
    from shoc.store import ocsf as layout

    rows = store.query(
        f"""SELECT metadata_product AS product, count(*) AS events
            FROM {layout.EVENTS_TABLE}
            WHERE tenant_id = :tenant_id AND time > :since
            GROUP BY metadata_product ORDER BY count(*) DESC""",
        {
            "tenant_id": tenant_id,
            "since": datetime.now(UTC) - timedelta(days=days),
        },
        100,
    ).rows
    return {
        "by_product": rows,
        "events": sum(int(r["events"]) for r in rows),
        "days": days,
    }


@dataclass
class OpsAlert:
    kind: str
    subject: str
    detail: str
    severity: str = "medium"

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "detail": self.detail,
            "severity": self.severity,
        }


def alerts(
    conn: Conn, tenant_id: str, budget_usd_per_day: float = 0.0, store: Any = None
) -> list[OpsAlert]:
    """What the Ops role would raise right now.

    `store` is optional so a caller without one still gets freshness and spend;
    with it, the quality axes are checked too, which is where the silent
    failures are.
    """
    out: list[OpsAlert] = []
    if store is not None:
        with contextlib.suppress(Exception):
            for quality in source_quality(conn, store, tenant_id):
                for note in quality.notes:
                    # A source that is fresh but whose key fields have gone null
                    # is the worse outage, because everything still looks green.
                    out.append(
                        OpsAlert(
                            "source.quality",
                            quality.product,
                            note,
                            "high" if quality.score < 0.5 else "medium",
                        )
                    )
    for source in source_health(conn, tenant_id):
        if source.error:
            out.append(
                OpsAlert("source.failing", source.source, f"last error: {source.error}", "high")
            )
        elif source.stale:
            minutes = f"{source.minutes_since:.0f} minutes" if source.minutes_since else "ever"
            out.append(
                OpsAlert("source.stale", source.source, f"no successful pull in {minutes}", "high")
            )
    for rule in rule_health(conn, tenant_id):
        if rule.error:
            out.append(OpsAlert("rule.failing", rule.rule_id, rule.error[:200], "high"))
        elif rule.noisy:
            out.append(
                OpsAlert(
                    "rule.noisy",
                    rule.rule_id,
                    f"{rule.findings_7d} finding(s) in 7 days across {rule.cases_7d} case(s)",
                    "medium",
                )
            )
    stuck = fetch_one(
        conn,
        # The window health.status uses: an old failure that was since fixed
        # stays listed by health.jobs but is no longer a live problem.
        """SELECT count(*) AS n FROM shoc.jobs
           WHERE tenant_id = %s AND state = 'failed'
             AND coalesce(finished_at, created_at) > now() - interval '24 hours'""",
        (tenant_id,),
    )
    if stuck and int(stuck["n"]):
        out.append(
            OpsAlert(
                "jobs.failed", "worker", f"{stuck['n']} job(s) failed in the last 24h", "medium"
            )
        )

    waiting = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.actions
           WHERE tenant_id = %s AND state = 'proposed' AND created_at < now() - interval '1 hour'""",
        (tenant_id,),
    )
    if waiting and int(waiting["n"]):
        out.append(
            OpsAlert(
                "approval.waiting",
                "response",
                f"{waiting['n']} action(s) have waited over an hour for a human",
                "high",
            )
        )
    for row in _failing_models(conn, tenant_id):
        out.append(
            OpsAlert(
                "llm.failing",
                str(row["model"]),
                f"{row['failures']} model call(s) failed today and "
                + ("none succeeded" if not int(row["calls"]) else f"{row['calls']} succeeded")
                + f"; last: {row['last_error']}",
                "high" if not int(row["calls"]) else "medium",
            )
        )
    # A hunt that could not look is a hole in what we see, not a hypothesis
    # for the hunt backlog (DET-11): its last run in the week was a gap.
    for row in fetch_all(
        conn,
        """SELECT DISTINCT ON (pack_id) pack_id, outcome, error FROM shoc.hunt_runs
           WHERE tenant_id = %s AND ran_at > now() - interval '7 days'
           ORDER BY pack_id, ran_at DESC""",
        (tenant_id,),
    ):
        if row["outcome"] == "gap":
            out.append(
                OpsAlert(
                    "hunt.gap",
                    str(row["pack_id"]),
                    str(row["error"] or "the hunt did not complete")[:300],
                    "medium",
                )
            )
    for row in _unworked_cases(conn, tenant_id):
        out.append(
            OpsAlert(
                "case.stalled",
                str(row["case_uid"]),
                f"{row['severity']} case open {row['hours']:.0f}h and no agent has spoken: "
                f"{row['title']}",
                "high" if row["severity"] in ("critical", "high") else "medium",
            )
        )
    # A worker that died between `action.started` and `action.executed` leaves
    # the row running, and nothing retries it: whether the change happened is
    # for somebody to check on the target (RSP-3).
    for row in fetch_all(
        conn,
        """SELECT action_uid, type, target FROM shoc.actions
           WHERE tenant_id = %s AND state = 'running'
             AND updated_at < now() - interval '1 hour'""",
        (tenant_id,),
    ):
        out.append(
            OpsAlert(
                "action.stuck",
                str(row["action_uid"]),
                f"{row['type']} on {row['target']} started over an hour ago and never finished",
                "high",
            )
        )
    for row in fetch_all(
        conn,
        """SELECT model, tokens_in + tokens_out AS tokens FROM shoc.llm_spend
           WHERE tenant_id = %s AND day = current_date AND tokens_in + tokens_out > 0""",
        (tenant_id,),
    ):
        if price_for(str(row["model"])) is None:
            out.append(
                OpsAlert(
                    "cost.unpriced",
                    str(row["model"]),
                    f"{row['tokens']} token(s) today counted at $0: shoc has no price for this "
                    "model; set SHOC_LLM_PRICE_IN and SHOC_LLM_PRICE_OUT (USD per million tokens)",
                    "medium",
                )
            )
    # Reports that scored well and still went unread: the intel budget is too
    # small for what the sources publish (RFC 0029). Weekly reading, not a page.
    short = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.intel_queue
           WHERE tenant_id = %s AND state = 'dropped' AND score >= 5
             AND reason LIKE 'not read within%%' AND changed_at > now() - interval '7 days'""",
        (tenant_id,),
    )
    if short and short["n"]:
        out.append(
            OpsAlert(
                "intel.budget_short",
                "intel",
                f"{short['n']} report(s) that scored 5 or more were dropped unread this week; "
                "raise intel_reports_per_day or intel_tokens_per_day (llm.configure)",
                "low",
            )
        )
    if budget_usd_per_day:
        today = spend(conn, tenant_id, days=1)["usd_today"]
        if today > budget_usd_per_day:
            out.append(
                OpsAlert(
                    "cost.over_budget",
                    "llm",
                    f"${today:.2f} spent today against a ${budget_usd_per_day:.2f} budget",
                    "medium",
                )
            )
    return out


def unpublished(conn: Conn, tenant_id: str, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The alerts the stream has not carried in the last day, numbers aside.

    `ops.check` runs every hour, so a source dark for two days used to reach
    every SSE and webhook subscriber 48 times. An alert goes out again when its
    wording changes, and once a day while it lasts; "dark for 3 hours" and
    "dark for 4 hours" are the same alert.
    """

    def shape(kind: str, subject: str, detail: str) -> tuple[str, str, str]:
        return kind, subject, re.sub(r"\d+(\.\d+)?", "#", detail)

    sent = {
        shape(str(r["type"]), str(r["subject"]), str(r["detail"] or ""))
        for r in fetch_all(
            conn,
            """SELECT type, subject, payload->>'detail' AS detail FROM shoc.stream_events
               WHERE tenant_id = %s AND type LIKE 'health.%%'
                 AND created_at > now() - interval '1 day'""",
            (tenant_id,),
        )
    }
    return [
        a
        for a in alerts
        if shape(f"health.{a['kind']}", str(a["subject"]), str(a["detail"])) not in sent
    ]


# A case nobody has spoken about for longer than this is not "in analysis", it is
# abandoned. One detection cycle plus a sweep is minutes; an hour is generous.
STALLED_CASE_HOURS = 1


def _failing_models(conn: Conn, tenant_id: str) -> list[dict[str, Any]]:
    """Models whose calls are failing today, worst first."""
    return fetch_all(
        conn,
        """SELECT model, calls, failures, last_error
           FROM shoc.llm_spend
           WHERE tenant_id = %s AND day = current_date AND failures > 0
             AND last_error_at > now() - interval '1 hour'
           ORDER BY calls, failures DESC""",
        (tenant_id,),
    )


def provider_failing(conn: Conn, tenant_id: str, minutes: int = 15) -> str:
    """The provider's last error if it is failing right now, else an empty string.

    Sending the crew at a case while the gateway is down spends the case's
    attempts on an outage, so the sweep asks this first.
    """
    row = fetch_one(
        conn,
        """SELECT last_error FROM shoc.llm_spend
           WHERE tenant_id = %s AND day = current_date AND failures > 0
             AND last_error_at > now() - %s * interval '1 minute'
           ORDER BY last_error_at DESC LIMIT 1""",
        (tenant_id, minutes),
    )
    return str(row["last_error"]) if row else ""


def _unworked_cases(conn: Conn, tenant_id: str) -> list[dict[str, Any]]:
    """Open cases where no agent has spoken at all — the crew never ran, or failed."""
    return fetch_all(
        conn,
        """SELECT case_uid, severity, title,
                  extract(epoch FROM now() - opened_at) / 3600 AS hours
           FROM shoc.cases
           WHERE tenant_id = %s AND state <> 'closed' AND tokens_used = 0
             AND opened_at < now() - %s * interval '1 hour'
           ORDER BY
             array_position(ARRAY['critical','high','medium','low','informational'], severity),
             opened_at
           LIMIT 10""",
        (tenant_id, STALLED_CASE_HOURS),
    )


# -- data-source quality (OPS-1, docs/agent-specs.md §12) -------------------
# DeTT&CT exists because coverage claims are usually lies. A source that is
# fresh but whose key fields have gone null is a worse outage than one that has
# stopped, because everything still looks green.
QUALITY_AXES = ("completeness", "retention", "timeliness", "field_fidelity")

# Below this fill rate, a rule that matches on the field is decoration.
FIDELITY_FLOOR = 0.6
# How far back we claim to be able to hunt. A 30-day hunt over 7 days of data is
# a lie, and this is what catches it.
RETENTION_TARGET_DAYS = 90


@dataclass
class SourceQuality:
    """One source, scored on the four axes that make a coverage claim true."""

    product: str
    events: int = 0
    completeness: float = 0.0
    retention_days: float = 0.0
    retention: float = 0.0
    timeliness_seconds: float = 0.0
    timeliness: float = 0.0
    field_fidelity: float = 0.0
    fields: dict[str, float] = field(default_factory=dict)
    readers: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return round(
            (self.completeness + self.retention + self.timeliness + self.field_fidelity) / 4, 3
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "events": self.events,
            "score": self.score,
            "completeness": self.completeness,
            "retention_days": round(self.retention_days, 1),
            "retention": self.retention,
            "timeliness_seconds": round(self.timeliness_seconds, 1),
            "timeliness": self.timeliness,
            "field_fidelity": self.field_fidelity,
            "fields": self.fields,
            "readers": self.readers,
            "notes": self.notes,
        }


def rule_fields(conn: Conn, tenant_id: str) -> dict[str, dict[str, list[str]]]:
    """{product: {field: [rule ids]}}: the keys each rule correlates on (OPS-1).

    Those are the entity and the group-by, which a rule needs on every row it
    counts. Selection fields are left out because many are empty by nature:
    CloudTrail carries an error code only on a failed call. A rule with no
    logsource we recognise is left out rather than charged to every source.
    """
    from shoc.detect import rules as ruleset
    from shoc.store import ocsf as layout

    out: dict[str, dict[str, list[str]]] = {}
    for rule in ruleset.load(None, conn, tenant_id):
        names = layout.products_for(
            rule.logsource.get("product", ""), rule.logsource.get("service", "")
        )
        used = {f for f in [*rule.detection.group_by, *rule.entity] if f and layout.column_for(f)}
        for product in names:
            by_field = out.setdefault(product, {})
            for f in used:
                key = f if layout.JSON_FIELD.match(f) else layout.column_for(f)
                by_field.setdefault(key or f, []).append(rule.id)
    return out


def product_of(source: str) -> str:
    """The `metadata_product` a source's events carry."""
    from shoc.ingest.connectors.base import connector_of
    from shoc.ingest.ocsf import load_mapping

    source = connector_of(source)
    try:
        return str(load_mapping(source).constants.get("metadata_product") or source)
    except Exception:  # a source with no mapping keeps its own name
        return source


# Seconds from an event to its ingestion, averaged. `TIME_TO_UNIX` is what
# SQLGlot writes per dialect; subtracting timestamps is Postgres-only (STO-1).
LAG_SECONDS = "AVG(TIME_TO_UNIX(ingested_at) - TIME_TO_UNIX(time))"


def source_quality(conn: Conn, store: Any, tenant_id: str, days: int = 30) -> list[SourceQuality]:
    """Score every configured source that is sending, on the four axes (OPS-1).

    All four come from the events themselves rather than from a connector
    saying it is fine: a source reports its own health, and a source is exactly
    the thing that cannot be trusted to. Events from a product no source is
    configured for (a removed source, replayed fixtures) are not scored: there
    is nothing to fix, and they would read as outages.
    """
    from shoc.store import ocsf as layout

    since = datetime.now(UTC) - timedelta(days=days)
    readers = rule_fields(conn, tenant_id)
    columns = sorted({col for by_col in readers.values() for col in by_col})
    index = {col: i for i, col in enumerate(columns)}
    types = dict(layout.COLUMNS)
    fidelity = ""
    for i, col in enumerate(columns):
        expr = layout.column_for(col)
        blank = f"{expr} IS NULL" + (f" OR {expr} = ''" if types.get(col, "TEXT") == "TEXT" else "")
        fidelity += f", SUM(CASE WHEN {blank} THEN 0 ELSE 1 END) AS have_{i}"
    rows = store.query(
        f"""SELECT metadata_product AS product, COUNT(*) AS events,
                   MIN(time) AS oldest, MAX(time) AS newest,
                   COUNT(DISTINCT FLOOR(TIME_TO_UNIX(time) / 86400)) AS days_seen,
                   {LAG_SECONDS} AS lag_seconds
                   {fidelity}
            FROM {layout.EVENTS_TABLE}
            WHERE tenant_id = :tenant_id AND time > :since
            GROUP BY metadata_product""",
        {"tenant_id": tenant_id, "since": since},
        200,
    ).rows

    # Events carry the product name, connector state the connector's. A file
    # source names its mapping in its settings. A source counts as configured
    # once it has settings or has run (a push source may have only the latter).
    mappings = {
        r["source"]: r["mapping"]
        for r in fetch_all(
            conn,
            "SELECT source, settings->>'mapping' AS mapping FROM shoc.connector_config"
            " WHERE tenant_id = %s",
            (tenant_id,),
        )
    }
    health = source_health(conn, tenant_id)
    known = {product_of(mappings.get(s.source) or s.source): s for s in health}
    configured = set(known) | {product_of(m or s) for s, m in mappings.items()}
    # Where each product's data starts, which the window cannot see past, and
    # how long the store keeps it.
    started = {
        str(r["product"]): r["start"]
        for r in fetch_all(
            conn,
            """SELECT unnest(products) AS product,
                      min(coalesce(first_event_at, first_loaded_at)) AS start
               FROM shoc.source_history WHERE tenant_id = %s GROUP BY 1""",
            (tenant_id,),
        )
    }
    kept = fetch_one(
        conn,
        "SELECT payload->>'days' AS days FROM shoc.schedules WHERE schedule_id = %s",
        (f"{tenant_id}:retention",),
    )
    kept_days = float((kept or {}).get("days") or RETENTION_TARGET_DAYS)
    now = datetime.now(UTC)
    out: list[SourceQuality] = []
    for row in rows:
        if str(row["product"]) not in configured:
            continue
        events = int(row["events"] or 0)
        quality = SourceQuality(product=str(row["product"] or "unknown"), events=events)

        # Completeness: is this source still arriving, and on how many of the
        # days since its first event in the window did it arrive? A week-long
        # gap that ended yesterday is not complete because today is fresh. A
        # quiet day counts against a quiet source too, so this is a score, and
        # only silence since the newest event is an alert.
        newest, oldest = row["newest"], row["oldest"]
        silent_hours = (now - newest).total_seconds() / 3600 if newest else 24 * 365
        spanned = (now.date() - oldest.astimezone(UTC).date()).days + 1 if oldest else 1
        arrived = min(1.0, int(row["days_seen"] or 0) / spanned)
        quality.completeness = round(max(0.0, min(1.0, 1 - (silent_hours / 24))) * arrived, 3)
        if silent_hours > 24:
            quality.notes.append(
                f"nothing for {silent_hours / 24:.1f} day(s): this is an outage, not a quiet day"
            )

        # Retention: how far back can we truthfully hunt? Data that reaches the
        # window's start goes back at least the window, and as far as the
        # source's history, up to what the store keeps.
        held = (now - oldest).total_seconds() / 86400 if oldest else 0.0
        if oldest and oldest < since + timedelta(days=1):
            start = started.get(quality.product)
            held = max(float(days), (now - start).total_seconds() / 86400 if start else 0.0)
        quality.retention_days = min(held, kept_days)
        quality.retention = round(min(1.0, quality.retention_days / RETENTION_TARGET_DAYS), 3)
        if quality.retention_days < 30:
            quality.notes.append(
                f"only {quality.retention_days:.0f} day(s) of history: a 30-day hunt over "
                f"this is a lie"
            )

        # Timeliness: how long between the event and us holding it?
        quality.timeliness_seconds = float(row["lag_seconds"] or 0)
        quality.timeliness = round(max(0.0, min(1.0, 1 - (quality.timeliness_seconds / 3600))), 3)

        # Field fidelity: are the keys this source's rules correlate on populated?
        # Each source is held to its own rules: an EDR feed to the host, an
        # audit log to the user. A source no rule reads scores 1.0 here; the
        # Surveyor reports it as unwatched.
        quality.readers = readers.get(quality.product, {})
        quality.fields = {
            col: round(int(row.get(f"have_{index[col]}") or 0) / events, 3) if events else 0.0
            for col in quality.readers
        }
        rates = quality.fields.values()
        quality.field_fidelity = round(sum(rates) / len(rates), 3) if rates else 1.0
        for col, rate in sorted(quality.fields.items(), key=lambda kv: kv[1]):
            if rate < FIDELITY_FLOOR:
                blind = quality.readers[col]
                quality.notes.append(
                    f"{col} is empty in {(1 - rate) * 100:.0f}% of {quality.product} rows: "
                    f"{len(blind)} rule(s) keyed on it are blind ({', '.join(blind[:3])})"
                )

        state = known.get(quality.product)
        if state and state.error:
            quality.notes.append(f"connector error: {state.error[:120]}")
        out.append(quality)
    return sorted(out, key=lambda q: q.score)


# -- the metric set (OPS-1) -------------------------------------------------
def metrics(conn: Conn, tenant_id: str, days: int = 30) -> dict[str, Any]:
    """MTTD and MTTR per incident type, false positives, and what it cost.

    Per type, because an aggregate hides everything: a company whose credential
    cases are handled in four minutes and whose endpoint cases sit for two days
    has an average that describes neither.
    """
    rows = fetch_all(
        conn,
        """SELECT c.case_uid, c.severity, c.verdict, c.opened_at, c.closed_at,
                  c.attack,
                  min(f.first_seen) AS activity_started,
                  min(m.created_at) FILTER (WHERE m.agent IN ('Sentinel', 'Investigator')) AS triaged_at,
                  min(a.executed_at) AS contained_at
           FROM shoc.cases c
           LEFT JOIN shoc.findings f ON f.tenant_id = c.tenant_id AND f.case_uid = c.case_uid
           LEFT JOIN shoc.openspace_messages m ON m.tenant_id = c.tenant_id AND m.case_uid = c.case_uid
           LEFT JOIN shoc.actions a
             ON a.tenant_id = c.tenant_id AND a.case_uid = c.case_uid AND a.state = 'done'
           WHERE c.tenant_id = %s AND c.opened_at > now() - %s * interval '1 day'
           GROUP BY c.case_uid, c.severity, c.verdict, c.opened_at, c.closed_at, c.attack""",
        (tenant_id, days),
    )

    buckets: dict[str, dict[str, list[float]]] = {}
    for row in rows:
        kind = _incident_type(row)
        bucket = buckets.setdefault(kind, {"detect": [], "triage": [], "contain": [], "close": []})
        if row["activity_started"] and row["opened_at"]:
            bucket["detect"].append(_minutes(row["activity_started"], row["opened_at"]))
        if row["opened_at"] and row["triaged_at"]:
            bucket["triage"].append(_minutes(row["opened_at"], row["triaged_at"]))
        if row["opened_at"] and row["contained_at"]:
            bucket["contain"].append(_minutes(row["opened_at"], row["contained_at"]))
        if row["opened_at"] and row["closed_at"]:
            bucket["close"].append(_minutes(row["opened_at"], row["closed_at"]))

    by_type = {
        kind: {
            "cases": max(len(v["detect"]), len(v["close"]), 1),
            "mttd_minutes": _mean(v["detect"]),
            "time_to_triage_minutes": _mean(v["triage"]),
            "time_to_contain_minutes": _mean(v["contain"]),
            "mttr_minutes": _mean(v["close"]),
        }
        for kind, v in sorted(buckets.items())
    }

    dispositions = fetch_all(
        conn,
        """SELECT verdict, count(*) AS n FROM shoc.cases
           WHERE tenant_id = %s AND opened_at > now() - %s * interval '1 day'
           GROUP BY verdict""",
        (tenant_id, days),
    )
    counts = {str(r["verdict"]): int(r["n"]) for r in dispositions}
    decided = sum(
        counts.get(v, 0) for v in ("malicious", "suspicious", "benign_expected", "false_positive")
    )
    # A false positive is a case a person or the crew closed as one (D77).
    by_rule = fetch_all(
        conn,
        """SELECT f.rule_id,
                  count(*) AS findings,
                  count(*) FILTER (WHERE c.state = 'closed' AND c.verdict = 'false_positive')
                    AS false_positives
           FROM shoc.findings f
           LEFT JOIN shoc.cases c ON c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid
           WHERE f.tenant_id = %s AND f.last_seen > now() - %s * interval '1 day'
             AND f.status NOT IN ('suppressed', 'self')
           GROUP BY f.rule_id HAVING count(*) > 0 ORDER BY count(*) DESC LIMIT 20""",
        (tenant_id, days),
    )
    return {
        "days": days,
        "by_incident_type": by_type,
        "dispositions": counts,
        "false_positive_rate": (
            round(counts.get("false_positive", 0) / decided, 3) if decided else None
        ),
        "false_positives_by_rule": [
            {
                "rule_id": str(r["rule_id"]),
                "findings": int(r["findings"]),
                "false_positives": int(r["false_positives"]),
                "rate": round(int(r["false_positives"]) / int(r["findings"]), 3),
            }
            for r in by_rule
        ],
        "spend_usd": spend(conn, tenant_id, days)["usd_total"],
    }


# What kind of incident this was, from the techniques the case carries. An
# aggregate MTTR over every kind of case describes none of them.
INCIDENT_TYPES = (
    ("credential", ("T1078", "T1110", "T1552", "T1555", "T1528", "T1550")),
    ("identity", ("T1098", "T1136", "T1556", "T1621", "T1531")),
    ("data", ("T1530", "T1567", "T1114", "T1485", "T1486")),
    ("evasion", ("T1562", "T1564")),
)


def _incident_type(row: dict[str, Any]) -> str:
    techniques = [str(t).upper() for t in (row["attack"] or [])]
    for name, prefixes in INCIDENT_TYPES:
        if any(t.startswith(p) for t in techniques for p in prefixes):
            return name
    return "other"


def _minutes(start: datetime, end: datetime) -> float:
    return max(0.0, (end - start).total_seconds() / 60)


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


# -- the Ops role above its queries (D47) --------------------------------------
def review(
    conn: Conn, store: Any, tenant_id: str, config: Any = None, client: Any = None
) -> dict[str, Any]:
    """Ops' model turn, once per outage of a source.

    The queries above decide what is unhealthy and whether a dark source pages
    (`manager.coverage`): a model cannot stop that page or raise one alone. The
    model adds what a query cannot: why a source is dark and the one fix, kept
    on the source for the page to carry; whether re-running the pull is the
    whole answer, which queues it; and what the SOC cannot see meanwhile, which
    goes in the weekly. A source is asked about again only after it recovered
    and failed again, so a long outage costs one turn.
    """
    from shoc.agents import loop, manager, roles, safety
    from shoc.agents.llm import NoLLM, from_config
    from shoc.db import jobs

    unhealthy = {s.source: s for s in source_health(conn, tenant_id) if s.error or s.stale}
    pending = [
        str(r["source"])
        for r in fetch_all(
            conn,
            """SELECT source FROM shoc.connector_state
               WHERE tenant_id = %s AND source = ANY(%s)
                 AND (diagnosed_at IS NULL OR diagnosed_at < last_ok_at)""",
            (tenant_id, list(unhealthy)),
        )
    ]
    if not pending:
        return {"read": False, "why": "no source is down without a diagnosis"}
    client = client if client is not None else from_config(config, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return {"read": False, "why": "no model is configured"}
    if failing := provider_failing(conn, tenant_id):
        return {"read": False, "why": f"the model provider is failing: {failing[:200]}"}
    try:
        said, usage = loop._ask(
            client,
            roles.OPS,
            "These sources are down and nobody has said why. Judge each, name the one fix, "
            "and say what the SOC cannot see meanwhile.\n\n"
            + safety.quote("sources", [unhealthy[s].__dict__ for s in pending])
            + "\n\n"
            + safety.quote("alerts", [a.to_json() for a in alerts(conn, tenant_id)]),
            roles.OpsOutput,
            config,
            conn,
            tenant_id,
            store,
        )
    except Exception as exc:
        record_failure(
            conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
        )
        return {"read": False, "why": f"the model failed: {type(exc).__name__}"}
    charge(conn, tenant_id, usage)
    judged = {j.source: j for j in said.sources if j.source in pending}
    retried: list[str] = []
    for source in pending:
        j = judged.get(source)
        fix = f"fix: {j.exact_fix.strip()}" if j is not None and j.exact_fix.strip() else ""
        text = "" if j is None else "; ".join(t for t in (j.diagnosis.strip(), fix) if t)[:600]
        # Written even when the model said nothing about it, so one outage is one turn.
        execute(
            conn,
            "UPDATE shoc.connector_state SET diagnosis = %s, diagnosed_at = now() "
            "WHERE tenant_id = %s AND source = %s",
            (text, tenant_id, source),
        )
        if j is not None and j.retry:
            hour = int(datetime.now(UTC).timestamp() // 3600)
            jobs.enqueue(
                conn,
                tenant_id,
                "source.sync",
                {"source": source},
                idempotency_key=f"retry:{source}:{hour}",
            )
            retried.append(source)
    heard = [
        *(f"Cannot currently see: {t}" for t in said.cannot_currently_see[:5]),
        *(f"Costly: {t}" for t in said.costly[:3]),
        *(f"If the budget runs hot, give up first: {t}" for t in said.degrade_first[:3]),
        # A page needs the coverage query's condition; on the model's word alone
        # it reaches the weekly.
        *([f"Ops would page: {said.page_reason}"] if said.page_human and said.page_reason else []),
    ]
    if heard:
        manager.tell(
            conn,
            tenant_id,
            "Ops",
            "digest",
            " ".join(heard)[:3000],
            group_key="ops:" + ",".join(sorted(pending)),
            deliver=False,
        )
    return {"read": True, "diagnosed": sorted(judged), "retried": retried, "tokens": usage.tokens}
