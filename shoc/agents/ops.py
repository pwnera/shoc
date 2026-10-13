"""Operations: is the pipeline actually working, and what is it costing? (OPS-1)

Ops is the SRE of the SOC, and it believes a detection you are not ingesting for
is worse than no detection, because it looks like coverage. Four things, all
queries and none of them a model's job:

- **Freshness.** A source silent beyond its own interval is an outage, not a
  quiet day. One only the vendor pushes to is quiet when the company is, for
  up to a week.
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
import itertools
import json
import re
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.store import kept

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
        """INSERT INTO shoc.llm_spend
             (tenant_id, day, model, calls, tokens_in, tokens_out, usd, last_ok_at)
           VALUES (%s, current_date, %s, 1, %s, %s, %s, now())
           ON CONFLICT (tenant_id, day, model) DO UPDATE SET
               calls = shoc.llm_spend.calls + 1,
               tokens_in = shoc.llm_spend.tokens_in + EXCLUDED.tokens_in,
               tokens_out = shoc.llm_spend.tokens_out + EXCLUDED.tokens_out,
               usd = shoc.llm_spend.usd + EXCLUDED.usd,
               last_ok_at = EXCLUDED.last_ok_at""",
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
    A reply that did not fit its schema still came back, so it also counts as
    the provider answering (`provider_failing`).
    """
    answered = bool(SCHEMA_FAILURE.search(reason))
    execute(
        conn,
        """INSERT INTO shoc.llm_spend
             (tenant_id, day, model, calls, failures, last_error, last_error_at, last_ok_at)
           VALUES (%s, current_date, %s, 0, 1, %s, now(), CASE WHEN %s THEN now() END)
           ON CONFLICT (tenant_id, day, model) DO UPDATE SET
               failures = shoc.llm_spend.failures + 1,
               last_error = EXCLUDED.last_error,
               last_error_at = EXCLUDED.last_error_at,
               last_ok_at = coalesce(EXCLUDED.last_ok_at, shoc.llm_spend.last_ok_at)""",
        (tenant_id, model or "none", reason[:500], answered),
    )


# What `complete_typed` raises when the model answered with JSON that does not
# fit, as the callers word it (`Role: ValidationError: $.x: ...`).
SCHEMA_FAILURE = re.compile(r"(^|: )(ValidationError: |ValueError: the model did not return JSON)")


@dataclass
class SourceHealth:
    source: str
    last_ok_at: datetime | None = None
    minutes_since: float | None = None
    stale: bool = False
    error: str | None = None
    events_seen: int = 0
    # Nothing polls it: only the vendor's pushes keep it fresh (ING-2). Not
    # `source.list`'s push_only, which names connectors that cannot be polled.
    pushed: bool = False
    # A pushed source with nothing to send lately, which is not an outage.
    quiet: bool = False
    # Its last pull read some streams and not others: `error` names the ones
    # refused, and the pull still counted (`connectors.base.write_state`).
    partial: bool = False
    # Running counts from its pulls: events found in the re-read overlap that no
    # earlier pull had read, by stream (D164); rows the store refused and left
    # out; events placed at ingest time because their own time did not read.
    late_events: dict[str, int] = field(default_factory=dict)
    skipped: int = 0
    replaced: int = 0


# A pushed source hears nothing while the company is quiet: a webhook-only
# GitHub is silent every night and weekend. It is stale after a week of
# silence; at once when the rule that sees its sender removed fired after its
# last delivery (the deletion is the last thing the webhook sends) and nobody
# closed that finding; and after a window of deliveries refused since the last
# one that loaded, as when the push key was rotated and GitHub still signs with
# the old one.
PUSH_QUIET_DAYS = 7
SENDER_REMOVED = {"github": "github_webhook_deleted"}


def source_health(conn: Conn, tenant_id: str, stale_after_minutes: int = 60) -> list[SourceHealth]:
    from shoc.ingest import connectors

    rows = fetch_all(
        conn,
        """SELECT s.source, s.last_ok_at, s.last_error, s.events_seen, s.push_refused_at,
                  s.last_run_at, c.interval_seconds, s.late_events, s.events_skipped,
                  s.times_replaced,
                  EXISTS (SELECT 1 FROM shoc.schedules p
                          WHERE p.tenant_id = s.tenant_id
                            AND p.schedule_id = s.tenant_id || ':sync:' || s.source) AS polled,
                  -- An open finding for this organisation, when the source names one.
                  (SELECT max(f.created_at) FROM shoc.findings f
                   WHERE f.tenant_id = s.tenant_id AND f.rule_id = ANY(%s)
                     AND f.status IN ('new', 'triage')
                     AND (coalesce(c.settings->>'org', '') = ''
                          OR coalesce(f.evidence->'sample'->>'cloud_account_uid', '') = ''
                          OR lower(f.evidence->'sample'->>'cloud_account_uid')
                             = lower(c.settings->>'org'))) AS removed_at
           FROM shoc.connector_state s
           LEFT JOIN shoc.connector_config c
             ON c.tenant_id = s.tenant_id AND c.source = s.source
           -- A disabled source is not polled, so it is not late either.
           WHERE s.tenant_id = %s AND c.enabled IS NOT FALSE ORDER BY s.source""",
        (list(SENDER_REMOVED.values()), tenant_id),
    )
    push = set(connectors.push_sources()) | set(connectors.also_push())
    now = datetime.now(UTC)
    out = []
    for row in rows:
        # A source is late when it has missed several of its own cycles, not on
        # a fixed clock: a five-minute connector and a daily one differ.
        window = max(stale_after_minutes, int((row["interval_seconds"] or 300) * 3 / 60))
        last = row["last_ok_at"]
        minutes = ((now - last).total_seconds() / 60) if last else None
        stale = minutes is None or minutes > window
        # `source.configure` schedules no sync for a source set up for push.
        name = connectors.connector_of(str(row["source"]))
        pushed = not row["polled"] and name in push
        quiet = False
        if pushed and minutes is not None:
            gone = row["removed_at"] if name in SENDER_REMOVED else None
            refused = row["push_refused_at"]
            late = (
                minutes > PUSH_QUIET_DAYS * 24 * 60
                or bool(gone and gone > last)
                or bool(refused and refused > last and now - refused > timedelta(minutes=window))
            )
            quiet, stale = stale and not late, late
        out.append(
            SourceHealth(
                source=row["source"],
                last_ok_at=last,
                minutes_since=round(minutes, 1) if minutes is not None else None,
                stale=stale,
                error=row["last_error"],
                events_seen=int(row["events_seen"] or 0),
                pushed=pushed,
                quiet=quiet,
                # `write_state` sets both from one now() on a pull that counted;
                # a whole failure leaves last_ok_at behind, and a push after it
                # (`mark_push`) moves only last_ok_at.
                partial=bool(row["last_error"] and last and last == row["last_run_at"]),
                late_events={k: int(v) for k, v in (row["late_events"] or {}).items()},
                skipped=int(row["events_skipped"] or 0),
                replaced=int(row["times_replaced"] or 0),
            )
        )
    return out


def record_push_refused(conn: Conn, tenant_id: str, source: str) -> None:
    """Note a push that failed its signature, for `source_health` (ING-2).

    The caller is unauthenticated, so nothing it sent is kept and only a source
    already on record is touched. The first refusal since the last delivery
    that loaded stays, so the window runs from it; a delivery that loads makes
    it older than `last_ok_at`, which ends it.
    """
    execute(
        conn,
        """UPDATE shoc.connector_state SET push_refused_at = now()
           WHERE tenant_id = %s AND source = %s
             AND (push_refused_at IS NULL
                  OR push_refused_at <= coalesce(last_ok_at, '-infinity'))""",
        (tenant_id, source),
    )


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
    seen_ops: dict[str, set[str]] | None = None
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
            if seen_ops is None:
                seen_ops = _operations(conn, store, tenant_id)
            have = {op for p in products for op in seen_ops.get(p, ())}
            if not any(w.lower() in have for w in wanted):
                out.append(f"value_absent:{sorted(wanted)[0]}")
                continue
        out.append("quiet")
    return out


def _operations(conn: Conn, store: Any, tenant_id: str) -> dict[str, set[str]]:
    """Every `api_operation` each product sent in 30 days, in one kept read."""
    from shoc.store import ocsf as layout

    seen: dict[str, set[str]] = {}
    for r in kept.rows(
        conn,
        store,
        tenant_id,
        "operations:30",
        f"SELECT metadata_product AS product, api_operation AS op FROM {layout.EVENTS_TABLE} "
        "WHERE tenant_id = :tenant_id AND time > :since AND api_operation IS NOT NULL "
        "GROUP BY metadata_product, api_operation",
        {"tenant_id": tenant_id, "since": datetime.now(UTC) - timedelta(days=30)},
        20_000,
    ):
        seen.setdefault(str(r["product"]), set()).add(str(r["op"]).lower())
    return seen


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

    rows = kept.rows(
        conn,
        store,
        tenant_id,
        f"volume:{days}",
        f"""SELECT metadata_product AS product, count(*) AS events
            FROM {layout.EVENTS_TABLE}
            WHERE tenant_id = :tenant_id AND time > :since
            GROUP BY metadata_product ORDER BY count(*) DESC""",
        {
            "tenant_id": tenant_id,
            "since": datetime.now(UTC) - timedelta(days=days),
        },
        100,
    )
    return {
        "by_product": rows,
        "events": sum(int(r["events"]) for r in rows),
        "days": days,
    }


# Shares of SHOC_DISK_BUDGET_GB. Past the first, Postgres' size is an alert;
# past the second, a page, while there is still room to write one.
DISK_ALERT, DISK_PAGE = 0.8, 0.9


def disk(conn: Conn, config: Any = None) -> dict[str, Any]:
    """Postgres' size, and its share of the budget the operator set (0 with none)."""
    row = fetch_one(conn, "SELECT pg_database_size(current_database()) AS bytes")
    size = int((row or {}).get("bytes") or 0)
    budget = float(getattr(config, "disk_budget_gb", 0) or 0)
    return {
        "bytes": size,
        "budget_gb": budget,
        "used": round(size / (budget * 1e9), 3) if budget else 0.0,
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
    conn: Conn,
    tenant_id: str,
    budget_usd_per_day: float = 0.0,
    store: Any = None,
    config: Any = None,
) -> list[OpsAlert]:
    """What the Ops role would raise right now.

    `store` is optional so a caller without one still gets freshness and spend;
    with it, the quality axes are checked too, which is where the silent
    failures are. `config` is the caller's, for whether a model is set up, how
    a person is reached and the disk budget.
    """
    from shoc.agents import manager

    out: list[OpsAlert] = []
    # Every other alert travels to a person through one of these.
    if not any(manager.reachable(conn, tenant_id, config).values()):
        out.append(
            OpsAlert(
                "notify.unreachable",
                "notify",
                "no way to reach a person: no pager routing key, Slack channel, mail to a "
                "signed-in admin or webhook, so pages and reports reach nobody",
                "high",
            )
        )
    failed = fetch_one(
        conn,
        # Settled as failed: a page still being retried has no outcome yet.
        """SELECT count(DISTINCT group_key) AS n,
                  (array_agg(last_error ORDER BY delivered_at DESC))[1] AS error
           FROM shoc.notices
           WHERE tenant_id = %s AND kind = 'page' AND outcome = 'failed'
             AND delivered_at > now() - interval '24 hours'""",
        (tenant_id,),
    )
    if failed and int(failed["n"]):
        out.append(
            OpsAlert(
                "page.failed",
                "manager",
                f"{failed['n']} page(s) reached nobody in the last 24h; last: {failed['error']}",
                "high",
            )
        )
    # Sizing the database stats every relation file: only with a budget to compare.
    room = disk(conn, config) if getattr(config, "disk_budget_gb", 0) else {"used": 0.0}
    if room["used"] >= DISK_ALERT:
        out.append(
            OpsAlert(
                "store.size",
                "postgres",
                f"the database holds {room['bytes'] / 1e9:.1f} GB, {room['used']:.0%} of "
                f"SHOC_DISK_BUDGET_GB={room['budget_gb']:g}; on a full disk Postgres refuses "
                "every write, the notices a page is sent from included",
                "high" if room["used"] >= DISK_PAGE else "medium",
            )
        )
    if store is not None:
        with contextlib.suppress(Exception):
            for quality in source_quality(conn, store, tenant_id):
                for note in quality.notes:
                    # A new source learning its baseline is not a fault (live-12).
                    if LEARNING in note:
                        continue
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
        if source.error and source.partial and not source.stale:
            # Some streams refused, the rest read: a tenant without one licence
            # (Entra P2) carried a standing high alert for it. The error says
            # which setting drops the stream.
            out.append(
                OpsAlert(
                    "source.partial",
                    source.source,
                    f"some streams failed: {source.error}",
                    "medium",
                )
            )
        elif source.error:
            out.append(
                OpsAlert("source.failing", source.source, f"last error: {source.error}", "high")
            )
        elif source.stale:
            minutes = f"{source.minutes_since:.0f} minutes" if source.minutes_since else "ever"
            what = "delivery" if source.pushed else "pull"
            out.append(
                OpsAlert(
                    "source.stale", source.source, f"no successful {what} in {minutes}", "high"
                )
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
    if waits := _unworked_hunts(conn, tenant_id):
        out.append(
            OpsAlert(
                "hunt.backlog_stale",
                "hunt",
                f"{waits} open hunt backlog item(s) waited over {UNWORKED_HUNT_HOURS}h without "
                f"being worked: {_why_hunts_wait(conn, tenant_id, config)}",
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
    for feed in failing_feeds(conn, tenant_id):
        out.append(OpsAlert("intel.feed_failing", feed["feed"], feed["why"], "medium"))
    # The lists lookups and the digest answer from, as this process loaded them:
    # the worker's are the ones its intel job and this check share.
    from shoc.detect import osint

    warned = {k: v for k, v in osint.LIST_WARNINGS.items() if not v.startswith("took the new")}
    for key in sorted(set(warned) | set(osint._FAILED)):
        out.append(
            OpsAlert(
                "intel.list_failing",
                key,
                warned.get(key) or "not loaded; tried again every 15 minutes",
                "medium",
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


# The refresh runs every 6 hours, so a feed with no good pull in a day missed four.
FEED_STALE_HOURS = 24
# Where an abuse.ch feed's indicators are stored from. Neither list is ever
# empty, so a feed that keeps none was read wrong: a renamed CSV column, or
# an HTML page served with a 200, parses to nothing and still counts as a pull.
FEED_SOURCES = {"abuse_ch_feodo": "abuse.ch/feodo", "abuse_ch_urlhaus": "abuse.ch/urlhaus"}


def failing_feeds(conn: Conn, tenant_id: str) -> list[dict[str, str]]:
    """Enabled intel feeds that failed, went stale or keep nothing (DET-4, OPS-1).

    A failure is caught per feed and the refresh job succeeds, so this stored
    state is the only place one shows. A feed that has never run is not judged.
    """
    out: list[dict[str, str]] = []
    for row in fetch_all(
        conn,
        """SELECT f.feed, f.last_ok_at, f.last_error,
                  f.last_ok_at IS NULL OR f.last_ok_at < now() - %s * interval '1 hour' AS stale,
                  NOT EXISTS (SELECT 1 FROM shoc.iocs i
                              WHERE i.tenant_id = f.tenant_id
                                AND i.source
                                    = (%s::jsonb ->> COALESCE(NULLIF(f.parser, ''), f.feed))
                                AND (i.expires_at IS NULL OR i.expires_at > now())) AS empty,
                  COALESCE(NULLIF(f.parser, ''), f.feed) AS parser
           FROM shoc.intel_feeds f
           WHERE f.tenant_id = %s AND f.enabled AND f.last_run_at IS NOT NULL
           ORDER BY f.feed""",
        (FEED_STALE_HOURS, json.dumps(FEED_SOURCES), tenant_id),
    ):
        if row["last_error"]:
            why = f"last pull failed: {str(row['last_error'])[:200]}"
        elif row["stale"]:
            when = f"{row['last_ok_at']:%Y-%m-%d %H:%M} UTC" if row["last_ok_at"] else "ever"
            why = f"no good pull in over {FEED_STALE_HOURS}h (last: {when})"
        elif row["parser"] in FEED_SOURCES and row["empty"]:
            why = "its pulls succeed and keep no indicator: the format may have changed"
        else:
            continue
        out.append({"feed": str(row["feed"]), "why": why})
    return out


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


# When some model last answered. A row written before migration 060 has calls
# and no last_ok_at: it is read as answering until the end of its day, so an
# upgrade does not page at the first failure (ai-4).
LAST_ANSWER = """greatest(max(last_ok_at),
    (max(day) FILTER (WHERE calls > 0 AND last_ok_at IS NULL) + 1)::timestamptz)"""


def provider_failing(conn: Conn, tenant_id: str, minutes: int = 15) -> str:
    """The provider's last error if it is failing right now, else an empty string.

    Sending the crew at a case while the gateway is down spends the case's
    attempts on an outage, so the sweep asks this first. A failure some model
    answered after is not an outage: a cheap model or one role failing must not
    hold back every case while the others work.
    """
    row = fetch_one(
        conn,
        f"""SELECT last_error FROM shoc.llm_spend
           WHERE tenant_id = %(t)s AND day = current_date AND failures > 0
             AND last_error_at > now() - %(m)s * interval '1 minute'
             AND last_error_at > (SELECT coalesce({LAST_ANSWER}, '-infinity')
                                  FROM shoc.llm_spend WHERE tenant_id = %(t)s)
           ORDER BY last_error_at DESC LIMIT 1""",
        {"t": tenant_id, "m": minutes},
    )
    return str(row["last_error"]) if row else ""


# A provider that has answered nothing for this long is down, not slow: the
# sweep has stood down and no case is read. A key it rejects, or credit it
# says is spent, is down at once: no retry fixes either (ai-4).
MODEL_DARK_HOURS = 6
REFUSED_STATUS = re.compile(r"\b(401|402|403)\b")


def model_down(conn: Conn, tenant_id: str) -> dict[str, Any] | None:
    """The outage of every model, read across days, or None while one answers.

    `provider_failing` looks at the last minutes of today; this is how long.
    Failing means the last failure came after the last answer of any model.
    """
    row = fetch_one(
        conn,
        f"""SELECT e.last_error, e.last_error_at, a.ok_at, a.first_error_at
           FROM shoc.llm_spend e,
                LATERAL (SELECT {LAST_ANSWER} AS ok_at,
                                min(last_error_at) FILTER (WHERE failures > 0) AS first_error_at
                         FROM shoc.llm_spend WHERE tenant_id = %(t)s) a
           WHERE e.tenant_id = %(t)s AND e.failures > 0
             AND e.last_error_at > now() - interval '1 hour'
           ORDER BY e.last_error_at DESC LIMIT 1""",
        {"t": tenant_id},
    )
    if not row or (row["ok_at"] and row["ok_at"] >= row["last_error_at"]):
        return None
    error = str(row["last_error"] or "")
    refused = REFUSED_STATUS.search(error)
    # A tenant no model ever answered is dark only once it has failed for as
    # long, not at its first transient error.
    since = row["ok_at"] or row["first_error_at"]
    dark = since < datetime.now(UTC) - timedelta(hours=MODEL_DARK_HOURS)
    if not (refused or dark):
        return None
    return {"since": row["ok_at"], "status": refused.group(1) if refused else "", "error": error}


# The Hunter wakes on each new item (D159), so an item two days old that no
# model turn has touched is a starved Hunter, not a busy one (DET-11).
UNWORKED_HUNT_HOURS = 48


def _unworked_hunts(conn: Conn, tenant_id: str) -> int:
    row = fetch_one(
        conn,
        """SELECT count(*) AS n FROM shoc.hunt_backlog
           WHERE tenant_id = %s AND state = 'open' AND NOT evidence ? 'worked_at'
             AND coalesce((evidence->>'reopened_at')::timestamptz, created_at)
                 < now() - %s * interval '1 hour'""",
        (tenant_id, UNWORKED_HUNT_HOURS),
    )
    return int((row or {}).get("n") or 0)


def _why_hunts_wait(conn: Conn, tenant_id: str, config: Any = None) -> str:
    """What holds the Hunter back, as far as it can be read off now: `hunt.work`
    says why in its job summary, which nothing keeps."""
    from shoc.agents import hunter
    from shoc.agents.llm import NoLLM, from_config

    with contextlib.suppress(Exception):
        client = from_config(config, conn, tenant_id)
        if isinstance(client, NoLLM) or not getattr(client, "available", True):
            return "no model is configured (llm.configure)"
    if _failing_models(conn, tenant_id):
        return "the model is failing (llm.failing)"
    spent = hunter._pack_tokens_today(conn, tenant_id)
    if spent and spent + hunter._typical_item(conn, tenant_id) >= hunter.PACK_TOKENS_PER_DAY:
        return f"today's ceiling of {hunter.PACK_TOKENS_PER_DAY} tokens is spent"
    return "no reason on record; health.jobs shows whether hunt.daily ran"


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
# The hunts' baseline, which a source's history should reach (`hunter`).
HUNT_DAYS = 30
# How the note on a source still short of it ends, before the date it gets there.
LEARNING = "has its whole baseline from"
# Empty working days in a row, inside the window, that make a hole: a backend
# switch on a running instance left a Thursday and a Friday (OPS-1).
HOLE_WORKDAYS = 2


def _workdays(a: int, b: int) -> int:
    """Monday to Friday between two epoch days, both left out. Day 0 was a Thursday."""
    return sum(1 for d in range(a + 1, b) if (d + 3) % 7 < 5)


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
LAG = "TIME_TO_UNIX(ingested_at) - TIME_TO_UNIX(time)"
LAG_SECONDS = f"AVG({LAG})"


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
    # A change the vendor's own automation made (Cloudflare renewing a
    # certificate) has no user to be missing, so it is not charged to an actor
    # field. It is most of a quiet account's audit log.
    system = "LOWER(actor_user_type) = 'system'"
    fidelity = f", SUM(CASE WHEN {system} THEN 1 ELSE 0 END) AS system_actors"
    for i, col in enumerate(columns):
        expr = layout.column_for(col)
        blank = f"{expr} IS NULL" + (f" OR {expr} = ''" if types.get(col, "TEXT") == "TEXT" else "")
        if col.startswith("actor_"):
            blank += f" OR {system}"
        fidelity += f", SUM(CASE WHEN {blank} THEN 0 ELSE 1 END) AS have_{i}"

    # Where each product's data starts, which the window cannot see past, and
    # when shoc first read it: the backfill a new source loads on its first run
    # is the past arriving, not lateness, and would read as hours late for a
    # month.
    history = fetch_all(
        conn,
        """SELECT unnest(products) AS product,
                  min(coalesce(first_event_at, first_loaded_at)) AS start,
                  min(first_loaded_at) AS loaded
           FROM shoc.source_history WHERE tenant_id = %s GROUP BY 1""",
        (tenant_id,),
    )
    started = {str(r["product"]): r["start"] for r in history}
    params: dict[str, Any] = {"tenant_id": tenant_id, "since": since}
    backfill = []
    for i, r in enumerate(history):
        params[f"p{i}"], params[f"l{i}"] = str(r["product"]), r["loaded"]
        backfill.append(f"(metadata_product = :p{i} AND time < :l{i})")
    lag = LAG
    if backfill:
        lag = f"CASE WHEN {' OR '.join(backfill)} THEN NULL ELSE {LAG} END"
    # One row per product and day, added up below, so a hole in the middle of
    # the window can be told apart from days a sparse source had nothing. The
    # lag is worked out once per event: written twice, its two placeholders per
    # product would halve how many products fit a Databricks statement.
    daily = kept.rows(
        conn,
        store,
        tenant_id,
        f"source_quality:{days}",
        f"""SELECT metadata_product AS product, epoch_day, COUNT(*) AS events,
                   MIN(time) AS oldest, MAX(time) AS newest,
                   SUM(lag_s) AS lag_sum, COUNT(lag_s) AS lag_n
                   {fidelity}
            FROM (SELECT *, FLOOR(TIME_TO_UNIX(time) / 86400) AS epoch_day, {lag} AS lag_s
                  FROM {layout.EVENTS_TABLE}
                  WHERE tenant_id = :tenant_id AND time > :since) AS e
            GROUP BY metadata_product, epoch_day""",
        params,
        200 * (days + 1),
    )
    rows: dict[str, dict[str, Any]] = {}
    for d in daily:
        row = rows.setdefault(str(d["product"]), {"days": set()})
        row["days"].add(int(float(d["epoch_day"])))
        row["oldest"] = min(row.get("oldest") or d["oldest"], d["oldest"])
        row["newest"] = max(row.get("newest") or d["newest"], d["newest"])
        for k in d.keys() - {"product", "epoch_day", "oldest", "newest"}:
            row[k] = row.get(k, 0.0) + float(d[k] or 0)

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
    # How long the store keeps it.
    retention = fetch_one(
        conn,
        "SELECT payload->>'days' AS days FROM shoc.schedules WHERE schedule_id = %s",
        (f"{tenant_id}:retention",),
    )
    kept_days = float((retention or {}).get("days") or RETENTION_TARGET_DAYS)
    now = datetime.now(UTC)
    out: list[SourceQuality] = []
    for product, row in rows.items():
        if product not in configured:
            continue
        events = int(row["events"] or 0)
        quality = SourceQuality(product=product, events=events)
        state = known.get(product)

        # Completeness: is this source still arriving, and on how many of the
        # days since its first event in the window did it arrive? A week-long
        # gap that ended yesterday is not complete because today is fresh. A
        # quiet day counts against a quiet source too, so this is a score, and
        # only silence since the newest event, or a run of empty working days,
        # is an alert. A pushed source's quiet days are the company's
        # (`source_health`).
        newest, oldest = row["newest"], row["oldest"]
        silent_hours = (now - newest).total_seconds() / 3600
        spanned = (now.date() - oldest.astimezone(UTC).date()).days + 1
        arrived = min(1.0, len(row["days"]) / spanned)
        quality.completeness = round(max(0.0, min(1.0, 1 - (silent_hours / 24))) * arrived, 3)
        if silent_hours > 24 and not (state and state.quiet):
            quality.notes.append(
                f"nothing for {silent_hours / 24:.1f} day(s): this is an outage, not a quiet day"
            )
        # A backend switch or a lost cursor leaves days nothing reads again. A
        # gap is measured in working days, so a weekend is none and a long
        # weekend one, and is a hole when it is longer than twice the source's
        # usual gap: a daily source's is none, and a weekly audit log's empty
        # week is its rhythm.
        gaps = sorted((_workdays(a, b), a, b) for a, b in itertools.pairwise(sorted(row["days"])))
        hole, before, after = gaps[-1] if gaps else (0, 0, 0)
        usual = statistics.median([g[0] for g in gaps[:-1]] or [0])
        if hole >= HOLE_WORKDAYS and hole > 2 * usual:
            first = datetime.fromtimestamp((before + 1) * 86400, UTC).date()
            last = datetime.fromtimestamp((after - 1) * 86400, UTC).date()
            quality.notes.append(
                f"no events on {hole} working day(s) between {first} and {last}: detections "
                "and baselines ran over a hole"
            )

        # Retention: how far back can we truthfully hunt? Data that reaches the
        # window's start goes back at least the window, and as far as the
        # source's history, up to what the store keeps. A sparse source's oldest
        # event in a short window is not where its history starts.
        held = (now - oldest).total_seconds() / 86400
        if oldest < since + timedelta(days=1):
            held = max(held, float(days))
        if start := started.get(product):
            held = max(held, (now - start).total_seconds() / 86400)
        quality.retention_days = min(held, kept_days)
        quality.retention = round(min(1.0, quality.retention_days / RETENTION_TARGET_DAYS), 3)
        if kept_days < HUNT_DAYS:
            quality.notes.append(
                f"the store keeps {kept_days:.0f} day(s): a {HUNT_DAYS}-day hunt never has "
                "its whole baseline"
            )
        elif quality.retention_days < HUNT_DAYS:
            # A new source is learning, which no person can fix: a fact for
            # health.quality, not an alert (`alerts`).
            ready = now + timedelta(days=HUNT_DAYS - quality.retention_days)
            quality.notes.append(
                f"only {quality.retention_days:.0f} day(s) of history: a {HUNT_DAYS}-day hunt "
                f"{LEARNING} {ready:%Y-%m-%d}"
            )

        # Timeliness: how long between the event and us holding it?
        quality.timeliness_seconds = row["lag_sum"] / row["lag_n"] if row["lag_n"] else 0.0
        quality.timeliness = round(max(0.0, min(1.0, 1 - (quality.timeliness_seconds / 3600))), 3)

        # Field fidelity: are the keys this source's rules correlate on populated?
        # Each source is held to its own rules: an EDR feed to the host, an
        # audit log to the user. A source no rule reads scores 1.0 here; the
        # Surveyor reports it as unwatched.
        quality.readers = readers.get(quality.product, {})
        people = events - int(row.get("system_actors") or 0)
        quality.fields = {
            col: round(int(row.get(f"have_{index[col]}") or 0) / of, 3) if of else 1.0
            for col in quality.readers
            for of in [people if col.startswith("actor_") else events]
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
    try:
        # An unknown provider or a key this master key cannot open is the
        # model's failure, not the check's: it raised exactly when a page was due.
        client = client if client is not None else from_config(config, conn, tenant_id)
    except Exception as exc:
        record_failure(conn, tenant_id, "none", f"{type(exc).__name__}: {exc}")
        return {"read": False, "why": f"the model is not set up: {type(exc).__name__}"}
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
            + safety.quote("alerts", [a.to_json() for a in alerts(conn, tenant_id, config=config)]),
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
