"""The Hunter (AGT-3, DET-8, DET-9, DET-11, RFC 0022): the daily cycle and what it owes.

Hunting is a hypothesis about behaviour, tested against data we already hold.
The work is split the way human hunters split it (PEAK, TaHiTI, MITRE's
TTP-based hunting):

1. **Readiness (code).** A pack runs only on data that can answer it. A pack
   whose product no connected source sends is *not applicable*: listed once,
   never "clear". A source whose data started less than the pack's lookback ago
   is *learning* until that date, because "never seen before" means nothing on
   a source's first day. Readiness is per account: a replay or another
   company's logs never make a baseline look a month old.
2. **Execute (code).** Every ready pack that is due runs. Its window is what
   was *ingested* since its last completed window, so a late delivery or a
   skipped day is caught up rather than lost. Rows are grouped into tuples with
   every event behind them.
3. **Triage (the model).** One Hunter turn reads every tuple with read-only
   tools and the packs' follow-up questions. Code checks what it returns: an
   explanation counts only on a basis code can verify, and doubt ends
   *inconclusive*, never suspicious.
4. **Route (code).** A suspicious tuple becomes a low finding with its actor
   entities, or a note on the open case that already covers it. The Hunter
   opens no case and pages nobody. A pack becomes a rule only after its
   findings were confirmed true positives.

A zero-row run on a ready pack is `clear`: over these sources and this window,
the behaviour did not happen (TaHiTI's "disproven"). It is not a claim about
anything else.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one

MAX_ROWS_PER_PACK = 2000
# Tuples one day's triage reads. More than this from one pack is triaged in a
# fixed order and the rest is recorded as too broad, never silently dropped.
TOO_MANY_TUPLES = 200
TRIAGE_STEPS = 12
# One turn settles every tuple of the day, so it gets more lookups than one
# agent turn on one case; the daily token ceiling still bounds it.
TRIAGE_CALLS = 36
# A case a hunt finding opens is low and cheap: a lifetime ceiling on what the
# crew may spend on it.
HUNT_CASE_TOKENS = 150_000
# Confirmed true positives that make a pack a rule.
PROMOTE_AFTER = 2
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
MAX_AGENDA_TECHNIQUES = 20
# Entity kinds a hunt finding names: who acted. An address or a resource shared
# by many principals would join unrelated cases.
ACTOR_ENTITIES = {"actor_user_name": "user", "actor_session_uid": "key", "device_hostname": "host"}


@dataclass
class Choice:
    """One pack, and why it runs today."""

    pack_id: str
    reason: str
    rank: int

    def to_json(self) -> dict[str, Any]:
        return {"pack_id": self.pack_id, "reason": self.reason, "rank": self.rank}


@dataclass
class Readiness:
    """Whether a pack can be answered here, and from which accounts."""

    pack_id: str
    state: str = "not_applicable"  # not_applicable | learning | stale | ready
    reason: str = ""
    ready_at: datetime | None = None
    sources: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    # The pack itself, so a list of packs can be read and filtered without a
    # second call: product, ATT&CK and where it was taken from (DET-8).
    title: str = ""
    product: str = ""
    attack: list[str] = field(default_factory=list)
    hypothesis: str = ""
    cites: list[dict[str, str]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "state": self.state,
            "reason": self.reason,
            "ready_at": self.ready_at.isoformat() if self.ready_at else None,
            "sources": self.sources,
            "accounts": self.accounts,
            "title": self.title,
            "product": self.product,
            "attack": self.attack,
            "hypothesis": self.hypothesis,
            "cites": self.cites,
        }


@dataclass
class Run:
    """What one pack concluded."""

    run_uid: str
    pack_id: str
    outcome: str = "clear"
    rows: int = 0
    chosen_because: str = ""
    rank: int = 0
    triage: str = ""
    model: str = "none"
    tokens: int = 0
    case_uid: str = ""
    finding_uid: str = ""
    error: str = ""
    duration_ms: int = 0
    query: str = ""
    query_params: dict[str, Any] = field(default_factory=dict)
    ingested_from: datetime | None = None
    ingested_to: datetime | None = None
    tuples: list[dict[str, Any]] = field(default_factory=list)
    ruled_out: list[str] = field(default_factory=list)
    unseen: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "run_uid": self.run_uid,
            "pack_id": self.pack_id,
            "outcome": self.outcome,
            "rows": self.rows,
            "chosen_because": self.chosen_because,
            "rank": self.rank,
            "triage": self.triage,
            "model": self.model,
            "tokens": self.tokens,
            "case_uid": self.case_uid,
            "finding_uid": self.finding_uid,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "query": self.query,
            "query_params": self.query_params,
            "ruled_out": self.ruled_out,
            "unseen": self.unseen,
        }

    @property
    def observations(self) -> list[dict[str, Any]]:
        return self.tuples


# -- readiness ----------------------------------------------------------------
def readiness(conn: Conn, tenant_id: str, pack: Any, now: datetime | None = None) -> Readiness:
    """Whether a pack's data can answer it, per source and account."""
    from shoc.store import ocsf as layout

    now = now or datetime.now(UTC)
    products = set(
        layout.products_for(pack.logsource.get("product", ""), pack.logsource.get("service", ""))
    )
    rows = [
        r
        for r in fetch_all(
            conn,
            """SELECT h.source, h.products, h.first_event_at, h.first_loaded_at,
                      h.last_loaded_at, h.account_uids, s.last_ok_at
               FROM shoc.source_history h
               JOIN shoc.connector_config c ON c.tenant_id = h.tenant_id AND c.source = h.source
               LEFT JOIN shoc.connector_state s
                 ON s.tenant_id = h.tenant_id AND s.source = h.source
               WHERE h.tenant_id = %s AND c.enabled""",
            (tenant_id,),
        )
        if set(r["products"] or []) & products
    ]
    out = Readiness(
        pack_id=pack.id,
        sources=sorted(str(r["source"]) for r in rows),
        title=pack.title,
        product=pack.logsource.get("product", ""),
        attack=list(pack.attack),
        hypothesis=pack.hypothesis,
        cites=[dict(c) for c in pack.sources],
    )
    if not rows:
        out.reason = f"no connected source sends {', '.join(sorted(products)) or 'its data'}"
        return out
    lookback = (
        timedelta(seconds=pack.baseline.lookback_seconds)
        if pack.baseline.kind != "none"
        else timedelta(0)
    )
    window = timedelta(seconds=pack.window_seconds)
    ready, learning = [], []
    for row in rows:
        start = row["first_event_at"] or row["first_loaded_at"]
        at = start + lookback
        (ready if at <= now else learning).append((row, at))
    if not ready:
        out.state = "learning"
        out.ready_at = min(at for _, at in learning)
        out.reason = (
            f"its baseline needs {pack.baseline.lookback} of data; "
            f"{', '.join(str(r['source']) for r, _ in learning)} started too recently"
        )
        return out
    fresh = [
        r
        for r, _ in ready
        if max(t for t in (r["last_ok_at"], r["last_loaded_at"]) if t is not None) >= now - window
    ]
    if not fresh:
        out.state = "stale"
        out.sources = sorted(str(r["source"]) for r, _ in ready)
        out.reason = f"no data from {', '.join(str(r['source']) for r, _ in ready)} within its {pack.window} window"
        return out
    out.state = "ready"
    out.sources = sorted(str(r["source"]) for r in fresh)
    out.accounts = sorted({str(a) for r in fresh for a in (r["account_uids"] or [])})
    return out


# -- selection ----------------------------------------------------------------
def select(conn: Conn, tenant_id: str, config: Any = None, limit: int = 0) -> list[Choice]:
    """Every due pack, or the first `limit`, in agenda order: the packs that test
    a behaviour this week's intel described, then those sharing a technique with
    intel or our cases. The day's budget is the triage ceiling, not a pack
    count: a query is cheap, and triage is what costs."""
    from shoc.detect import hunts

    packs = {p.id: p for p in hunts.load(config, conn, tenant_id)}
    state = {
        str(r["pack_id"]): r
        for r in fetch_all(conn, "SELECT * FROM shoc.hunt_packs WHERE tenant_id = %s", (tenant_id,))
    }
    today = datetime.now(UTC).date()
    due = {
        pid
        for pid, pack in packs.items()
        if (last := (state.get(pid) or {}).get("last_run_at")) is None
        or (today - last.date()).days >= max(1, pack.cadence_days)
    }
    ranked: dict[str, Choice] = {}

    def offer(pack_id: str, reason: str, rank: int) -> None:
        if pack_id in due and pack_id not in ranked:
            ranked[pack_id] = Choice(pack_id=pack_id, reason=reason, rank=rank)

    for pack_id, why in _hypotheses(conn, tenant_id):
        offer(pack_id, why, 1)
    by_technique: dict[str, list[str]] = {}
    for pack in packs.values():
        for technique in pack.attack:
            by_technique.setdefault(str(technique).upper(), []).append(pack.id)
    for code, why in _agenda(conn, tenant_id):
        for pack_id in by_technique.get(code, []) + by_technique.get(code.split(".", 1)[0], []):
            offer(pack_id, why, 2)
    for pack_id in sorted(due):
        last = (state.get(pack_id) or {}).get("last_run_at")
        offer(pack_id, "never run here" if last is None else f"due: last run {last:%Y-%m-%d}", 3)
    return sorted(ranked.values(), key=lambda c: (c.rank, c.pack_id))[: limit or None]


def _hypotheses(conn: Conn, tenant_id: str) -> list[tuple[str, str]]:
    """Packs that answer a hypothesis a configured feed's report raised this week:
    the pack merged for it, or the one the Hunter said covers it (D132)."""
    return [
        (str(row["pack_id"]), f"tests '{str(row['title'])[:80]}' ('{str(row['report'])[:80]}')")
        for row in fetch_all(
            conn,
            """SELECT coalesce(nullif(b.pack_id, ''), b.evidence->>'covered_by') AS pack_id,
                      b.title, r.title AS report
               FROM shoc.hunt_backlog b
               JOIN shoc.intel_reports r
                 ON r.tenant_id = b.tenant_id AND r.report_uid = b.evidence->>'report_uid'
               JOIN shoc.intel_feeds f
                 ON f.tenant_id = r.tenant_id AND f.feed = r.source AND f.enabled
               WHERE b.tenant_id = %s AND b.trigger = 'cti'
                 AND r.digested_at > now() - interval '7 days'
                 AND coalesce(nullif(b.pack_id, ''), b.evidence->>'covered_by', '') <> ''
               ORDER BY b.priority, b.created_at DESC""",
            (tenant_id,),
        )
    ]


def _agenda(conn: Conn, tenant_id: str) -> list[tuple[str, str]]:
    """Techniques worth hunting this week: from configured intel feeds, and from
    cases on our own sources (not those a hunt opened)."""
    out: list[tuple[str, str]] = []
    for row in fetch_all(
        conn,
        """SELECT DISTINCT unnest(r.techniques) AS technique, r.title FROM shoc.intel_reports r
           JOIN shoc.intel_feeds f ON f.tenant_id = r.tenant_id AND f.feed = r.source AND f.enabled
           WHERE r.tenant_id = %s AND r.source <> ''
             AND r.digested_at > now() - interval '7 days'""",
        (tenant_id,),
    ):
        code = str(row["technique"]).upper()
        if TECHNIQUE.match(code):
            out.append((code, f"{code} was named in intel this week ('{str(row['title'])[:80]}')"))
    for row in fetch_all(
        conn,
        """SELECT DISTINCT unnest(c.attack) AS technique, c.case_uid FROM shoc.cases c
           WHERE c.tenant_id = %s AND c.opened_at > now() - interval '7 days'
             AND EXISTS (SELECT 1 FROM shoc.findings f
                         WHERE f.tenant_id = c.tenant_id AND f.case_uid = c.case_uid
                           AND f.rule_id NOT LIKE 'hunt:%%')""",
        (tenant_id,),
    ):
        code = str(row["technique"]).upper()
        if TECHNIQUE.match(code):
            out.append((code, f"{code} appeared in {row['case_uid']} this week"))
    return out[:MAX_AGENDA_TECHNIQUES]


# -- running one pack -----------------------------------------------------------
def _uid(tenant_id: str, pack_id: str, when: datetime) -> str:
    blob = f"{tenant_id}|{pack_id}|{when.isoformat()}"
    return "HUNT-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def window(conn: Conn, tenant_id: str, pack: Any, now: datetime) -> tuple[datetime, datetime]:
    """From where the last completed window stopped, at most one lookback back."""
    row = (
        fetch_one(
            conn,
            "SELECT ingested_through FROM shoc.hunt_packs WHERE tenant_id = %s AND pack_id = %s",
            (tenant_id, pack.id),
        )
        or {}
    )
    start = row.get("ingested_through") or now - timedelta(seconds=pack.window_seconds)
    earliest = now - timedelta(seconds=max(pack.window_seconds, pack.baseline.lookback_seconds))
    return max(start, earliest), now


def run_pack(
    conn: Conn,
    store: Any,
    tenant_id: str,
    pack: Any,
    client: Any = None,
    config: Any = None,
    choice: Choice | None = None,
    end: datetime | None = None,
    triage: bool = True,
) -> Run:
    """Check readiness, run one pack over its window, and triage what came back.

    `triage=False` leaves the tuples on the run for `daily` to read in one turn.
    """
    started = time.monotonic()
    now = end or datetime.now(UTC)
    ready = readiness(conn, tenant_id, pack, now)
    _remember_readiness(conn, tenant_id, pack, ready)
    run = Run(
        run_uid=_uid(tenant_id, pack.id, now),
        pack_id=pack.id,
        chosen_because=choice.reason if choice else "asked for directly",
        rank=choice.rank if choice else 0,
    )
    if ready.state in ("not_applicable", "learning"):
        run.outcome = ready.state  # not recorded as a run: nothing was hunted
        run.error = ready.reason
        return run
    if ready.state == "stale":
        run.outcome, run.error = "gap", ready.reason
        _record(conn, tenant_id, pack, run)
        return run

    run.ingested_from, run.ingested_to = window(conn, tenant_id, pack, now)
    try:
        rows = _query(store, tenant_id, pack, run, ready.accounts)
    except Exception as exc:
        # A pack that cannot run is a gap in what we can see, not a crash.
        run.outcome, run.error = "gap", f"{type(exc).__name__}: {exc}"
        _record(conn, tenant_id, pack, run)
        return run
    run.rows = len(rows)
    run.tuples = group(tenant_id, run.run_uid, pack, rows)
    if len(run.tuples) > TOO_MANY_TUPLES:
        run.unseen.append(
            f"{len(run.tuples) - TOO_MANY_TUPLES} tuple(s) beyond the first {TOO_MANY_TUPLES} "
            "were too broad to triage today"
        )
        run.tuples = run.tuples[:TOO_MANY_TUPLES]
    run.duration_ms = int((time.monotonic() - started) * 1000)
    if not rows or not run.tuples:
        run.outcome = "clear" if not rows else "gap"
        run.error = "" if not rows else "; ".join(run.unseen)
        _record(conn, tenant_id, pack, run, advance=True)
    elif triage:
        triaged(conn, store, tenant_id, [(pack, run)], client, config)
    return run


def _query(
    store: Any, tenant_id: str, pack: Any, run: Run, accounts: list[str]
) -> list[dict[str, Any]]:
    """Run the pack, and write on `run` exactly what was sent."""
    from shoc.detect.compiler import compile_pack

    compiled = compile_pack(pack, MAX_ROWS_PER_PACK, accounts)
    params: dict[str, Any] = dict(compiled.params)
    params.update(
        {
            "tenant_id": tenant_id,
            "ingested_from": run.ingested_from,
            "ingested_to": run.ingested_to,
            "baseline_start": (run.ingested_from or datetime.now(UTC))
            - timedelta(seconds=pack.baseline.lookback_seconds),
        }
    )
    run.query, run.query_params = compiled.select_sql, params
    result = store.query(compiled.select_sql, params, MAX_ROWS_PER_PACK)
    run.query = result.sql or run.query
    return result.rows


def group(
    tenant_id: str, run_uid: str, pack: Any, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Rows as tuples: one per distinct pivot value set, with every event behind it."""
    from shoc.store import ocsf as layout

    keys = [
        layout.alias_for(f) or f
        for f in (*pack.pivot, *pack.baseline.first_seen, *pack.baseline.rare_by)
    ]
    keys = list(dict.fromkeys(k for k in keys if k))
    tuples: dict[str, dict[str, Any]] = {}
    for row in rows:
        values = {k: str(row[k]) for k in keys if row.get(k) not in (None, "", "-")}
        tid = (
            "TUP-"
            + hashlib.sha256(
                f"{tenant_id}|{run_uid}|{sorted(values.items())}".encode()
            ).hexdigest()[:16]
        )
        item = tuples.setdefault(
            tid,
            {
                "tuple_id": tid,
                "values": values,
                "events": 0,
                "event_uids": [],
                "operations": [],
                "classes": [],
                "first": None,
                "last": None,
                "actors": {
                    c: str(row[c]) for c in ACTOR_ENTITIES if row.get(c) not in (None, "", "-")
                },
            },
        )
        item["events"] += int(row.get("event_count") or 1)
        if row.get("event_uid") and len(item["event_uids"]) < 50:
            item["event_uids"].append(str(row["event_uid"]))
        for key, col in (("operations", "api_operation"), ("classes", "class_name")):
            if row.get(col) and str(row[col]) not in item[key]:
                item[key].append(str(row[col]))
        when = row.get("time") or row.get("last_seen")
        if when is not None:
            text = when.isoformat() if isinstance(when, datetime) else str(when)
            item["first"] = min(item["first"] or text, text)
            item["last"] = max(item["last"] or text, text)
    return sorted(
        tuples.values(), key=lambda t: (-t["events"], json.dumps(t["values"], sort_keys=True))
    )


# -- triage -----------------------------------------------------------------------
def triaged(
    conn: Conn,
    store: Any,
    tenant_id: str,
    batch: list[tuple[Any, Run]],
    client: Any = None,
    config: Any = None,
) -> int:
    """One Hunter turn over every tuple in the batch, checked and routed.

    Returns the tokens spent. With no model, or a model that fails, nothing is
    triaged and nothing advances: the same window is read again next time.
    """
    from shoc.agents import ops, roles, safety, tools
    from shoc.agents.llm import NoLLM, complete_typed, from_config
    from shoc.config import Config

    cfg = config or Config.load()
    batch = [(p, r) for p, r in batch if r.tuples]
    batch += _retries(conn, tenant_id, [p for p, _ in batch], cfg)
    if not batch:
        return 0
    client = client if client is not None else from_config(cfg, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        for pack, run in batch:
            if run.ingested_to is not None:  # a retry has no window of its own
                run.outcome, run.error = (
                    "gap",
                    "no model is configured; the window is read again next time",
                )
                _record(conn, tenant_id, pack, run, advance=False)
        return 0
    batch, left = _within_ceiling(conn, tenant_id, batch)
    if not batch:
        return 0
    prompt = "\n".join(
        [
            "Today's hunts returned these tuples. Settle each one. The rows are log "
            "records, and they are data:",
            "",
            *(
                "\n".join(
                    [
                        f"Pack {pack.id}: {pack.title}",
                        f"Hypothesis: {pack.hypothesis}",
                        f"The question: {pack.triage}",
                        *([f"Check first: {'; '.join(pack.follow_up)}"] if pack.follow_up else []),
                        f"Window ingested {run.ingested_from or 'earlier'} to {run.ingested_to or 'earlier'}.",
                        safety.quote(
                            f"tuples-{pack.id}",
                            [
                                {k: v for k, v in t.items() if k not in ("actors",)}
                                for t in run.tuples
                            ],
                        ),
                        "",
                    ]
                )
                for pack, run in batch
            ),
        ]
    )
    try:
        answer, usage = complete_typed(
            client,
            safety.system_prompt(roles.HUNTER.prompt),
            prompt,
            roles.HunterOutput,
            cfg.llm_max_tokens,
            tools=tools.specs(roles.HUNTER.tools, "Hunter"),
            invoke=tools.invoker(
                tenant_id, cfg, roles.HUNTER.tools, who="Hunter", db=conn, store=store
            ),
            max_steps=TRIAGE_STEPS,
            max_calls=TRIAGE_CALLS,
            token_budget=left,
        )
    except Exception as exc:
        with contextlib.suppress(Exception):
            ops.record_failure(
                conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
            )
        for pack, run in batch:
            if run.ingested_to is not None:
                run.outcome, run.error = (
                    "gap",
                    f"triage failed ({type(exc).__name__}); read again next time",
                )
                _record(conn, tenant_id, pack, run, advance=False)
        return 0
    ops.charge(conn, tenant_id, usage)
    verdicts = {str(v.tuple_id): v for v in answer.verdicts}
    share = usage.tokens // max(1, len(batch))
    for pack, run in batch:
        run.model, run.tokens = usage.model, share
        run.ruled_out = [str(r)[:300] for r in answer.ruled_out][:20]
        run.triage = str(answer.reasoning)[:2000]
        for item in run.tuples:
            item["verdict"], item["why"] = check(
                conn, store, tenant_id, run, item, verdicts.get(item["tuple_id"]), usage.seen
            )
        outcomes = {t["verdict"] for t in run.tuples}
        run.outcome = next(
            o
            for o in ("suspicious", "inconclusive", "explained")
            if o in outcomes or o == "explained"
        )
        _route(conn, store, tenant_id, pack, run)
        if run.ingested_to is not None:
            _record(conn, tenant_id, pack, run, advance=True)
        else:
            _settle_retry(conn, tenant_id, run)
    return usage.tokens


def _within_ceiling(
    conn: Conn, tenant_id: str, batch: list[tuple[Any, Run]]
) -> tuple[list[tuple[Any, Run]], int]:
    """The packs today's triage ceiling has room for, in agenda order, and the
    tokens left for the turn (DET-9, `llm.configure hunt_tokens_per_day`).

    A pack is read only if its tuples fit in half of what is left, at about four
    characters a token, so the lookups and the answer have the rest. One that
    does not fit is a gap whose window stays where it was, read the next day.
    """
    from shoc.agents.llm import budget

    spent = (
        fetch_one(
            conn,
            "SELECT coalesce(sum(tokens), 0) AS n FROM shoc.hunt_runs "
            "WHERE tenant_id = %s AND ran_at >= current_date",
            (tenant_id,),
        )
        or {}
    )
    left = int(budget(conn, tenant_id, "hunt_tokens_per_day")) - int(spent.get("n") or 0)
    fits, size = [], 0
    for pack, run in batch:
        cost = len(json.dumps(run.tuples, default=str)) // 4
        if size + cost <= left // 2:
            fits.append((pack, run))
            size += cost
        elif run.ingested_to is not None:
            run.outcome = "gap"
            run.error = (
                f"today's triage ceiling has {max(left, 0)} token(s) left, too few for "
                f"{cost} token(s) of tuples; read again tomorrow"
            )
            _record(conn, tenant_id, pack, run, advance=False)
    return fits, left


def check(
    conn: Conn,
    store: Any,
    tenant_id: str,
    run: Run,
    item: dict[str, Any],
    verdict: Any,
    seen: list[str] | None = None,
) -> tuple[str, str]:
    """What code accepts of the Hunter's verdict on one tuple.

    Either outcome cites events, and they count only when they are the tuple's
    own or a lookup in this turn returned them (`seen`, SEC-2).
    """
    from shoc.agents.openspace import Evidence, validate_citations
    from shoc.cases import own

    if verdict is None:
        return "inconclusive", "the Hunter gave no verdict on it"
    outcome, ref = str(verdict.outcome), str(verdict.basis_ref or "").strip()
    cited = validate_citations(
        store,
        tenant_id,
        [str(c) for c in verdict.citations or []],
        Evidence(set(item.get("event_uids") or []), list(seen or [])),
    )
    if outcome == "suspicious":
        if not cited:
            return "inconclusive", "suspicious without an event that shows it"
        item["citations"] = cited
        return "suspicious", str(verdict.reasoning)[:500]
    if outcome == "explained" and not cited:
        return (
            "inconclusive",
            f"explained without citing the events it explains: {verdict.reasoning}"[:500],
        )
    if outcome == "explained":
        basis = str(verdict.basis)
        if basis == "human_fact" and fetch_one(
            conn,
            """SELECT 1 FROM shoc.memory WHERE tenant_id = %s AND memory_id = %s
                 AND source = 'human' AND (expires_at IS NULL OR expires_at > now())""",
            (tenant_id, ref),
        ):
            return "explained", f"a person said so ({ref}): {verdict.reasoning}"[:500]
        if basis == "own_credential" and own.bare(ref).lower() in own.values(
            conn, tenant_id, "credential", "automation", "address"
        ):
            return "explained", f"{ref} is shoc's own or the company's automation"
        if basis == "older_event" and _older(store, tenant_id, ref, run):
            return "explained", f"routine before this window ({ref}): {verdict.reasoning}"[:500]
        return "inconclusive", f"explained without a basis shoc can check: {verdict.reasoning}"[
            :500
        ]
    return "inconclusive", (str(verdict.missing or verdict.reasoning) or "not settled")[:500]


def _older(store: Any, tenant_id: str, event_uid: str, run: Run) -> bool:
    from shoc.store import ocsf as layout

    if not event_uid or run.ingested_from is None:
        return bool(event_uid) and run.ingested_from is None
    rows = store.query(
        f"SELECT event_uid FROM {layout.EVENTS_TABLE} WHERE tenant_id = :tenant_id "
        "AND event_uid = :uid AND ingested_at < :before",
        {"tenant_id": tenant_id, "uid": event_uid, "before": run.ingested_from},
        1,
    ).rows
    return bool(rows)


# -- routing ------------------------------------------------------------------------
def _route(conn: Conn, store: Any, tenant_id: str, pack: Any, run: Run) -> None:
    """A suspicious tuple goes to a person; a second inconclusive on a sensitive pack too."""
    raise_now = [t for t in run.tuples if t["verdict"] == "suspicious"]
    if pack.sensitive:
        raise_now += [t for t in run.tuples if t["verdict"] == "inconclusive" and t.get("retried")]
    for item in raise_now:
        uid = _raise_finding(conn, tenant_id, pack, run, item)
        run.finding_uid = run.finding_uid or uid
    if raise_now:
        from shoc.agents import manager

        manager.tell(
            conn,
            tenant_id,
            "Hunter",
            "digest",
            f"Hunt {pack.id} raised {len(raise_now)} finding(s): "
            + "; ".join(json.dumps(t["values"])[:120] for t in raise_now[:3]),
            deliver=False,
        )


def _raise_finding(conn: Conn, tenant_id: str, pack: Any, run: Run, item: dict[str, Any]) -> str:
    """A low finding with the actor's entities, or a note on the case that covers it.

    The Hunter is not the incident team: if an open case from a rule already
    names this actor in the same days, the rows are told to that case. A closed
    case is never written into.
    """
    from shoc.agents.openspace import Message, post
    from shoc.detect.engine import Finding, upsert

    entities = sorted(f"{ACTOR_ENTITIES[c]}:{v}" for c, v in item["actors"].items())
    cited = item.get("citations") or item["event_uids"][:20]
    first = _when(item["first"]) or datetime.now(UTC)
    last = _when(item["last"]) or datetime.now(UTC)
    covering = (
        fetch_one(
            conn,
            """SELECT c.case_uid FROM shoc.case_entities e
           JOIN shoc.cases c ON c.tenant_id = e.tenant_id AND c.case_uid = e.case_uid
           JOIN shoc.findings f ON f.tenant_id = c.tenant_id AND f.case_uid = c.case_uid
           WHERE e.tenant_id = %s AND e.entity = ANY(%s) AND c.state <> 'closed'
             AND f.rule_id NOT LIKE 'hunt:%%'
             AND f.last_seen > %s AND f.first_seen < %s
           ORDER BY c.opened_at DESC LIMIT 1""",
            (tenant_id, entities, first - timedelta(days=1), last + timedelta(days=1)),
        )
        if entities
        else None
    )
    if covering:
        with contextlib.suppress(Exception):
            post(
                conn,
                None,
                tenant_id,
                covering["case_uid"],
                Message(
                    agent="Hunter",
                    kind="observation",
                    principal="agent",
                    body=f"Hunt {pack.id} surfaced this for the same actor: "
                    f"{json.dumps(item['values'])[:300]} ({item['events']} event(s)). "
                    f"{item.get('why', '')}",
                    citations=cited,
                ),
            )
        run.case_uid = run.case_uid or str(covering["case_uid"])
        return ""
    finding = Finding(
        finding_uid="F-"
        + hashlib.sha256(f"{tenant_id}|{item['tuple_id']}".encode()).hexdigest()[:20],
        tenant_id=tenant_id,
        rule_id=f"hunt:{pack.id}",
        title=f"Hunt: {pack.title}",
        severity="low",
        confidence=0.4,
        entity_key="|".join(sorted(item["actors"].values())) or json.dumps(item["values"])[:200],
        window_start=first,
        window_end=last,
        first_seen=first,
        last_seen=last,
        event_count=int(item["events"]),
        event_uids=cited,
        attack=list(pack.attack),
        evidence={
            "kind": "hunt",
            "pack_id": pack.id,
            "run_uid": run.run_uid,
            "hypothesis": pack.hypothesis,
            "tuple": item["values"],
            "why": item.get("why", ""),
        },
        entities=entities,
    )
    upsert(conn, finding)
    return finding.finding_uid


def _when(text: str | None) -> datetime | None:
    if not text:
        return None
    with contextlib.suppress(ValueError):
        value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return None


def _retries(conn: Conn, tenant_id: str, running: list[Any], config: Any) -> list[tuple[Any, Run]]:
    """Yesterday's inconclusive tuples, read once more with what was missing named."""
    from shoc.detect import hunts

    packs = {p.id: p for p in hunts.load(config, conn, tenant_id)}
    rows = fetch_all(
        conn,
        """SELECT * FROM shoc.hunt_observations
           WHERE tenant_id = %s AND verdict = 'inconclusive'
             AND NOT coalesce((row_data->>'retried')::boolean, false)
             AND seen_at > now() - interval '7 days'
           ORDER BY seen_at LIMIT %s""",
        (tenant_id, TOO_MANY_TUPLES),
    )
    by_pack: dict[str, Run] = {}
    for row in rows:
        pack = packs.get(str(row["pack_id"]))
        if pack is None:
            continue
        run = by_pack.setdefault(
            pack.id,
            Run(
                run_uid=str(row["run_uid"]),
                pack_id=pack.id,
                chosen_because="retry of an inconclusive tuple",
            ),
        )
        item = dict(row["row_data"] or {})
        item.update(retried=True, tuple_id=str(row["observation_uid"]))
        item["values"] = {**item.get("values", {}), "missing_before": row["summary"]}
        run.tuples.append(item)
    return [(packs[pid], run) for pid, run in by_pack.items()]


def _settle_retry(conn: Conn, tenant_id: str, run: Run) -> None:
    for item in run.tuples:
        execute(
            conn,
            """UPDATE shoc.hunt_observations
                  SET verdict = %s, summary = %s,
                      row_data = row_data || '{"retried": true}'::jsonb
                WHERE tenant_id = %s AND observation_uid = %s""",
            (item["verdict"], str(item.get("why", ""))[:500], tenant_id, item["tuple_id"]),
        )


def _remember_readiness(conn: Conn, tenant_id: str, pack: Any, ready: Readiness) -> None:
    """Keep each pack's readiness, and tell the Manager when a ready pack falls back.

    Falling back because a source stopped sending is a `coverage_dark` page,
    grouped with the source's own coverage page so the operator is woken once.
    Falling back because a source was removed is the operator's own doing, and
    a digest.
    """
    before = (
        fetch_one(
            conn,
            "SELECT readiness FROM shoc.hunt_packs WHERE tenant_id = %s AND pack_id = %s",
            (tenant_id, pack.id),
        )
        or {}
    )
    execute(
        conn,
        """INSERT INTO shoc.hunt_packs (tenant_id, pack_id, readiness, ready_at, cadence_days)
           VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, pack_id) DO UPDATE SET
               readiness = EXCLUDED.readiness, ready_at = EXCLUDED.ready_at""",
        (tenant_id, pack.id, ready.state, ready.ready_at, pack.cadence_days),
    )
    if before.get("readiness") == "ready" and ready.state != "ready":
        from shoc.agents import manager

        said = f"Hunt {pack.id} can no longer run: {ready.reason}."
        if ready.state != "stale":
            manager.tell(conn, tenant_id, "Hunter", "digest", said, deliver=False)
        for source in ready.sources if ready.state == "stale" else []:
            manager.tell(
                conn,
                tenant_id,
                "Hunter",
                "page",
                said,
                condition="coverage_dark",
                severity="high",
                group_key=f"source:{source}",
            )


def _record(conn: Conn, tenant_id: str, pack: Any, run: Run, advance: bool = False) -> None:
    """Write the run and its tuples; move the pack's cursor only when it concluded."""
    execute(
        conn,
        """INSERT INTO shoc.hunt_runs
               (run_uid, tenant_id, pack_id, window_start, window_end, outcome,
                rows_returned, chosen_because, rank, triage, model, tokens, error, duration_ms,
                query, query_params, ingested_from, ingested_to, ruled_out, unseen,
                finding_uid, case_uid)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (run_uid) DO UPDATE SET
               outcome = EXCLUDED.outcome, rows_returned = EXCLUDED.rows_returned,
               triage = EXCLUDED.triage, error = EXCLUDED.error,
               query = EXCLUDED.query, query_params = EXCLUDED.query_params,
               ruled_out = EXCLUDED.ruled_out, unseen = EXCLUDED.unseen,
               finding_uid = EXCLUDED.finding_uid, case_uid = EXCLUDED.case_uid,
               model = EXCLUDED.model, tokens = EXCLUDED.tokens""",
        (
            run.run_uid,
            tenant_id,
            pack.id,
            run.ingested_from,
            run.ingested_to,
            run.outcome,
            run.rows,
            run.chosen_because,
            run.rank,
            run.triage,
            run.model,
            run.tokens,
            run.error,
            run.duration_ms,
            run.query,
            json.dumps(run.query_params, default=str),
            run.ingested_from,
            run.ingested_to,
            json.dumps(run.ruled_out),
            json.dumps(run.unseen),
            run.finding_uid,
            run.case_uid,
        ),
    )
    for item in run.tuples:
        verdict = item.get("verdict") or "unreviewed"
        execute(
            conn,
            """INSERT INTO shoc.hunt_observations
                   (observation_uid, tenant_id, run_uid, pack_id, entity, summary,
                    row_data, event_uids, verdict)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (observation_uid) DO UPDATE SET
                   verdict = EXCLUDED.verdict, summary = EXCLUDED.summary""",
            (
                item["tuple_id"],
                tenant_id,
                run.run_uid,
                pack.id,
                next(iter(item["actors"].values()), ""),
                str(item.get("why") or json.dumps(item["values"]))[:500],
                json.dumps(item, default=str),
                item["event_uids"],
                verdict,
            ),
        )
    streak = sum(1 for t in run.tuples if t.get("verdict") == "inconclusive")
    execute(
        conn,
        """INSERT INTO shoc.hunt_packs
               (tenant_id, pack_id, last_run_at, last_outcome, runs, cadence_days,
                ingested_through, inconclusive_streak)
           VALUES (%s,%s,now(),%s,1,%s,%s,%s)
           ON CONFLICT (tenant_id, pack_id) DO UPDATE SET
               last_run_at = now(), last_outcome = EXCLUDED.last_outcome,
               runs = shoc.hunt_packs.runs + 1,
               ingested_through = CASE WHEN %s THEN EXCLUDED.ingested_through
                                       ELSE shoc.hunt_packs.ingested_through END,
               inconclusive_streak = CASE WHEN EXCLUDED.inconclusive_streak > 0
                                          THEN shoc.hunt_packs.inconclusive_streak + 1 ELSE 0 END""",
        (
            tenant_id,
            pack.id,
            run.outcome,
            pack.cadence_days,
            run.ingested_to if advance else None,
            streak,
            advance,
        ),
    )
    # A `gap` is not a hypothesis to hunt: Ops raises it with source health
    # (`hunt.gap` in `ops.alerts`), from this row.
    if advance:
        # A pack the Hunter wrote for its backlog has tested the hypothesis once.
        execute(
            conn,
            """UPDATE shoc.hunt_backlog SET state = 'done', decided_at = now(),
                      evidence = evidence || %s
               WHERE tenant_id = %s AND pack_id = %s AND state = 'packed'""",
            (
                json.dumps(
                    {
                        "decision": "tested",
                        "because": f"its first run concluded {run.outcome}",
                        "run_uid": run.run_uid,
                    }
                ),
                tenant_id,
                pack.id,
            ),
        )


# -- promotion ------------------------------------------------------------------------
def promotions(conn: Conn, tenant_id: str, config: Any = None) -> int:
    """A pack whose findings were confirmed attacks twice belongs in the rule set.

    Counted from case verdicts: closed malicious, or closed suspicious by a
    person. A case that is still open, or closed benign, counts for nothing.
    """
    from shoc.agents import detection_engineer as engineer
    from shoc.detect import hunts

    packs = {p.id: p for p in hunts.load(config, conn, tenant_id)}
    proposed = 0
    for row in fetch_all(
        conn,
        """SELECT substr(f.rule_id, 6) AS pack_id,
                  array_agg(DISTINCT c.case_uid) AS cases,
                  array_agg(DISTINCT f.evidence->>'run_uid') AS runs,
                  (array_agg(f.event_uids))[1:5] AS events
           FROM shoc.findings f JOIN shoc.cases c
             ON c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid
           WHERE f.tenant_id = %s AND f.rule_id LIKE 'hunt:%%' AND c.state = 'closed'
             AND (c.verdict = 'malicious' OR (c.verdict = 'suspicious' AND c.closed_by = 'human'))
           GROUP BY substr(f.rule_id, 6)
           HAVING count(DISTINCT c.case_uid) >= %s""",
        (tenant_id, PROMOTE_AFTER),
    ):
        pack = packs.get(str(row["pack_id"]))
        if pack is None:
            continue
        execute(
            conn,
            "UPDATE shoc.hunt_packs SET true_positives = %s WHERE tenant_id = %s AND pack_id = %s",
            (len(row["cases"] or []), tenant_id, pack.id),
        )
        engineer.add(
            conn,
            tenant_id,
            engineer.BacklogItem(
                item_uid=engineer.item_uid(tenant_id, "promote", pack.id),
                kind="promote",
                intake="hunt",
                rule_id="",
                title=f"promote hunt {pack.id} to a rule",
                reason=f"{pack.id} found {len(row['cases'] or [])} confirmed attack(s)",
                priority=engineer.PRIORITY["promote"],
                observability="have",
                evidence={
                    "pack_id": pack.id,
                    "case_uids": list(row["cases"] or []),
                    "run_uids": [r for r in row["runs"] or [] if r],
                    "event_uids": [u for evs in row["events"] or [] for u in (evs or [])][:20],
                    "pack": pack.to_json(),
                },
            ),
        )
        proposed += 1
    return proposed


# -- the daily cycle ----------------------------------------------------------------
@dataclass
class DailyReport:
    chosen: list[dict[str, Any]] = field(default_factory=list)
    runs: list[dict[str, Any]] = field(default_factory=list)
    outcomes: dict[str, int] = field(default_factory=dict)
    readiness: list[dict[str, Any]] = field(default_factory=list)
    tokens: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "chosen": self.chosen,
            "runs": self.runs,
            "outcomes": self.outcomes,
            "readiness": self.readiness,
            "tokens": self.tokens,
        }


def daily(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any = None,
    client: Any = None,
    limit: int = 0,
) -> DailyReport:
    """Run every due pack that can be answered, then one triage turn over all of them."""
    from shoc.detect import hunts

    packs = {p.id: p for p in hunts.load(config, conn, tenant_id)}
    report = DailyReport()
    pending: list[tuple[Any, Run]] = []
    for choice in select(conn, tenant_id, config, limit):
        pack = packs[choice.pack_id]
        run = run_pack(conn, store, tenant_id, pack, client, config, choice, triage=False)
        report.chosen.append(choice.to_json())
        if run.outcome in ("not_applicable", "learning"):
            continue
        if run.tuples:
            pending.append((pack, run))
    report.tokens = triaged(conn, store, tenant_id, pending, client, config)
    for pack in packs.values():
        ready = readiness(conn, tenant_id, pack)
        report.readiness.append(ready.to_json())
    for run_row in results(conn, tenant_id, days=1, limit=100):
        report.runs.append(
            {k: run_row.get(k) for k in ("run_uid", "pack_id", "outcome", "rows_returned", "error")}
        )
        outcome = str(run_row["outcome"])
        report.outcomes[outcome] = report.outcomes.get(outcome, 0) + 1
    promotions(conn, tenant_id, config)
    _learning_digest(conn, store, tenant_id, report.readiness)
    _suggest_feed(conn, tenant_id)
    return report


# A report feed written for cloud, identity and code-host estates. Suggested once,
# never switched on: a feed on by default needs its own RFC (D57).
SUGGESTED_FEED = {
    "feed": "datadog_security_labs",
    "parser": "rss",
    "settings": {"url": "https://securitylabs.datadoghq.com/rss/feed.xml"},
}


def _suggest_feed(conn: Conn, tenant_id: str) -> None:
    """Without a report feed, intel steers nothing; say so once, with the exact call."""
    from shoc.agents import manager

    if fetch_one(
        conn,
        """SELECT 1 FROM shoc.intel_feeds WHERE tenant_id = %s
             AND coalesce(nullif(parser, ''), feed) IN ('rss', 'otx_pulses', 'misp_events')""",
        (tenant_id,),
    ) or fetch_one(
        conn,
        "SELECT 1 FROM shoc.notices WHERE tenant_id = %s AND group_key = 'intel:report-feed'",
        (tenant_id,),
    ):
        return
    manager.tell(
        conn,
        tenant_id,
        "Hunter",
        "digest",
        "No threat-report feed is configured, so no report chooses what is hunted. One "
        "that covers cloud, identity and code hosts can be added with: intel.configure "
        + json.dumps(SUGGESTED_FEED),
        group_key="intel:report-feed",
        deliver=False,
    )


def _learning_digest(conn: Conn, store: Any, tenant_id: str, ready: list[dict[str, Any]]) -> None:
    """While a source is learning, once a week, the accounts becoming "normal".

    Whatever an account does in the learning period is the baseline later hunts
    compare against, so a stranger in it would be invisible for good. The
    operator is shown who is in it, and can spot one.
    """
    from shoc.agents import manager
    from shoc.store import ocsf as layout

    if datetime.now(UTC).weekday() != 0:
        return
    for row in [r for r in ready if r["state"] == "learning"]:
        for source in row["sources"][:3]:
            history = (
                fetch_one(
                    conn,
                    "SELECT products FROM shoc.source_history WHERE tenant_id = %s AND source = %s",
                    (tenant_id, source),
                )
                or {}
            )
            products = list(history.get("products") or [])
            if not products:
                continue
            with contextlib.suppress(Exception):
                actors = store.query(
                    f"SELECT actor_user_name AS actor, count(*) AS n FROM {layout.EVENTS_TABLE} "
                    "WHERE tenant_id = :tenant_id AND metadata_product = :product "
                    "AND time > :since AND actor_user_name IS NOT NULL "
                    "GROUP BY actor_user_name ORDER BY count(*) DESC",
                    {
                        "tenant_id": tenant_id,
                        "product": products[0],
                        "since": datetime.now(UTC) - timedelta(days=7),
                    },
                    20,
                ).rows
                if actors:
                    manager.tell(
                        conn,
                        tenant_id,
                        "Hunter",
                        "digest",
                        f"{source} is learning what is normal until {str(row['ready_at'])[:10]}. "
                        "These accounts are becoming its baseline; a name you do not know "
                        "here is worth a look: "
                        + ", ".join(f"{a['actor']} ({a['n']})" for a in actors),
                        group_key=f"learning:{source}",
                        deliver=False,
                    )


# -- the backlog (TaHiTI) ---------------------------------------------------------------
def add_to_backlog(
    conn: Conn,
    tenant_id: str,
    *,
    trigger: str,
    title: str,
    hypothesis: str = "",
    would_confirm: str = "",
    data_needed: str = "",
    why_now: str = "",
    attack: list[str] | None = None,
    priority: int = 3,
    evidence: dict[str, Any] | None = None,
) -> str:
    """Write a trigger up as an abstract and put it on the backlog."""
    uid = "HBL-" + hashlib.sha256(f"{tenant_id}|{trigger}|{title}".encode()).hexdigest()[:20]
    execute(
        conn,
        """INSERT INTO shoc.hunt_backlog
               (item_uid, tenant_id, trigger, title, hypothesis, would_confirm,
                data_needed, why_now, attack, priority, evidence)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (item_uid) DO UPDATE SET
               hypothesis = EXCLUDED.hypothesis, would_confirm = EXCLUDED.would_confirm,
               data_needed = EXCLUDED.data_needed, why_now = EXCLUDED.why_now,
               attack = EXCLUDED.attack, priority = EXCLUDED.priority,
               evidence = shoc.hunt_backlog.evidence || EXCLUDED.evidence
           WHERE shoc.hunt_backlog.state = 'open'""",
        (
            uid,
            tenant_id,
            trigger,
            title,
            hypothesis,
            would_confirm,
            data_needed,
            why_now,
            list(attack or []),
            priority,
            json.dumps(evidence or {}, default=str),
        ),
    )
    return uid


def backlog(
    conn: Conn, tenant_id: str, state: str = "open", limit: int = 100
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.hunt_backlog WHERE {' AND '.join(where)} "
        "ORDER BY priority, created_at DESC LIMIT %(limit)s",
        params,
    )


# -- packs for the backlog (RFC 0032) ---------------------------------------------------
# Once a day the Hunter takes the top of its backlog, one model turn per item:
# a pack behind the gate, or the reason there is none. A merged pack runs with
# the shipped ones from the next cycle, and its first concluded run closes the item.
PACK_ID = re.compile(r"^[a-z0-9][a-z0-9_]{2,79}$")
PACK_WHO = "agent:Hunter"
ITEMS_PER_DAY = 3
PACK_STEPS = 8
PACK_CALLS = 24
PACK_TOKENS_PER_DAY = 300_000
STUCK_AFTER = 3
# How long before the window a `first_seen` baseline fixture is placed.
BASELINE_DAYS_BEFORE = 10
# The shape `hunt.merge` takes, shown to the model.
EXAMPLE_PACK = {
    "id": "aws_secret_first_read",
    "title": "An identity reads a secret it never read",
    "hypothesis": "A stolen key is used to read secrets the identity behind it never "
    "touched, to move from one foothold to the credentials of others.",
    "attack": ["T1555.006"],
    "logsource": {"product": "aws", "service": "cloudtrail"},
    "window": "1d",
    "cadence_days": 1,
    "detection": {
        "selection": {"api.operation": ["GetSecretValue", "BatchGetSecretValue"]},
        "condition": "selection",
    },
    "baseline": {"first_seen": ["actor.user.name", "resource.uid"], "lookback": "30d"},
    "pivot": ["actor.user.name", "resource.uid", "src_endpoint.ip"],
    "triage": "Is this identity the service that owns the secret, deployed this week?",
    "follow_up": ["Did a deploy of the service that owns the secret run that day?"],
}
EXAMPLE_FIXTURES = {
    "source": "aws_cloudtrail",
    "surfaced": ["raw records as the source sends them, which the pack must return"],
    "baseline": ["raw records that make the surfaced ones routine"],
}


def merge_pack(
    conn: Conn, store: Any, tenant_id: str, config: Any, spec: dict[str, Any], who: str = PACK_WHO
) -> dict[str, Any]:
    """Merge a pack for an open backlog item behind the gate, or say exactly why not.

    With `dry_run` it runs the whole gate, needs no backlog item and writes nothing.
    A person's merge (`by_hand`) needs none either: it records its own (D130).
    """
    from shoc.detect import hunts
    from shoc.detect.compiler import compile_pack
    from shoc.errors import ConfigError, GateRefused

    uid = str(spec.get("item_uid") or "")
    dry = bool(spec.get("dry_run"))
    loose = not uid and (dry or bool(spec.get("by_hand")))
    item = {"item_uid": uid} if loose else _open_item(conn, tenant_id, uid)
    body = dict(spec.get("pack") or {})
    try:
        pack = hunts.from_dict(body)
        compile_pack(pack)
    except (ConfigError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise GateRefused.unparsed("the pack", exc) from exc
    refused: list[str] = []
    if not PACK_ID.match(pack.id):
        refused.append("the id must be lower_snake_case, 3 to 80 characters")
    here = next((p for p in hunts.load(config, conn, tenant_id) if p.id == pack.id), None)
    if here is not None:
        refused.append(
            f"'{pack.id}' is merged here: revert it first (hunt.revert)"
            if here.merged_by
            else f"'{pack.id}' ships in content/; merge yours under another id"
        )
    if not (pack.attack and pack.logsource.get("product")):
        refused.append("a pack needs attack and logsource.product")
    if pack.baseline.kind == "none":
        refused.append("a pack needs a baseline: first_seen or rare")
    ready = readiness(conn, tenant_id, pack)
    if ready.state == "not_applicable":
        refused.append(ready.reason)
    if refused:
        raise GateRefused(refused, "lint")
    fixtures = dict(spec.get("fixtures") or {})
    if why := _fixtures_fail(config, tenant_id, pack, fixtures):
        raise GateRefused([why], "fixtures")
    checked: dict[str, Any] = {"readiness": ready.state}
    if ready.state == "ready":
        now = datetime.now(UTC)
        run = Run(
            run_uid="gate",
            pack_id=pack.id,
            ingested_from=now - timedelta(seconds=pack.window_seconds),
            ingested_to=now,
        )
        try:
            rows = _query(store, tenant_id, pack, run, ready.accounts)
        except Exception as exc:
            raise GateRefused(
                [f"it does not run here: {type(exc).__name__}: {exc}"], "query"
            ) from exc
        tuples = len(group(tenant_id, "gate", pack, rows))
        if tuples > TOO_MANY_TUPLES:
            raise GateRefused(
                [
                    f"over our last {pack.window} it returns {tuples} tuples; triage reads "
                    f"at most {TOO_MANY_TUPLES}, so narrow the selection or the baseline"
                ],
                "volume",
            )
        checked.update(window=pack.window, rows=len(rows), tuples=tuples)
    if dry:
        return {"pack_id": pack.id, "item_uid": item["item_uid"], "checked": checked}
    if not item["item_uid"]:
        item = {
            "item_uid": add_to_backlog(
                conn,
                tenant_id,
                trigger=who,
                title=pack.title,
                hypothesis=pack.hypothesis,
                attack=list(pack.attack),
            ),
            "title": pack.title,
        }
    execute(
        conn,
        """INSERT INTO shoc.merged_hunts
               (tenant_id, pack_id, body, fixtures, checked, item_uid, reason, merged_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, pack_id) DO UPDATE SET
               body = EXCLUDED.body, fixtures = EXCLUDED.fixtures, checked = EXCLUDED.checked,
               item_uid = EXCLUDED.item_uid, reason = EXCLUDED.reason,
               merged_by = EXCLUDED.merged_by, state = 'merged', merged_at = now(),
               reverted_at = NULL""",
        (
            tenant_id,
            pack.id,
            json.dumps(body, default=str),
            json.dumps(fixtures, default=str),
            json.dumps(checked),
            item["item_uid"],
            str(spec.get("reason") or "")[:500],
            who,
        ),
    )
    execute(
        conn,
        """UPDATE shoc.hunt_backlog
              SET state = 'packed', pack_id = %s, decided_at = now(), decided_by = %s
            WHERE tenant_id = %s AND item_uid = %s AND state = 'open'""",
        (pack.id, who, tenant_id, item["item_uid"]),
    )
    _tell_manager(
        conn,
        tenant_id,
        f"New hunt pack {pack.id} merged for '{str(item['title'])[:120]}'"
        + (
            f"; {checked['tuples']} tuple(s) over our last {pack.window}."
            if "tuples" in checked
            else f"; it is {ready.state} here."
        ),
    )
    return {"pack_id": pack.id, "item_uid": item["item_uid"], "checked": checked}


def revert_pack(conn: Conn, tenant_id: str, pack_id: str, reason: str, who: str) -> dict[str, Any]:
    """Take back a merged pack; it stops running. A shipped pack is not in reach."""
    from shoc.errors import NotFound

    row = fetch_one(
        conn,
        """UPDATE shoc.merged_hunts SET state = 'reverted', reverted_at = now(), reason = %s
           WHERE tenant_id = %s AND pack_id = %s AND state = 'merged'
           RETURNING item_uid""",
        (f"reverted by {who}: {reason}"[:1000], tenant_id, pack_id),
    )
    if not row:
        raise NotFound(
            f"'{pack_id}' is not a merged pack; a shipped pack stays a human's to change"
        )
    _decide(
        conn,
        tenant_id,
        str(row["item_uid"]),
        "rejected",
        who,
        {"decision": "reverted", "because": reason[:500]},
        states=("packed", "done"),
    )
    _tell_manager(conn, tenant_id, f"Hunt pack {pack_id} reverted: {reason[:200]}")
    return {"pack_id": pack_id, "state": "reverted"}


def _open_item(conn: Conn, tenant_id: str, uid: str) -> dict[str, Any]:
    from shoc.errors import GateRefused

    if not uid:
        raise GateRefused(["name the backlog item this answers (item_uid)"], "item")
    row = fetch_one(
        conn,
        "SELECT * FROM shoc.hunt_backlog WHERE tenant_id = %s AND item_uid = %s",
        (tenant_id, uid),
    )
    if not row or row["state"] != "open":
        raise GateRefused([f"'{uid}' is not an open hunt backlog item here"], "item")
    return row


def _fixtures_fail(config: Any, tenant_id: str, pack: Any, fixtures: dict[str, Any]) -> str:
    """Why the pack does not return its surfaced fixture and stay quiet once its
    baseline fixture came first, or ''. Run in a scratch tenant, the way
    tests/conformance/test_hunts.py runs every shipped pack."""
    from shoc.agents.detection_engineer import _scratch
    from shoc.ingest import batch, ocsf
    from shoc.ingest.replay import expand

    source = str(fixtures.get("source") or "")
    if source not in ocsf.available_sources():
        return f"fixtures name source '{source}'; use one of {', '.join(ocsf.available_sources())}"
    surfaced = [r for r in fixtures.get("surfaced") or [] if isinstance(r, dict)]
    baseline = [r for r in fixtures.get("baseline") or [] if isinstance(r, dict)]
    if not surfaced or not baseline:
        return "a pack needs a surfaced and a baseline fixture"
    mapping = ocsf.load_mapping(source)
    scratch = _scratch(config, tenant_id, "hunt_gate")

    def load(records: list[dict[str, Any]], when: datetime) -> None:
        rows = [mapping.map_record(r, scratch.tenant_id) for r in expand(records, source, when)]
        batch.load(scratch, rows)

    def returned(since: datetime) -> bool:
        run = Run(
            run_uid="gate",
            pack_id=pack.id,
            ingested_from=since,
            ingested_to=datetime.now(UTC) + timedelta(seconds=1),
        )
        return bool(_query(scratch, scratch.tenant_id, pack, run, []))

    try:
        since = datetime.now(UTC) - timedelta(seconds=1)
        load(surfaced, datetime.now(UTC))
        if not returned(since):
            return "it did not return its surfaced fixture"
        scratch.reset()
        # A floor (`seen_by_at_least` alone) only rises with more events: its
        # baseline is the normal shape, which must stay quiet on its own.
        floor_only = pack.baseline.seen_by_at_least and not pack.baseline.seen_by_fewer_than
        now = datetime.now(UTC)
        if not floor_only:
            before = now - timedelta(days=BASELINE_DAYS_BEFORE)
            load(baseline, before if pack.baseline.kind == "first_seen" else now)
        since = datetime.now(UTC)
        load(baseline if floor_only else surfaced, datetime.now(UTC))
        if returned(since):
            return "its baseline fixture did not silence it"
        return ""
    finally:
        with contextlib.suppress(Exception):
            scratch.reset()
        scratch.close()


def _decide(
    conn: Conn,
    tenant_id: str,
    uid: str,
    state: str,
    who: str,
    note: dict[str, Any],
    states: tuple[str, ...] = ("open",),
    drop: tuple[str, ...] = (),
) -> int:
    """Move an item in one of `states` to `state`, noting why; `drop` clears stale notes."""
    return execute(
        conn,
        """UPDATE shoc.hunt_backlog
              SET state = %s, decided_at = now(), decided_by = %s,
                  evidence = (evidence - %s::text[]) || %s
            WHERE tenant_id = %s AND item_uid = %s AND state = ANY(%s)""",
        (state, who, list(drop), json.dumps(note, default=str), tenant_id, uid, list(states)),
    )


def decide_item(
    conn: Conn, tenant_id: str, item_uid: str, state: str, who: str, reason: str = ""
) -> None:
    """A person reopens, rejects or marks an item done, and says why (DET-8, D132).

    The same rule as a detection item's: ending one needs a reason, kept as its
    `because`. What the Hunter put off is stale once a person decided, and a
    reopened item gets its tries back.
    """
    from shoc.errors import NotFound, ValidationError

    if state not in ("rejected", "done", "open"):
        raise ValidationError(f"unknown backlog state '{state}'")
    reason = reason.strip()[:500]
    if state != "open" and not reason:
        raise ValidationError(f"say why it is {state}: the item shows the reason once it is closed")
    note = (
        {"reopened": reason or f"reopened by {who}"}
        if state == "open"
        else {"decision": state, "because": reason}
    )
    every = ("open", "packed", "rejected", "done")
    drop = ("later", "tries") if state == "open" else ("later",)
    if not _decide(conn, tenant_id, item_uid, state, who, note, every, drop):
        raise NotFound(f"no hunt backlog item '{item_uid}'")


def _tell_manager(conn: Conn, tenant_id: str, body: str) -> None:
    from shoc.agents import manager

    with contextlib.suppress(Exception):
        manager.tell(conn, tenant_id, "Hunter", "digest", body, deliver=False)


def work_backlog(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any = None,
    client: Any = None,
    limit: int = ITEMS_PER_DAY,
) -> dict[str, Any]:
    """Reopen gaps a new source closed, then one model turn per item, priority first."""
    from shoc.agents.llm import NoLLM, from_config
    from shoc.config import Config

    cfg = config or Config.load()
    counted: dict[str, int] = {}
    if reopened := _reopen_gaps(conn, tenant_id):
        counted["reopened"] = reopened
    client = client if client is not None else from_config(cfg, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return {"worked": 0, "outcomes": counted, "why": "no model is configured"}
    items = fetch_all(
        conn,
        """SELECT item_uid, trigger, title, hypothesis, would_confirm, data_needed, why_now,
                  attack, priority, evidence
           FROM shoc.hunt_backlog WHERE tenant_id = %s AND state = 'open'
           ORDER BY priority, evidence->>'worked_at' NULLS FIRST, created_at
           LIMIT %s""",
        (tenant_id, max(1, limit)),
    )
    if not items:
        return {"worked": 0, "outcomes": counted, "why": "the backlog is empty"}
    spent = _pack_tokens_today(conn, tenant_id)
    tokens, worked, reasoning = 0, 0, []
    context = _pack_context(conn, tenant_id, cfg)
    for item in items:
        if spent + tokens >= PACK_TOKENS_PER_DAY:
            reasoning.append(f"stopped at the daily ceiling of {PACK_TOKENS_PER_DAY} tokens")
            break
        outcome, because, used = _work_item(conn, store, tenant_id, cfg, client, item, context)
        tokens += used
        worked += 1
        counted[outcome] = counted.get(outcome, 0) + 1
        reasoning.append(f"{item['item_uid']}: {outcome} — {because}")
    return {
        "worked": worked,
        "outcomes": counted,
        "reasoning": " ".join(reasoning)[:2000],
        "tokens": tokens,
    }


def _pack_tokens_today(conn: Conn, tenant_id: str) -> int:
    row = (
        fetch_one(
            conn,
            """SELECT coalesce(sum((evidence->>'tokens_today')::int), 0) AS n
               FROM shoc.hunt_backlog
               WHERE tenant_id = %s AND (evidence->>'worked_at')::date = current_date""",
            (tenant_id,),
        )
        or {}
    )
    return int(row.get("n") or 0)


def _reopen_gaps(conn: Conn, tenant_id: str) -> int:
    """An item ended `source_gap` comes back once a source sends what it waited for."""
    from shoc.agents.detection_engineer import _delivering

    delivering = _delivering(conn, tenant_id)
    if not delivering:
        return 0
    rows = fetch_all(
        conn,
        """SELECT item_uid, evidence->'waiting_for' AS waiting FROM shoc.hunt_backlog
           WHERE tenant_id = %s AND state = 'rejected'
             AND evidence->>'decision' = 'source_gap'""",
        (tenant_id,),
    )
    reopened = 0
    for row in rows:
        if not set(row["waiting"] or []) & delivering:
            continue
        execute(
            conn,
            """UPDATE shoc.hunt_backlog
                  SET state = 'open', decided_at = NULL, decided_by = NULL,
                      evidence = (evidence - 'decision' - 'tries') || %s
                WHERE tenant_id = %s AND item_uid = %s""",
            (
                json.dumps({"reopened_at": datetime.now(UTC).isoformat()}),
                tenant_id,
                row["item_uid"],
            ),
        )
        reopened += 1
    return reopened


def _pack_context(conn: Conn, tenant_id: str, config: Any) -> str:
    """What every item's turn is told: what we ingest, the packs there are, the shape."""
    from shoc.agents.detection_engineer import _delivering
    from shoc.detect import hunts
    from shoc.ingest import ocsf
    from shoc.store import ocsf as layout

    packs = [
        {
            "id": p.id,
            "title": p.title,
            "attack": p.attack,
            "logsource": p.logsource,
            "baseline": p.baseline.kind,
        }
        for p in hunts.load(config, conn, tenant_id)
    ]
    delivering = _delivering(conn, tenant_id)
    logsources = sorted(
        {
            f"{product}/{service}" if service else product
            for (product, service), names in layout.products().items()
            if set(names) & delivering
        }
    )
    return "\n".join(
        [
            f"Logsources delivering here (product/service): {', '.join(logsources) or 'none'}.",
            f"Fixture sources (raw records): {', '.join(ocsf.available_sources())}.",
            f"A pack returns at most {TOO_MANY_TUPLES} tuples over one window here.",
            "",
            "Packs that exist here:",
            json.dumps(packs),
            "",
            "Call hunt.merge with `item_uid`, `pack` in this shape, and `fixtures`:",
            json.dumps(EXAMPLE_PACK),
            json.dumps(EXAMPLE_FIXTURES),
        ]
    )


def _work_item(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any,
    client: Any,
    item: dict[str, Any],
    context: str,
) -> tuple[str, str, int]:
    """One model turn for one item, and what code records about it."""
    from shoc.agents import ops, roles, safety, tools
    from shoc.agents.llm import complete_typed
    from shoc.store import ocsf as layout

    uid = str(item["item_uid"])
    prompt = "\n".join(
        [
            "End this hunt backlog item: `packed` once hunt.merge accepted a pack, "
            "`covered`, `not_worth` or `source_gap` when no pack should be written, "
            "`later` only when something you need is missing today, and say what.",
            "",
            safety.quote("hunt_backlog_item", item),
            "",
            context,
        ]
    )
    evidence = dict(item["evidence"] or {})
    tries = int(evidence.get("tries") or 0) + 1
    note: dict[str, Any] = {"worked_at": datetime.now(UTC).isoformat(), "tries": tries}
    try:
        answer, usage = complete_typed(
            client,
            safety.system_prompt(roles.HUNTER_PACK_PROMPT),
            prompt,
            roles.HuntBacklogOutput,
            config.llm_max_tokens,
            tools=tools.specs(roles.HUNTER_PACK_TOOLS, "Hunter"),
            invoke=tools.invoker(
                tenant_id, config, roles.HUNTER_PACK_TOOLS, who="Hunter", db=conn, store=store
            ),
            max_steps=PACK_STEPS,
            max_calls=PACK_CALLS,
        )
    except Exception as exc:
        with contextlib.suppress(Exception):
            ops.record_failure(
                conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
            )
        _note(conn, tenant_id, uid, note)
        return "failed", type(exc).__name__, 0
    ops.charge(conn, tenant_id, usage)
    note["tokens_today"] = usage.tokens
    outcome = next((o for o in answer.outcomes if str(o.item_uid) == uid), None)
    kind = outcome.outcome if outcome else "later"
    because = str(outcome.because if outcome else answer.reasoning)[:500]
    packed = fetch_one(
        conn,
        "SELECT pack_id FROM shoc.merged_hunts WHERE tenant_id = %s AND item_uid = %s AND state = 'merged'",
        (tenant_id, uid),
    )
    if packed:
        kind = "packed"  # the gate's record outranks what the model says it did
    elif kind == "packed":
        kind = "later"
        said = [a for n, a in zip(usage.lookups, usage.seen, strict=False) if n == "hunt_merge"]
        note["gate"] = said[-1][:800] if said else "hunt.merge was never called"
        because = f"the gate did not accept a pack: {because}"
    if kind in ("covered", "not_worth", "source_gap"):
        decided: dict[str, Any] = {"decision": kind, "because": because}
        if outcome and outcome.pack_id:
            decided["covered_by"] = str(outcome.pack_id)[:80]
        if kind == "source_gap":
            named = {str(p).lower() for p in (outcome.products if outcome else [])}
            # A logsource product (`aws`) is waited for as the products it maps to.
            decided["waiting_for"] = sorted(
                {n for (p, _), names in layout.products().items() if p in named for n in names}
                or named
            )
        _decide(conn, tenant_id, uid, "rejected", PACK_WHO, decided)
    elif kind == "later":
        note["later"] = because
        if tries >= STUCK_AFTER:
            _decide(
                conn,
                tenant_id,
                uid,
                "rejected",
                PACK_WHO,
                {"decision": "stuck", "because": because},
            )
            kind = "stuck"
    _note(conn, tenant_id, uid, note)
    return kind, because, usage.tokens


def _note(conn: Conn, tenant_id: str, uid: str, note: dict[str, Any]) -> None:
    execute(
        conn,
        "UPDATE shoc.hunt_backlog SET evidence = evidence || %s WHERE tenant_id = %s AND item_uid = %s",
        (json.dumps(note, default=str), tenant_id, uid),
    )


def results(
    conn: Conn, tenant_id: str, pack_id: str = "", days: int = 7, limit: int = 100
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s", "ran_at > now() - %(days)s * interval '1 day'"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "days": days, "limit": limit}
    if pack_id:
        where.append("pack_id = %(pack_id)s")
        params["pack_id"] = pack_id
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.hunt_runs WHERE {' AND '.join(where)} "
        "ORDER BY ran_at DESC LIMIT %(limit)s",
        params,
    )


def metrics(conn: Conn, tenant_id: str, days: int = 30) -> dict[str, Any]:
    """What PEAK says counts: detections created and gaps closed, not runs."""
    runs = fetch_all(
        conn,
        """SELECT outcome, count(*) AS n FROM shoc.hunt_runs
           WHERE tenant_id = %s AND ran_at > now() - %s * interval '1 day'
           GROUP BY outcome""",
        (tenant_id, days),
    )
    promoted = (
        fetch_one(
            conn,
            "SELECT count(*) AS n FROM shoc.detection_backlog WHERE tenant_id = %s AND intake = 'hunt'",
            (tenant_id,),
        )
        or {}
    )
    gaps = (
        fetch_one(
            conn,
            """SELECT count(*) FILTER (WHERE state = 'open') AS open,
                  count(*) FILTER (WHERE state IN ('packed','done')) AS closed
           FROM shoc.hunt_backlog WHERE tenant_id = %s""",
            (tenant_id,),
        )
        or {}
    )
    packs = fetch_all(
        conn,
        "SELECT readiness, count(*) AS n FROM shoc.hunt_packs WHERE tenant_id = %s GROUP BY readiness",
        (tenant_id,),
    )
    covered = (
        fetch_one(
            conn,
            """SELECT count(DISTINCT pack_id) AS n FROM shoc.hunt_runs
           WHERE tenant_id = %s AND ran_at > now() - %s * interval '1 day'
             AND outcome <> 'gap'""",
            (tenant_id, days),
        )
        or {}
    )
    return {
        "days": days,
        "by_outcome": {str(r["outcome"]): int(r["n"]) for r in runs},
        "readiness": {str(r["readiness"] or "unknown"): int(r["n"]) for r in packs},
        "detections_proposed": int(promoted.get("n") or 0),
        "gaps_open": int(gaps.get("open") or 0),
        "gaps_closed": int(gaps.get("closed") or 0),
        "packs_hunted": int(covered.get("n") or 0),
    }


# -- the narrow case: indicator search ------------------------------------------------
@dataclass
class Suggestion:
    value: str
    field: str
    reason: str
    priority: int = 3

    def to_json(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "field": self.field,
            "reason": self.reason,
            "priority": self.priority,
        }


def suggest(conn: Conn, tenant_id: str, limit: int = 10) -> list[Suggestion]:
    """Indicators nobody has searched for yet. Enrichment, not hunting."""
    out: list[Suggestion] = []
    for row in fetch_all(
        conn,
        """SELECT value, type, source FROM shoc.iocs
           WHERE tenant_id = %s AND retro_hunted_at IS NULL AND type IN ('ip','domain')
           ORDER BY confidence DESC LIMIT %s""",
        (tenant_id, limit),
    ):
        out.append(
            Suggestion(
                value=row["value"],
                field="src_ip" if row["type"] == "ip" else "domain",
                reason=f"new indicator from {row['source']} that nobody has searched for yet",
                priority=1,
            )
        )
    for row in fetch_all(
        conn,
        """SELECT DISTINCT f.entity_key, f.rule_id, f.severity FROM shoc.findings f
           WHERE f.tenant_id = %s AND f.severity IN ('high','critical')
             AND f.last_seen > now() - interval '7 days'
           ORDER BY f.entity_key LIMIT %s""",
        (tenant_id, limit),
    ):
        if row["entity_key"]:
            out.append(
                Suggestion(
                    value=str(row["entity_key"]).split("|")[0],
                    field="auto",
                    reason=f"behind a {row['severity']} finding from {row['rule_id']} this week",
                    priority=2,
                )
            )
    seen: dict[str, Suggestion] = {}
    for suggestion in sorted(out, key=lambda s: s.priority):
        seen.setdefault(suggestion.value, suggestion)
    return list(seen.values())[:limit]
