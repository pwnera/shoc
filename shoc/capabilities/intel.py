"""Threat-intelligence capabilities (DET-4, DET-6, DET-7).

Sources and matching are DET-4: poll indicator sources, match them forward
against new events, retro-hunt anything new across the retention window.
`intel.add` and `intel.remove` handle indicators somebody hands in or withdraws.
`intel.lookup` (DET-6) is the on-demand half — research one indicator across
OSINT sources and our own history, the way an analyst would — and
`intel.digest` (DET-7) reads a threat report, handed in or polled from a report
source, and turns it into indicators, techniques and hunts. See RFC 0004 and
RFC 0016.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.detect import intake, intel
from shoc.errors import ConfigError
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json

if TYPE_CHECKING:
    from shoc.detect.report import Document

_ANNOUNCED: set[str] = set()


def _announce(hosts_by_source: dict[str, str]) -> None:
    """Say which hosts a refresh reaches, once per process.

    A default feed is an outbound connection the operator did not ask for. It
    stays enabled, because intel nobody switched on is intel nobody has, but it
    does not happen quietly.
    """
    import logging

    fresh = [n for n in hosts_by_source if n not in _ANNOUNCED]
    if not fresh:
        return
    _ANNOUNCED.update(fresh)
    hosts = sorted({hosts_by_source[n] for n in fresh})
    logging.getLogger("shoc.intel").info(
        "pulling threat intel from: %s. SHOC_INTEL_FEEDS=off stops this.", ", ".join(hosts)
    )


@dataclass
class RefreshInput:
    feed: str = f("", doc="One source, or empty for every enabled source")
    retro_hunt: bool = f(True, doc="Search the retention window for indicators that are new to us")


@dataclass
class RefreshReport:
    feeds: list[dict[str, Any]] = field(default_factory=list)
    indicators_new: int = 0
    expired_removed: int = 0
    retro_hunt: dict[str, Any] = field(default_factory=dict)


@capability(
    name="intel.refresh",
    summary="Poll threat-intel sources and retro-hunt anything new",
    input=RefreshInput,
    output=RefreshReport,
    scope="intel:write",
    principals=("human", "agent", "external_agent", "service"),
    audit=True,
    tags=("intel", "write"),
)
def refresh(ctx: Context, inp: RefreshInput) -> Result:
    from shoc.db.pool import fetch_all
    from shoc.db.secrets import open_secret

    configured = {
        r["feed"]: r
        for r in fetch_all(
            ctx.db,
            "SELECT feed, parser, enabled, settings, secret FROM shoc.intel_feeds "
            "WHERE tenant_id = %s",
            (ctx.tenant_id,),
        )
    }
    defaults = intel.default_feeds(ctx.config.intel_feeds)
    names = (
        [inp.feed]
        if inp.feed
        # A default feed somebody disabled stays disabled.
        else sorted(
            {
                *[d for d in defaults if d not in configured],
                *[k for k, v in configured.items() if v["enabled"]],
            }
        )
    )
    if not names:
        return Result(
            data=RefreshReport(
                feeds=[],
                indicators_new=0,
                expired_removed=0,
                retro_hunt={"indicators": 0, "hits": 0, "findings": []},
            ),
            summary="No intel feed is enabled (SHOC_INTEL_FEEDS=off), so nothing was contacted.",
        )
    sources = {}
    for name in names:
        row = configured.get(name, {})
        sources[name] = (row.get("parser") or name, dict(row.get("settings") or {}), row)
    _announce({n: intel.host_of(p, s) for n, (p, s, _) in sources.items()})
    abuse_ch = _lookup_secret(ctx, "abuse_ch")
    company = intake.profile(ctx.db, ctx.tenant_id)
    results: dict[str, intel.FeedResult] = {}
    for name, (parser, settings, row) in sources.items():
        secret = (
            open_secret(ctx.config.master_key, row["secret"], ctx.tenant_id, "intel_feeds", name)
            if row.get("secret")
            else {}
        )
        # The abuse.ch key configured for lookups is the feeds' key too (RFC 0030).
        if parser.startswith("abuse_ch") and not secret:
            secret = abuse_ch
        if parser in intel.REPORT_FEEDS:
            results[name] = _queue_reports(ctx, name, parser, settings, secret, company)
        else:
            results[name] = intel.refresh(ctx.db, ctx.tenant_id, name, settings, secret, parser)
    report_sources = {n: s for n, (p, s, _) in sources.items() if p in intel.REPORT_FEEDS}
    # Without a feed named, the queue is read even with no report source: a
    # report an agent handed in on a spent day waits there too.
    if report_sources or not inp.feed:
        _read_queue(ctx, report_sources, results, company, only=inp.feed)
        for name in report_sources:
            intel.record_run(ctx.db, ctx.tenant_id, name, report_sources[name], results[name])
    reports = [
        {"feed": r.feed, "fetched": r.fetched, "stored": r.stored, "error": r.error}
        for r in results.values()
    ]
    expired = intel.prune(ctx.db, ctx.tenant_id)
    hunted = (
        intel.retro_hunt(ctx.db, ctx.store, ctx.tenant_id)
        if inp.retro_hunt
        else {"indicators": 0, "hits": 0, "findings": []}
    )
    new = sum(r["stored"] for r in reports)
    failed = [r["feed"] for r in reports if r["error"]]
    return Result(
        data=RefreshReport(
            feeds=reports, indicators_new=new, expired_removed=expired, retro_hunt=hunted
        ),
        summary=(
            f"{new} new indicator(s) or report(s) from {len(reports)} source(s)"
            + (f" ({len(failed)} failed: {', '.join(failed)})" if failed else "")
            + f"; retro-hunt found {hunted['hits']} hit(s) in the last 90 days."
        ),
        citations=hunted["findings"],
    )


# A queued report is tried this many times, and waits at most this long before
# it is dropped unread; any row the queue keeps goes after `KEEP_DAYS`.
MAX_ATTEMPTS = 3
QUEUE_DAYS = 7
KEEP_DAYS = 30
# Feed name for a report an agent handed in when the day's budget was spent.
HANDED_IN = "handed-in"
QUEUE_STATES = ("waiting", "skipped", "same_story", "dropped")


def _queue_reports(
    ctx: Context,
    name: str,
    parser: str,
    settings: dict[str, Any],
    secret: dict[str, Any],
    company: intake.Profile,
) -> intel.FeedResult:
    """Queue and score what a report source published that we have not seen (DET-7).

    Every unread item is queued, so one the source has stopped listing by the
    next poll is still read. Each is scored on what the feed says about it; an
    item that scores too low is skipped and one that repeats a story read in
    the last two weeks is linked to it, both with the reason, and neither is
    read. An item published more than a week ago is not queued at all
    (RFC 0029).
    """
    from shoc.db.pool import execute
    from shoc.detect import report as reader

    result = intel.FeedResult(feed=name)
    try:
        items = intel.REPORT_FEEDS[parser](settings, secret)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"[:1000]
        return result
    result.fetched = len(items)
    grade = int(settings.get("grade") or 0)
    oldest = datetime.now(UTC) - timedelta(days=QUEUE_DAYS)
    earlier = intake.recent_reports(ctx.db, ctx.tenant_id)
    for item in items:
        if item.published and item.published < oldest:
            continue
        url = intel.canonical(item.url)
        summary = item.summary or item.text[: intel.SUMMARY_CHARS]
        score, reason = intake.score(
            item.title, summary, item.categories, item.published, grade, company
        )
        twin = intake.same_as(item.title, summary, earlier)
        state = "same_story" if twin else "waiting" if score >= intake.TRIAGE else "skipped"
        execute(
            ctx.db,
            """INSERT INTO shoc.intel_queue
                   (tenant_id, feed, url, title, text, summary, published_at, score, reason,
                    state, same_as)
               SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
               WHERE NOT EXISTS (SELECT 1 FROM shoc.intel_reports
                                 WHERE tenant_id = %s AND url IN (%s, %s))
               ON CONFLICT (tenant_id, url) DO NOTHING""",
            (
                ctx.tenant_id,
                name,
                url,
                item.title[:500],
                item.text[: reader.MAX_TEXT],
                summary,
                item.published,
                score,
                f"same story as {twin}" if twin else reason,
                state,
                twin,
                ctx.tenant_id,
                url,
                item.url,
            ),
        )
    return result


def _spent_today(ctx: Context) -> tuple[int, int]:
    """Reports read and tokens spent reading them today, triage calls included."""
    from shoc.db.pool import fetch_one

    row = (
        fetch_one(
            ctx.db,
            """SELECT (SELECT count(*) FROM shoc.intel_reports
                       WHERE tenant_id = %(t)s AND digested_at >= current_date) AS reports,
                      (SELECT coalesce(sum(tokens), 0) FROM shoc.intel_reports
                       WHERE tenant_id = %(t)s AND digested_at >= current_date)
                    + (SELECT coalesce(sum(tokens), 0) FROM shoc.intel_queue
                       WHERE tenant_id = %(t)s AND triaged_at >= current_date) AS tokens""",
            {"t": ctx.tenant_id},
        )
        or {}
    )
    return int(row.get("reports") or 0), int(row.get("tokens") or 0)


def _caps(ctx: Context) -> tuple[int, int]:
    from shoc.agents.llm import budget

    return (
        int(budget(ctx.db, ctx.tenant_id, "intel_reports_per_day")),
        int(budget(ctx.db, ctx.tenant_id, "intel_tokens_per_day")),
    )


def _set_state(ctx: Context, url: str, state: str, reason: str, **extra: Any) -> None:
    from shoc.db.pool import execute

    sets = ", ".join(f"{k} = %({k})s" for k in extra)
    execute(
        ctx.db,
        f"""UPDATE shoc.intel_queue SET state = %(state)s, reason = %(reason)s,
                   changed_at = now(){", " + sets if sets else ""}
            WHERE tenant_id = %(tenant_id)s AND url = %(url)s""",
        {"state": state, "reason": reason[:500], "tenant_id": ctx.tenant_id, "url": url, **extra},
    )


def _read_queue(
    ctx: Context,
    sources: dict[str, dict[str, Any]],
    results: dict[str, intel.FeedResult],
    company: intake.Profile,
    only: str = "",
) -> None:
    """Read the waiting items best-first until the day's cap is reached (RFC 0029).

    Across every report source, ordered by score. Each read must fit in the
    tokens left today at an estimate of four characters a token plus the
    prompt; `max_items` still caps one source per poll. An item between the
    triage and read thresholds is first put to the cheap model. An item that
    fails is tried again on the next poll, three times in all; one still
    waiting after a week is dropped. A missing model stops them all.
    """
    from collections import Counter

    from shoc.db.pool import execute, fetch_all
    from shoc.detect import report as reader

    errors: dict[str, list[str]] = {name: [] for name in results}
    for row in fetch_all(
        ctx.db,
        """UPDATE shoc.intel_queue SET state = 'dropped', changed_at = now(),
               reason = CASE WHEN attempts >= %s THEN 'failed ' || attempts || ' times'
                             ELSE 'not read within ' || %s || ' days: the daily budget' END
           WHERE tenant_id = %s AND state = 'waiting'
             AND (attempts >= %s OR queued_at < now() - %s * interval '1 day')
           RETURNING feed""",
        (MAX_ATTEMPTS, QUEUE_DAYS, ctx.tenant_id, MAX_ATTEMPTS, QUEUE_DAYS),
    ):
        errors.setdefault(row["feed"], []).append("dropped")
    for name, said in errors.items():
        if said:
            errors[name] = [
                f"{len(said)} report(s) dropped unread after {MAX_ATTEMPTS} failures or "
                f"{QUEUE_DAYS} days; raise the intel budget if good ones wait too long"
            ]
    execute(
        ctx.db,
        """DELETE FROM shoc.intel_queue WHERE tenant_id = %s AND state <> 'waiting'
             AND queued_at < now() - %s * interval '1 day'""",
        (ctx.tenant_id, KEEP_DAYS),
    )
    cap_reports, cap_tokens = _caps(ctx)
    read, spent = _spent_today(ctx)
    waiting = fetch_all(
        ctx.db,
        """SELECT feed, url, title, text, summary, score, tokens, triaged_at
           FROM shoc.intel_queue
           WHERE tenant_id = %s AND state = 'waiting' AND (%s = '' OR feed = %s)
           ORDER BY score DESC, queued_at, url""",
        (ctx.tenant_id, only, only),
    )
    taken: Counter[str] = Counter()
    try:
        for item in waiting:
            if read >= cap_reports or spent >= cap_tokens:
                break
            feed = str(item["feed"])
            if taken[feed] >= max(1, int(sources.get(feed, {}).get("max_items", 5))):
                continue
            twin = intake.same_as(
                item["title"], item["summary"], intake.recent_reports(ctx.db, ctx.tenant_id)
            )
            if twin:
                _set_state(ctx, item["url"], "same_story", f"same story as {twin}", same_as=twin)
                continue
            extra = int(item["tokens"] or 0)
            if item["score"] < intake.READ and item["triaged_at"] is None:
                verdict, cost = _triage(ctx, item, company)
                spent += cost
                extra += cost
                if not verdict.read:
                    _set_state(
                        ctx,
                        item["url"],
                        "skipped",
                        f"triage: {verdict.why}",
                        tokens=extra,
                        triaged_at=datetime.now(UTC),
                    )
                    continue
                _set_state(
                    ctx,
                    item["url"],
                    "waiting",
                    f"triage: {verdict.why}",
                    tokens=extra,
                    triaged_at=datetime.now(UTC),
                )
            text = str(item["text"] or "")
            estimate = (min(len(text), reader.PROSE_LIMIT) if text else reader.PROSE_LIMIT) // 4
            if spent + estimate + 3_000 > cap_tokens:
                continue
            pasted = item["url"].startswith("pasted:")
            try:
                doc = (
                    reader.Document(
                        url="" if pasted else item["url"],
                        title=item["title"],
                        text=text,
                        content_type="text/plain",
                        bytes=len(text),
                    )
                    if text
                    else reader.fetch(item["url"])
                )
                out = _digest(
                    ctx,
                    doc,
                    store=True,
                    retro_hunt=False,
                    source="" if feed == HANDED_IN else feed,
                    company=company,
                    extra_tokens=extra,
                )
            except ConfigError:
                raise
            except Exception as exc:
                errors.setdefault(feed, []).append(f"{item['url']}: {type(exc).__name__}: {exc}")
                execute(
                    ctx.db,
                    "UPDATE shoc.intel_queue SET attempts = attempts + 1 "
                    "WHERE tenant_id = %s AND url = %s",
                    (ctx.tenant_id, item["url"]),
                )
                continue
            execute(
                ctx.db,
                "DELETE FROM shoc.intel_queue WHERE tenant_id = %s AND url = %s",
                (ctx.tenant_id, item["url"]),
            )
            taken[feed] += 1
            read += 1
            spent += int(out.data.tokens or 0)
            if feed in results and not out.summary.startswith("Already read"):
                results[feed].stored += 1
    except ConfigError as exc:
        for name in results:
            if name in sources:
                errors.setdefault(name, []).append(f"ConfigError: {exc}")
    for name, said in errors.items():
        if name in results and said:
            before = results[name].error
            results[name].error = "; ".join([*([before] if before else []), *said])[:1000]


def _triage(ctx: Context, item: dict[str, Any], company: intake.Profile) -> tuple[Any, int]:
    """Put a middle-band item to the cheap model: title and feed summary only."""
    from shoc.agents import ops, roles, safety
    from shoc.agents.llm import NoLLM, complete_typed, for_hint, from_config

    client = from_config(ctx.config, ctx.db, ctx.tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        raise ConfigError("reading threat reports needs a model: set SHOC_LLM_PROVIDER")
    prompt = "\n".join(
        [
            company.describe(),
            "",
            safety.quote(
                "feed_item",
                f"{item['title']}\n\n{' '.join(str(item['summary'] or '').split()[:300])}",
            ),
        ]
    )
    answer, usage = complete_typed(
        for_hint(client, "cheap", ctx.config),
        safety.system_prompt(roles.CTI_TRIAGE_PROMPT),
        prompt,
        roles.CtiTriageOutput,
        300,
    )
    ops.charge(ctx.db, ctx.tenant_id, usage)
    return answer, int(usage.tokens)


def _lookup_secret(ctx: Context, source: str) -> dict[str, Any]:
    """A keyed lookup source's secret, or {} when it is not configured (RFC 0030)."""
    from shoc.db.pool import fetch_one
    from shoc.db.secrets import open_secret

    row = fetch_one(
        ctx.db,
        "SELECT secret FROM shoc.lookup_sources WHERE tenant_id = %s AND source = %s AND enabled",
        (ctx.tenant_id, source),
    )
    if not row or not row["secret"]:
        return {}
    return open_secret(
        ctx.config.master_key, row["secret"], ctx.tenant_id, "lookup_sources", source
    )


def _lookups(ctx: Context) -> list[dict[str, Any]]:
    """Every lookup source that needs an account: configured or not, and today's calls."""
    from shoc.db.pool import fetch_all
    from shoc.detect import osint

    rows = {
        r["source"]: r
        for r in fetch_all(
            ctx.db,
            """SELECT s.source, s.enabled, s.settings, u.calls, u.paused_until
               FROM shoc.lookup_sources s
               LEFT JOIN shoc.lookup_usage u
                 ON u.tenant_id = s.tenant_id AND u.source = s.source AND u.day = current_date
               WHERE s.tenant_id = %s""",
            (ctx.tenant_id,),
        )
    }
    out = []
    for name, provider in sorted(osint.KEYED.items()):
        row = rows.get(name) or {}
        out.append(
            {
                "source": name,
                "answers": provider.answers,
                "hosts": list(provider.hosts),
                "configured": bool(row),
                "enabled": bool(row.get("enabled")),
                "per_day": int((row.get("settings") or {}).get("per_day") or provider.per_day),
                "calls_today": int(row.get("calls") or 0),
                "paused_until": to_json(row.get("paused_until")),
                "licence_needed": provider.licence,
                "secret_field": provider.secret_field,
            }
        )
    return out


@dataclass
class IocFilter:
    type: str = f("", doc="ip, domain, url, sha256 or cve")
    contains: str = f("", doc="Substring of the value or the description")
    limit: int = f(50, doc="Maximum rows")


@dataclass
class IocPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    total: int = 0
    # Each source with its queue: read today, waiting, skipped, same story, dropped.
    feeds: list[dict[str, Any]] = field(default_factory=list)
    # Report sources shoc knows by name, and whether each is configured.
    presets: list[dict[str, Any]] = field(default_factory=list)
    # Lookup sources that need an account, and today's calls against the quota.
    lookups: list[dict[str, Any]] = field(default_factory=list)
    # What CTI may read today and what it has read (RFC 0029).
    budget: dict[str, Any] = field(default_factory=dict)


@capability(
    name="intel.list",
    summary="List known indicators and the health of the feeds behind them",
    input=IocFilter,
    output=IocPage,
    scope="intel:read",
    tags=("intel", "read"),
)
def list_iocs(ctx: Context, inp: IocFilter) -> Result:
    from shoc.db.pool import fetch_all, fetch_one

    where = ["tenant_id = %(tenant_id)s", "(expires_at IS NULL OR expires_at > now())"]
    params: dict[str, Any] = {"tenant_id": ctx.tenant_id, "limit": max(1, min(inp.limit, 500))}
    if inp.type:
        where.append("type = %(type)s")
        params["type"] = inp.type
    if inp.contains:
        where.append("(value LIKE %(needle)s OR description ILIKE %(needle)s)")
        params["needle"] = f"%{inp.contains}%"
    rows = fetch_all(
        ctx.db,
        f"SELECT type, value, source, confidence, severity, description, tags, first_seen, last_seen "
        f"FROM shoc.iocs WHERE {' AND '.join(where)} ORDER BY last_seen DESC LIMIT %(limit)s",
        params,
    )
    total = fetch_one(
        ctx.db, "SELECT count(*) AS n FROM shoc.iocs WHERE tenant_id = %s", (ctx.tenant_id,)
    )
    feeds = fetch_all(
        ctx.db,
        """SELECT f.feed, COALESCE(NULLIF(f.parser, ''), f.feed) AS parser, f.enabled,
                  f.settings, f.last_run_at, f.last_ok_at, f.last_error, f.indicators,
                  (SELECT count(*) FROM shoc.intel_reports r
                   WHERE r.tenant_id = f.tenant_id AND r.source = f.feed
                     AND r.digested_at >= current_date) AS read_today,
                  (SELECT coalesce(sum(r.tokens), 0) FROM shoc.intel_reports r
                   WHERE r.tenant_id = f.tenant_id AND r.source = f.feed
                     AND r.digested_at >= current_date) AS tokens_today,
                  (SELECT jsonb_object_agg(state, n) FROM (
                       SELECT q.state, count(*) AS n FROM shoc.intel_queue q
                       WHERE q.tenant_id = f.tenant_id AND q.feed = f.feed
                       GROUP BY q.state) states) AS queue
           FROM shoc.intel_feeds f WHERE f.tenant_id = %s ORDER BY f.feed""",
        (ctx.tenant_id,),
    )
    for feed in feeds:
        feed["queue"] = dict(feed["queue"] or {})
    cap_reports, cap_tokens = _caps(ctx)
    read, spent = _spent_today(ctx)
    configured_urls = {str((r["settings"] or {}).get("url") or "") for r in feeds}
    return Result(
        data=IocPage(
            rows=[to_json(r) for r in rows],
            count=len(rows),
            total=int(total["n"]) if total else 0,
            feeds=[to_json(r) for r in feeds],
            presets=[
                {
                    "name": p.name,
                    "url": p.url,
                    "host": intel.host_of(p.parser, {"url": p.url}),
                    "grade": p.grade,
                    "configured": p.name in {r["feed"] for r in feeds} or p.url in configured_urls,
                }
                for p in intel.PRESETS.values()
            ],
            lookups=_lookups(ctx),
            budget={
                "reports_per_day": cap_reports,
                "tokens_per_day": cap_tokens,
                "reports_today": read,
                "tokens_today": spent,
            },
        ),
        summary=f"{len(rows)} of {int(total['n']) if total else 0} indicator(s) from {len(feeds)} feed(s).",
    )


@dataclass
class HuntInput:
    """Search history for an indicator, an address or a user."""

    value: str = f(doc="What to hunt for: an IP, a domain or a user name")
    days: int = f(90, doc="How far back to look")
    field: str = f("auto", doc="auto, src_ip, domain or actor")


@dataclass
class HuntReport:
    hunt_uid: str = ""
    value: str = ""
    days: int = 0
    matches: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


@capability(
    name="hunt.run",
    summary="Hunt for an indicator across the retention window",
    input=HuntInput,
    output=HuntReport,
    scope="hunts:run",
    principals=("human", "agent", "external_agent", "service"),
    audit=True,
    tags=("intel", "hunt"),
)
def run_hunt(ctx: Context, inp: HuntInput) -> Result:
    from shoc.capabilities.events import EventQuery, build_query
    from shoc.db.pool import execute

    value = inp.value.strip()
    kind = inp.field
    if kind == "auto":
        digits = value.replace(".", "").replace(":", "")
        kind = "src_ip" if digits.isdigit() else ("actor" if "@" in value else "domain")
    query = EventQuery(since=f"-{max(1, inp.days)}d", limit=200)
    if kind == "src_ip":
        query.src_ip = value
    elif kind == "actor":
        query.actor = value
    else:
        query.contains = value
    sql, params, limit = build_query(query, ctx.tenant_id)
    rows = ctx.store.query(sql, params, limit).rows
    hunt_uid = (
        "HUNT-"
        + hashlib.sha256(
            f"{ctx.tenant_id}|{value}|{datetime.now(UTC).isoformat()}".encode()
        ).hexdigest()[:16]
    )

    # A value somebody searched for is not a known-bad one: turning every hit
    # into "traffic involving a known-bad ip" opened a case on an address the
    # operator was only curious about (RFC 0022). The hits are returned; a
    # finding comes from an indicator a feed or a person listed.
    findings: list[str] = []
    execute(
        ctx.db,
        """INSERT INTO shoc.hunts (hunt_uid, tenant_id, kind, query, window_days, matches,
                                   findings, run_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            hunt_uid,
            ctx.tenant_id,
            kind,
            value,
            inp.days,
            len(rows),
            findings,
            f"{ctx.caller.kind}:{ctx.caller.id}",
        ),
    )
    return Result(
        data=HuntReport(
            hunt_uid=hunt_uid,
            value=value,
            days=inp.days,
            matches=len(rows),
            events=[to_json(r) for r in rows[:50]],
            findings=findings,
        ),
        summary=(
            f"{len(rows)} event(s) in the last {inp.days} days involve {value}"
            + (f"; {len(findings)} finding(s) raised." if findings else ".")
        ),
        citations=[str(r["event_uid"]) for r in rows[:50]],
    )


@dataclass
class FeedConfig:
    feed: str = f(
        "",
        doc="The source's name. For a built-in feed, its name is its parser; empty "
        "means the preset's or the lookup's name",
    )
    preset: str = f(
        "",
        doc="A report source shoc knows by name, e.g. microsoft_ti or the_dfir_report "
        "(intel.list names them). It fills in the parser and the URL",
    )
    lookup: str = f(
        "",
        doc="Configure a lookup source that needs an account instead of a feed, e.g. "
        "abuse_ch, ipapi_is or virustotal (intel.list names them). The first save needs its "
        "key in secret under the source's secret_field: api_key, or auth_key for abuse_ch "
        "and key for ipapi_is. settings take per_day, and commercial_licence: true where "
        "intel.list says licence_needed, since that free tier is non-commercial",
    )
    parser: str = f(
        "",
        doc="Indicators: abuse_ch_feodo, abuse_ch_urlhaus, otx, misp or list (any URL naming "
        "indicators). Reports: rss, otx_pulses or misp_events. Empty means the name",
    )
    settings: dict[str, Any] = f(
        doc="Source settings, e.g. {'url': '…'}; report sources take max_items per poll",
        factory=dict,
    )
    secret: dict[str, Any] = f(doc="Source credentials, e.g. {'api_key': '…'}", factory=dict)
    enabled: bool = f(True, doc="Whether the worker polls it")
    remove: bool = f(
        False, doc="Forget the source. Indicators it brought in stay until intel.remove"
    )


@dataclass
class FeedState:
    feed: str = ""
    parser: str = ""
    enabled: bool = True
    removed: bool = False


@capability(
    name="intel.configure",
    summary="Add, change, disable or remove a threat-intel source",
    input=FeedConfig,
    output=FeedState,
    # Its own scope, and a human's: a source holds credentials and decides what
    # shoc fetches every six hours from then on (RFC 0016).
    scope="intel:configure",
    principals=("human",),
    audit=True,
    tags=("intel", "write"),
)
def configure(ctx: Context, inp: FeedConfig) -> Result:
    import json

    from shoc.db.pool import execute
    from shoc.db.secrets import seal
    from shoc.detect import report as reader
    from shoc.errors import NotFound, ValidationError

    if inp.lookup:
        return _configure_lookup(ctx, inp)
    if inp.preset and inp.preset not in intel.PRESETS:
        raise NotFound(f"no preset '{inp.preset}' (have: {', '.join(sorted(intel.PRESETS))})")
    preset = intel.PRESETS.get(inp.preset)
    if preset:
        inp.parser = inp.parser or preset.parser
        inp.settings = {"url": preset.url, "grade": preset.grade, **inp.settings}
    inp.feed = inp.feed or inp.preset
    if not inp.feed:
        raise ValidationError("intel.configure needs a feed, a preset or a lookup")
    if inp.remove:
        gone = execute(
            ctx.db,
            "DELETE FROM shoc.intel_feeds WHERE tenant_id = %s AND feed = %s",
            (ctx.tenant_id, inp.feed),
        )
        execute(
            ctx.db,
            "DELETE FROM shoc.intel_queue WHERE tenant_id = %s AND feed = %s",
            (ctx.tenant_id, inp.feed),
        )
        default = inp.feed in intel.default_feeds(ctx.config.intel_feeds)
        return Result(
            data=FeedState(feed=inp.feed, enabled=default, removed=bool(gone)),
            summary=f"Source {inp.feed} {'removed' if gone else 'was not configured'}."
            + (" It is a default feed and still runs; disable it to stop it." if default else ""),
        )
    parser = inp.parser or inp.feed
    known = {**intel.FEEDS, **intel.REPORT_FEEDS}
    if parser not in known:
        raise ValidationError(f"unknown parser '{parser}' (have: {', '.join(sorted(known))})")
    if parser in ("list", "rss"):
        if not inp.settings.get("url"):
            raise ValidationError(f"a {parser} source needs settings.url")
        reader.guard(str(inp.settings["url"]))
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_feeds (tenant_id, feed, parser, enabled, settings, secret)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, feed) DO UPDATE SET
               parser = EXCLUDED.parser,
               enabled = EXCLUDED.enabled,
               settings = EXCLUDED.settings,
               secret = COALESCE(EXCLUDED.secret, shoc.intel_feeds.secret)""",
        (
            ctx.tenant_id,
            inp.feed,
            parser,
            inp.enabled,
            json.dumps(inp.settings),
            seal(ctx.config.master_key, inp.secret, ctx.tenant_id, "intel_feeds", inp.feed)
            if inp.secret
            else None,
        ),
    )
    kind = "report" if parser in intel.REPORT_FEEDS else "indicator"
    terms = (
        " OTX's terms make it free for non-commercial use only."
        if parser in ("otx", "otx_pulses")
        else ""
    )
    return Result(
        data=FeedState(feed=inp.feed, parser=parser, enabled=inp.enabled),
        summary=f"{kind.capitalize()} source {inp.feed} ({parser}) is "
        f"{'enabled' if inp.enabled else 'disabled'}; it contacts "
        f"{intel.host_of(parser, inp.settings)}.{terms}",
    )


def _configure_lookup(ctx: Context, inp: FeedConfig) -> Result:
    """A lookup source that needs an account: its key, its daily quota (RFC 0030)."""
    import json

    from shoc.db.pool import execute, fetch_one
    from shoc.db.secrets import seal
    from shoc.detect import osint
    from shoc.errors import NotFound, ValidationError

    provider = osint.KEYED.get(inp.lookup)
    if not provider:
        raise NotFound(f"no lookup '{inp.lookup}' (have: {', '.join(sorted(osint.KEYED))})")
    if inp.remove:
        gone = execute(
            ctx.db,
            "DELETE FROM shoc.lookup_sources WHERE tenant_id = %s AND source = %s",
            (ctx.tenant_id, provider.name),
        )
        return Result(
            data=FeedState(feed=provider.name, enabled=False, removed=bool(gone)),
            summary=f"Lookup {provider.name} {'removed' if gone else 'was not configured'}.",
        )
    # A free key from these is for non-commercial use, and the company is a
    # business: the person configuring it says the key is licensed for this.
    if provider.licence and not inp.settings.get("commercial_licence"):
        raise ValidationError(
            f"{provider.name}'s free API is for non-commercial use. Set "
            "settings.commercial_licence to true if this key is under a commercial licence."
        )
    settings = {"per_day": provider.per_day, **inp.settings}
    if not str(settings["per_day"]).isdigit() or int(settings["per_day"]) < 1:
        raise ValidationError("settings.per_day is a whole number, at least 1")
    # A lookup runs only with its key (D123): the first save needs one, as a
    # credential's does, and a later one may leave it out to keep it.
    keyed = fetch_one(
        ctx.db,
        "SELECT 1 FROM shoc.lookup_sources WHERE tenant_id = %s AND source = %s "
        "AND secret IS NOT NULL",
        (ctx.tenant_id, provider.name),
    )
    if not inp.secret.get(provider.secret_field) and (inp.secret or not keyed):
        raise ValidationError(f"{provider.name} needs its key in secret.{provider.secret_field}")
    execute(
        ctx.db,
        """INSERT INTO shoc.lookup_sources (tenant_id, source, enabled, settings, secret)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               enabled = EXCLUDED.enabled, settings = EXCLUDED.settings,
               secret = COALESCE(EXCLUDED.secret, shoc.lookup_sources.secret),
               updated_at = now()""",
        (
            ctx.tenant_id,
            provider.name,
            inp.enabled,
            json.dumps(settings),
            seal(ctx.config.master_key, inp.secret, ctx.tenant_id, "lookup_sources", provider.name)
            if inp.secret
            else None,
        ),
    )
    return Result(
        data=FeedState(feed=provider.name, parser="lookup", enabled=inp.enabled),
        summary=f"Lookup {provider.name} is {'enabled' if inp.enabled else 'disabled'}, "
        f"at most {settings['per_day']} call(s) a day; it contacts "
        f"{', '.join(provider.hosts)}.",
    )


# -- indicators handed in or withdrawn (DET-4) ------------------------------
INDICATOR_TYPES = ("ip", "domain", "url", "sha256", "md5", "cve")


@dataclass
class AddInput:
    """Indicators somebody hands in: typed values, or a page that names them."""

    values: list[str] = f(doc="Indicators, one per entry; each type is worked out", factory=list)
    url: str = f("", doc="Or a page, list or advisory to pull indicators from, once")
    severity: str = f("medium", doc="low, medium, high or critical")
    confidence: float = f(0.8, doc="0 to 1; an agent's indicators are capped at 0.55")
    description: str = f("", doc="Why these are bad")
    days: int = f(90, doc="Days until they expire; 0 means never")
    retro_hunt: bool = f(True, doc="Search the retention window for them now")


@dataclass
class AddReport:
    source: str = ""
    added: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    stored_new: int = 0
    retro_hunt: dict[str, Any] = field(default_factory=dict)


@capability(
    name="intel.add",
    summary="Add indicators by value, or pull them from one URL",
    input=AddInput,
    output=AddReport,
    scope="intel:write",
    principals=("human", "agent", "external_agent"),
    audit=True,
    tags=("intel", "write"),
)
def add(ctx: Context, inp: AddInput) -> Result:
    """Each value keeps the type it has: a URL is stored as a URL, never as its host.

    Only a human's say-so reaches the confidence an automatic action needs. An
    agent may be working from log content an attacker wrote, so what it adds is
    a lead (D33): matched and retro-hunted, but capped below every action floor.
    """
    from urllib.parse import urlparse

    from shoc.detect import osint
    from shoc.detect import report as reader
    from shoc.errors import ValidationError

    if not (inp.values or inp.url):
        raise ValidationError("intel.add needs values or a url")
    confidence = max(0.0, min(inp.confidence, 1.0 if ctx.caller.kind == "human" else 0.55))
    source = (
        f"import:{urlparse(inp.url).hostname}"
        if inp.url
        else f"manual:{ctx.caller.kind}:{ctx.caller.id}"
    )
    expires = datetime.now(UTC) + timedelta(days=inp.days) if inp.days > 0 else None
    indicators: list[intel.Indicator] = []
    rejected: list[str] = []
    ours = intel.ours(ctx.db, ctx.tenant_id)
    human = ctx.caller.kind == "human"

    def excluded(value: str, kind: str) -> bool:
        # A value on a known-benign list is refused from anyone but a person:
        # an agent may be relaying what a log line asked for (RFC 0030).
        return ours(value, kind) or (not human and bool(osint.known_benign(value, kind)))

    for raw in inp.values:
        value = reader.refang(raw.strip())
        kind = osint.classify(value)
        if kind not in INDICATOR_TYPES or excluded(value, kind):
            rejected.append(raw)
            continue
        indicators.append(
            intel.Indicator(
                type=kind,
                value=value.strip("."),
                source=source,
                confidence=confidence,
                severity=inp.severity,
                description=inp.description[:200],
                tags=["manual"],
                expires_at=expires,
            )
        )
    if inp.url:
        for ioc in intel.indicators_in(
            reader.get(inp.url).text[: reader.MAX_BYTES],
            source,
            confidence,
            inp.severity,
            inp.description or inp.url,
            inp.days,
        ):
            if excluded(ioc.value, ioc.type):
                rejected.append(ioc.value)
            else:
                indicators.append(ioc)
    stored = intel.store_indicators(ctx.db, ctx.tenant_id, indicators)
    if human and indicators:
        # A person naming a value held as too common here releases it (DET-4).
        from shoc.db.pool import execute

        execute(
            ctx.db,
            """UPDATE shoc.iocs SET tags = array_remove(tags, 'prevalent')
               WHERE tenant_id = %s AND (type, value) IN (SELECT * FROM unnest(%s::text[], %s::text[]))""",
            (ctx.tenant_id, [i.type for i in indicators], [i.value.lower() for i in indicators]),
        )
    hunted = (
        intel.retro_hunt(ctx.db, ctx.store, ctx.tenant_id)
        if inp.retro_hunt and stored
        else {"indicators": 0, "hits": 0, "findings": []}
    )
    return Result(
        data=AddReport(
            source=source,
            added=[{"type": i.type, "value": i.value} for i in indicators],
            rejected=rejected,
            stored_new=stored,
            retro_hunt=hunted,
        ),
        summary=f"{len(indicators)} indicator(s) under {source}, {stored} new"
        + (f", {len(rejected)} rejected (untyped, internal or known benign)" if rejected else "")
        + f"; retro-hunt found {hunted['hits']} hit(s).",
        citations=hunted["findings"],
    )


@dataclass
class RemoveInput:
    """Withdraw indicators: named ones, or everything one source or report brought in."""

    values: list[str] = f(doc="These values, whatever their type", factory=list)
    source: str = f(
        "", doc="Everything from this source, e.g. manual:human:ana or report:example.com"
    )
    report_uid: str = f("", doc="Everything one digested report brought in")


@dataclass
class RemoveReport:
    removed: int = 0


@capability(
    name="intel.remove",
    summary="Withdraw indicators by value, by source or by report",
    input=RemoveInput,
    output=RemoveReport,
    scope="intel:write",
    principals=("human", "agent", "external_agent"),
    audit=True,
    tags=("intel", "write"),
)
def remove(ctx: Context, inp: RemoveInput) -> Result:
    """Findings already raised stay. A source still polled brings its indicators back."""
    from shoc.db.pool import execute
    from shoc.detect import report as reader
    from shoc.errors import ValidationError

    if not (inp.values or inp.source or inp.report_uid):
        raise ValidationError("intel.remove needs values, a source or a report_uid")
    # Refanged and trimmed the way `intel.add` stored them, so the value pasted
    # from a report withdraws what that report put in.
    removed = execute(
        ctx.db,
        """DELETE FROM shoc.iocs WHERE tenant_id = %s
             AND (value = ANY(%s) OR source = %s OR report_uid = %s)""",
        (
            ctx.tenant_id,
            [reader.refang(v.strip()).strip(".").lower() for v in inp.values],
            inp.source or None,
            inp.report_uid or None,
        ),
    )
    return Result(data=RemoveReport(removed=removed), summary=f"{removed} indicator(s) withdrawn.")


# -- research (DET-6) -------------------------------------------------------
@dataclass
class LookupInput:
    """Research one indicator the way an analyst would."""

    value: str = f(doc="An IP, a domain, a URL, a hash or a CVE")
    type: str = f("", doc="Leave empty to work it out from the value")
    refresh: bool = f(False, doc="Ignore the cached answer and ask every source again")
    sources: list[str] = f(
        doc="Only these sources, e.g. ['rdap', 'tor_exit']. Empty means all that apply",
        factory=list,
    )


@dataclass
class LookupReport:
    value: str = ""
    type: str = ""
    verdict: str = "unknown"
    score: float = 0.0
    confidence: float = 0.0
    owner: str = ""
    shared_infrastructure: bool = False
    internal: bool = False
    seen_in_our_logs: int = 0
    cached: bool = False
    elapsed_ms: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)


@capability(
    name="intel.lookup",
    summary="Research an indicator across OSINT sources and our own history",
    input=LookupInput,
    output=LookupReport,
    scope="intel:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("intel", "read", "research"),
)
def lookup(ctx: Context, inp: LookupInput) -> Result:
    from shoc.detect import osint

    found = osint.research(
        ctx.db,
        ctx.store,
        ctx.tenant_id,
        inp.value,
        inp.type,
        refresh=inp.refresh,
        only=tuple(inp.sources),
        master_key=ctx.config.master_key,
    )
    payload = found.to_json()
    citations = [
        uid
        for obs in found.observations
        if obs.source == "history"
        for uid in obs.data.get("event_uids", [])
    ]
    return Result(
        data=LookupReport(**{k: v for k, v in payload.items() if k != "summary"}),
        summary=found.summary,
        citations=citations,
    )


# -- report digestion (DET-7) ----------------------------------------------
@dataclass
class DigestInput:
    """Hand the CTI role a threat report and get indicators, techniques and hunts."""

    url: str = f("", doc="A link to a report — a blog post, an advisory or a PDF")
    text: str = f("", doc="Or the report pasted in, instead of a URL")
    title: str = f("", doc="A title for pasted text")
    store_indicators: bool = f(
        True, doc="Store what the report publishes as indicators we will match against"
    )
    retro_hunt: bool = f(True, doc="Search the retention window for what the report publishes")


@dataclass
class DigestReport:
    report_uid: str = ""
    url: str = ""
    title: str = ""
    summary: str = ""
    relevance: str = ""
    actors: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    targeted_sectors: list[str] = field(default_factory=list)
    techniques: list[dict[str, Any]] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    suggested_hunts: list[dict[str, Any]] = field(default_factory=list)
    kept: bool = True
    extracted: dict[str, Any] = field(default_factory=dict)
    indicators_stored: int = 0
    unverified: int = 0
    retro_hunt: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    model: str = ""
    tokens: int = 0
    truncated: bool = False
    # An agent's report on a day the budget is spent waits in the queue (RFC 0029).
    queued: bool = False


@capability(
    name="intel.digest",
    summary="Read a threat report and turn it into indicators, techniques and hunts",
    input=DigestInput,
    output=DigestReport,
    scope="intel:write",
    principals=("human", "agent", "external_agent", "service"),
    audit=True,
    tags=("intel", "write", "research"),
)
def digest(ctx: Context, inp: DigestInput) -> Result:
    from shoc.detect import report as reader
    from shoc.errors import ValidationError

    if not (inp.url or inp.text):
        raise ValidationError("intel.digest needs a url or some text")
    # A person is never refused for budget; the read counts toward the day. An
    # agent's or an MCP client's report waits for room, like a polled one.
    if ctx.caller.kind != "human":
        cap_reports, cap_tokens = _caps(ctx)
        read, spent = _spent_today(ctx)
        if read >= cap_reports or spent >= cap_tokens:
            return _queue_handed_in(ctx, inp, read, spent)
    url = intel.canonical(inp.url) if inp.url else ""
    doc = reader.fetch(url) if url else reader.from_text(inp.text, inp.title)
    # An agent reads for what the report says. Storing and retro-hunting its
    # values is for a report a feed or a person brought in (DET-7).
    keep = ctx.caller.kind != "agent"
    return _digest(ctx, doc, inp.store_indicators and keep, inp.retro_hunt and keep)


def _queue_handed_in(ctx: Context, inp: DigestInput, read: int, spent: int) -> Result:
    from shoc.db.pool import execute
    from shoc.detect import report as reader

    url = (
        intel.canonical(inp.url)
        if inp.url
        else "pasted:" + hashlib.sha256(inp.text.encode()).hexdigest()[:16]
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_queue (tenant_id, feed, url, title, text, summary, score,
                                         reason, state)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'waiting')
           ON CONFLICT (tenant_id, url) DO NOTHING""",
        (
            ctx.tenant_id,
            HANDED_IN,
            url,
            (inp.title or inp.url)[:500],
            inp.text[: reader.MAX_TEXT],
            inp.text[: intel.SUMMARY_CHARS],
            10.0,
            f"handed in by {ctx.caller.kind}:{ctx.caller.id}",
        ),
    )
    return Result(
        data=DigestReport(url=inp.url, title=inp.title, queued=True),
        summary=f"Today's intel budget is spent ({read} report(s), {spent} tokens); "
        "the report is queued and read when there is room.",
    )


def _digest(
    ctx: Context,
    doc: Document,
    store: bool,
    retro_hunt: bool,
    source: str = "",
    company: intake.Profile | None = None,
    extra_tokens: int = 0,
) -> Result:
    """The one CTI operation that needs a model (RFC 0004, amending D29).

    The report is a document written by somebody else, which may be quoting an
    attacker and may itself be hostile, so it reaches the model only inside an
    untrusted-data block. What comes back is the model's reading of it: the
    indicators it returns are stored under their own `report:` source with low
    confidence, and any value that does not appear in the report text is flagged
    unverified, so a planted indicator is visible and withdrawable rather than
    indistinguishable from a feed.

    The model reads the report's prose with its indicator tables folded into the
    list of values found, cut at `report.PROSE_LIMIT`, and is told what the
    company runs; it asks no peer (RFC 0029). `extra_tokens` is what a triage
    call already spent on this report.
    """
    from shoc.agents.llm import NoLLM, from_config
    from shoc.db.pool import execute, fetch_one
    from shoc.detect import report as reader
    from shoc.errors import ValidationError

    if not doc.text.strip():
        raise ValidationError(f"nothing readable came back from {doc.url or 'the text'}")
    digest_sha = hashlib.sha256(doc.text.encode()).hexdigest()
    report_uid = (
        "RPT-"
        + hashlib.sha256(f"{ctx.tenant_id}|{doc.url or digest_sha}".encode()).hexdigest()[:16]
    )
    # A report is read once: the same text under any URL (a feed's tracking
    # parameters, a mirror) or the same URL again would only spend the model,
    # and a second read used to queue the first one's hunts twice. A person
    # may ask for a re-read of the same URL.
    again = ctx.caller.kind == "human"
    twin = fetch_one(
        ctx.db,
        "SELECT report_uid, title FROM shoc.intel_reports WHERE tenant_id = %s AND raw_sha256 = %s"
        + (" AND report_uid <> %s" if again else ""),
        (ctx.tenant_id, digest_sha, report_uid) if again else (ctx.tenant_id, digest_sha),
    )
    if twin:
        return Result(
            data=DigestReport(report_uid=twin["report_uid"], url=doc.url, title=twin["title"]),
            summary=f"Already read as {twin['report_uid']} ({twin['title']}).",
        )
    found = reader.extract(doc.text)

    client = from_config(ctx.config, ctx.db, ctx.tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        raise ConfigError(
            "intel.digest reads prose, so it needs a model: set SHOC_LLM_PROVIDER "
            "(anthropic or openai) with SHOC_LLM_API_KEY. Feeds, matching, retro-hunts "
            "and intel.lookup all work without one."
        )
    # Claimed before the model is called, so two workers that picked the same
    # report 12 seconds apart do not both read it. The pool is in autocommit,
    # so the row itself is the lock; a read that fails gives it back.
    claimed = fetch_one(
        ctx.db,
        """INSERT INTO shoc.intel_reports
               (report_uid, tenant_id, url, source_host, title, raw_sha256, digested_by, source)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING report_uid""",
        (
            report_uid,
            ctx.tenant_id,
            doc.url,
            doc.host,
            doc.title,
            digest_sha,
            f"{ctx.caller.kind}:{ctx.caller.id}",
            source,
        ),
    )
    if not claimed and not again:
        return Result(
            data=DigestReport(report_uid=report_uid, url=doc.url, title=doc.title),
            summary=f"Already read, or being read, as {report_uid}.",
        )
    try:
        return _read(
            ctx,
            doc,
            store,
            retro_hunt,
            source,
            company,
            extra_tokens,
            client,
            found,
            report_uid,
            digest_sha,
        )
    except Exception:
        if claimed:
            execute(
                ctx.db,
                "DELETE FROM shoc.intel_reports WHERE report_uid = %s AND tenant_id = %s "
                "AND model = ''",
                (report_uid, ctx.tenant_id),
            )
        raise


def _read(
    ctx: Context,
    doc: Document,
    store: bool,
    retro_hunt: bool,
    source: str,
    company: intake.Profile | None,
    extra_tokens: int,
    client: Any,
    found: Any,
    report_uid: str,
    digest_sha: str,
) -> Result:
    """The model's read of a claimed report, and what code keeps from it."""
    import json

    from shoc.agents import ops, roles, safety
    from shoc.agents.llm import complete_typed
    from shoc.db.pool import execute
    from shoc.detect import osint
    from shoc.detect import report as reader

    prose, cut = reader.for_model(doc.text, found)
    company = company or intake.profile(ctx.db, ctx.tenant_id)
    prompt = "\n".join(
        [
            f"Digest this threat report{f' from {doc.host}' if doc.url else ''}.",
            "",
            company.describe(),
            "",
            safety.quote(f"threat_report:{doc.host}", prose),
            "",
            "For reference, these values appear literally in the text above. Use them to "
            "get the indicators right; do not treat their presence as proof any of them "
            "is malicious.",
            safety.quote("values_found_by_pattern", to_json(found)),
        ]
    )
    # What the company runs is computed and in the prompt, so reading asks no
    # peer: the Surveyor call spent a report's budget before (RFC 0029).
    answer, usage = complete_typed(
        client,
        safety.system_prompt(roles.CTI.prompt),
        prompt,
        roles.CtiDigestOutput,
        ctx.config.llm_max_tokens,
    )
    ops.charge(ctx.db, ctx.tenant_id, usage)
    tokens = int(usage.tokens) + extra_tokens

    excluded = intel.ours(ctx.db, ctx.tenant_id)
    keep = bool(answer.keep)
    indicators: list[dict[str, Any]] = []
    # A discarded report steers nothing, whatever the model listed anyway.
    for item in answer.indicators if keep else []:
        value = reader.refang(str(item.value or "").strip()).strip(".").lower()
        kind = str(item.type or "").strip().lower()
        if not value or kind not in INDICATOR_TYPES:
            continue
        # What CTI curated is kept in the report, and only an observable the
        # report published, that nobody said to leave alone and that is not
        # ours, becomes an indicator (DET-7).
        benign = osint.known_benign(value, kind)
        held_back = (
            "internal, or the company's own"
            if excluded(value, kind)
            else f"on the {benign} warninglist"
            if benign
            else f"do not match: {str(item.do_not_match)[:120]}"
            if str(item.do_not_match).strip()
            else f"derived from {str(item.derived_from)[:120]}"
            if str(item.derived_from).strip()
            else ""
        )
        indicators.append(
            {
                "type": kind,
                "value": value,
                "context": str(item.context or "")[:200],
                "severity": str(item.severity or "medium"),
                # The model was asked for values from the report. One that is not in
                # it was either inferred or planted; either way it is marked.
                "unverified": not found.contains(value),
                # Never longer than the default, so a report cannot make one permanent.
                "ttl_days": max(1, min(int(item.ttl_days or 90), 90)),
                "held_back": held_back,
            }
        )
    unverified = sum(1 for i in indicators if i["unverified"])
    storable = [i for i in indicators if not i["held_back"]] if keep else []

    stored = 0
    source_name = f"report:{doc.host}"
    if store and storable:
        stored = intel.store_indicators(
            ctx.db,
            ctx.tenant_id,
            [
                intel.Indicator(
                    type=i["type"],
                    value=i["value"],
                    source=source_name,
                    # Deliberately below every automatic-action confidence floor:
                    # a report-derived indicator is a lead, not a warrant.
                    confidence=0.35 if i["unverified"] else 0.55,
                    severity=i["severity"],
                    description=i["context"] or (answer.title or doc.title)[:200],
                    tags=["report", doc.host, *[a.lower() for a in answer.actors[:3]]],
                    expires_at=datetime.now(UTC) + timedelta(days=i["ttl_days"]),
                )
                for i in storable
            ],
        )
        # Only rows the report itself brought in: a feed's row for the same
        # value stays the feed's, so withdrawing the report leaves it alone.
        for i in storable:
            execute(
                ctx.db,
                """UPDATE shoc.iocs SET report_uid = %s, unverified = %s
                   WHERE tenant_id = %s AND type = %s AND value = %s AND source = %s""",
                (report_uid, i["unverified"], ctx.tenant_id, i["type"], i["value"], source_name),
            )

    hunted = (
        intel.retro_hunt(ctx.db, ctx.store, ctx.tenant_id)
        if retro_hunt and stored
        else {"indicators": 0, "hits": 0, "findings": []}
    )

    from shoc.detect.context import LOG_KINDS, kinds

    techniques = [
        {
            "id": str(t.id).upper(),
            "name": str(t.name)[:200],
            "evidence": str(t.evidence)[:500],
            "seen_in": kinds(t.seen_in),
        }
        for t in answer.techniques
        if str(t.id).strip()
    ]
    # A discarded report is remembered as read, and steers nothing: no
    # technique reaches the Hunter's agenda or the Detection Engineer's coverage.
    kept_techniques = [t["id"] for t in techniques] if keep else []
    # Three hunts at most: a read queued a dozen, most for telemetry nobody here
    # sends. A hunt for a value this read stored is the retro-hunt's job.
    values = [i["value"] for i in storable] if store else []
    hunts = [
        h
        for h in answer.suggested_hunts
        if keep
        and (h.title or h.hypothesis).strip()
        and not any(v in str(h).lower() for v in values)
    ][:3]
    # Suggested hunts go to the Hunter's backlog when the report came from a
    # configured source or a person handed it in (D79). Each carries the
    # behaviour and only the techniques it tests (D132).
    if source or ctx.caller.kind == "human":
        from shoc.agents import hunter

        filed = [
            hunter.add_to_backlog(
                ctx.db,
                ctx.tenant_id,
                trigger="cti",
                title=(hunt.title or hunt.hypothesis).strip()[:200],
                hypothesis=hunt.hypothesis[:1000],
                would_confirm=hunt.would_confirm[:1000],
                data_needed=", ".join(LOG_KINDS[k][0] for k in kinds(hunt.seen_in)),
                why_now=answer.relevance[:500],
                attack=[
                    a for t in hunt.attack if hunter.TECHNIQUE.match(a := str(t).strip().upper())
                ],
                priority=3,
                evidence={
                    "report_uid": report_uid,
                    "source": source or doc.host,
                    "procedure": hunt.procedure[:1000],
                    "logic": hunt.logic[:1000],
                    "false_positives": hunt.false_positives[:500],
                    "seen_in": kinds(hunt.seen_in),
                },
            )
            for hunt in hunts
        ]
        # Read again, the report's hunts are the ones just filed, or none when
        # it no longer applies: what it suggested before and nothing answered
        # yet gives way.
        execute(
            ctx.db,
            """UPDATE shoc.hunt_backlog
                  SET state = 'rejected', decided_at = now(), decided_by = %s,
                      evidence = evidence || %s
                WHERE tenant_id = %s AND trigger = 'cti' AND state = 'open' AND pack_id = ''
                  AND evidence->>'report_uid' = %s AND NOT item_uid = ANY(%s)""",
            (
                f"{ctx.caller.kind}:{ctx.caller.id}",
                json.dumps(
                    {
                        "decision": "superseded",
                        "because": "the report was read again"
                        + ("" if keep else " and does not apply here"),
                    }
                ),
                ctx.tenant_id,
                report_uid,
                filed,
            ),
        )
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_reports
               (report_uid, tenant_id, url, source_host, title, summary, relevance,
                actors, malware, campaigns, techniques, indicators, extracted, hunts,
                findings, stored_count, confidence, raw_sha256, model, tokens, digested_by,
                source, procedures)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (report_uid) DO UPDATE SET
               title = EXCLUDED.title, summary = EXCLUDED.summary, relevance = EXCLUDED.relevance,
               actors = EXCLUDED.actors, malware = EXCLUDED.malware,
               campaigns = EXCLUDED.campaigns, techniques = EXCLUDED.techniques,
               procedures = EXCLUDED.procedures,
               indicators = EXCLUDED.indicators, extracted = EXCLUDED.extracted,
               hunts = EXCLUDED.hunts, findings = EXCLUDED.findings,
               stored_count = EXCLUDED.stored_count, confidence = EXCLUDED.confidence,
               model = EXCLUDED.model, tokens = EXCLUDED.tokens,
               digested_at = now()""",
        (
            report_uid,
            ctx.tenant_id,
            doc.url,
            doc.host,
            answer.title or doc.title,
            answer.summary,
            answer.relevance,
            list(answer.actors),
            list(answer.malware),
            list(answer.campaigns),
            kept_techniques,
            json.dumps(indicators),
            json.dumps(to_json(found)),
            [(h.title or h.hypothesis).strip()[:200] for h in hunts],
            hunted["findings"],
            stored,
            float(answer.confidence),
            digest_sha,
            usage.model,
            tokens,
            f"{ctx.caller.kind}:{ctx.caller.id}",
            source,
            json.dumps(techniques if keep else []),
        ),
    )

    caveat = (
        f" {unverified} of them are not in the report text and are marked unverified."
        if unverified
        else ""
    )
    held = sum(1 for i in indicators if i["held_back"])
    caveat += f" {held} held back from matching." if held else ""
    caveat += " CTI discarded it as not applying here." if not keep else ""
    return Result(
        data=DigestReport(
            report_uid=report_uid,
            url=doc.url,
            title=answer.title or doc.title,
            summary=answer.summary,
            relevance=answer.relevance,
            actors=list(answer.actors),
            malware=list(answer.malware),
            campaigns=list(answer.campaigns),
            targeted_sectors=list(answer.targeted_sectors),
            techniques=techniques,
            indicators=indicators,
            suggested_hunts=[to_json(h) for h in answer.suggested_hunts],
            kept=keep,
            extracted=to_json(found),
            indicators_stored=stored,
            unverified=unverified,
            retro_hunt=hunted,
            confidence=float(answer.confidence),
            model=usage.model,
            tokens=tokens,
            truncated=doc.truncated or cut,
        ),
        summary=(
            f"{answer.title or doc.title or 'The report'}: {len(indicators)} indicator(s), "
            f"{len(techniques)} technique(s)"
            + (f", actors {', '.join(answer.actors[:3])}" if answer.actors else "")
            + f". {stored} stored, {hunted['hits']} historical hit(s)."
            + caveat
        ),
        citations=hunted["findings"],
    )


@dataclass
class ReportFilter:
    contains: str = f("", doc="Substring of the title, summary, an actor or a malware name")
    limit: int = f(20, doc="Maximum rows")
    state: str = f(
        "read",
        doc="read (the default); or waiting, skipped, same_story or dropped for items not "
        "read, with the reason; or queue for all of those",
    )


@dataclass
class ReportPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="intel.reports",
    summary="List the threat reports we have read, and what came out of them",
    input=ReportFilter,
    output=ReportPage,
    scope="intel:read",
    tags=("intel", "read", "research"),
)
def list_reports(ctx: Context, inp: ReportFilter) -> Result:
    from shoc.db.pool import fetch_all
    from shoc.errors import ValidationError

    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": ctx.tenant_id, "limit": max(1, min(inp.limit, 200))}
    if inp.state != "read":
        if inp.state not in ("queue", *QUEUE_STATES):
            raise ValidationError(f"state must be read, queue or one of {', '.join(QUEUE_STATES)}")
        if inp.state != "queue":
            where.append("state = %(state)s")
            params["state"] = inp.state
        if inp.contains:
            where.append("(title ILIKE %(needle)s OR reason ILIKE %(needle)s)")
            params["needle"] = f"%{inp.contains}%"
        queued = fetch_all(
            ctx.db,
            f"""SELECT url, feed AS source, title, state, score, reason, same_as, published_at,
                       queued_at, changed_at, tokens
                FROM shoc.intel_queue WHERE {" AND ".join(where)}
                ORDER BY changed_at DESC, url LIMIT %(limit)s""",
            params,
        )
        return Result(
            data=ReportPage(rows=[to_json(r) for r in queued], count=len(queued)),
            summary=f"{len(queued)} report(s) not read ({inp.state}).",
        )
    if inp.contains:
        where.append(
            "(title ILIKE %(needle)s OR summary ILIKE %(needle)s "
            "OR array_to_string(actors, ' ') ILIKE %(needle)s "
            "OR array_to_string(malware, ' ') ILIKE %(needle)s)"
        )
        params["needle"] = f"%{inp.contains}%"
    rows = fetch_all(
        ctx.db,
        f"""SELECT report_uid, url, source, source_host, title, summary, relevance, actors, malware,
                   campaigns, techniques, hunts, stored_count, confidence, tokens, digested_at
            FROM shoc.intel_reports WHERE {" AND ".join(where)}
            ORDER BY digested_at DESC LIMIT %(limit)s""",
        params,
    )
    return Result(
        data=ReportPage(rows=[to_json(r) for r in rows], count=len(rows)),
        summary=f"{len(rows)} report(s) read.",
    )
