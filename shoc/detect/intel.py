"""Threat intelligence: sources, indicators and retro-hunts (DET-4, DET-7).

A source is polled on the intel schedule and brings in one of two things:

- **indicators** — abuse.ch Feodo Tracker and URLhaus, OTX, MISP, or `list`: any
  URL whose page names indicators, one per line or in prose.
- **reports** — `rss` (an RSS or Atom feed), `otx_pulses` or `misp_events`. Each
  new item is read by `intel.digest`, the same as a report somebody pasted.

Each one is a single HTTP call and a parser; no feed framework, and no source
is required. RFC 0016.

Two things happen with an indicator:

- **forward matching** — every detection cycle checks recent events against the
  indicator table, so a known-bad address in today's logs becomes a finding.
- **retro-hunt** — a *new* indicator is searched backwards over the retention
  window, because the interesting case is the one where it was in your logs
  three weeks before anyone published it.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx

from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.errors import ConfigError
from shoc.store import ocsf as layout
from shoc.store.base import EventStore

TIMEOUT = httpx.Timeout(60.0, connect=15.0)

# The OCSF columns each indicator type is matched against (D75). The event
# table has no MD5 or CVE column, so `md5` and `cve` indicators are stored for
# research and never matched.
MATCH_COLUMNS = {
    "ip": ("src_endpoint_ip", "dst_endpoint_ip"),
    "domain": ("src_endpoint_domain", "dst_endpoint_domain", "dns_query_hostname"),
    "url": ("http_request_url",),
    "sha256": ("process_hash_sha256", "file_hash_sha256"),
}
MATCHED = tuple(MATCH_COLUMNS)
# The entity a hit names, by indicator type.
ENTITY_KIND = {"ip": "ip", "domain": "domain", "url": "url", "sha256": "hash"}


@dataclass
class Indicator:
    type: str
    value: str
    source: str
    confidence: float = 0.6
    severity: str = "medium"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    expires_at: datetime | None = None


@dataclass
class FeedResult:
    feed: str
    fetched: int = 0
    stored: int = 0
    error: str | None = None


# -- feeds ------------------------------------------------------------------
def _client(headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, headers=headers or {}, follow_redirects=True)


def feodo(settings: dict[str, Any], secret: dict[str, Any]) -> list[Indicator]:
    """abuse.ch Feodo Tracker: botnet command-and-control addresses."""
    url = settings.get("url", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
    with _client(_abuse_ch(secret)) as http:
        resp = http.get(url)
        resp.raise_for_status()
        text = resp.text
    out: list[Indicator] = []
    rows = csv.reader(
        io.StringIO(
            "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
        )
    )
    for row in rows:
        if len(row) < 5:
            continue
        out.append(
            Indicator(
                type="ip",
                value=row[1].strip(),
                source="abuse.ch/feodo",
                confidence=0.9,
                severity="high",
                description=f"{row[4].strip()} command-and-control",
                tags=["c2", "botnet", row[4].strip().lower()],
                expires_at=datetime.now(UTC) + timedelta(days=30),
            )
        )
    return out


def _abuse_ch(secret: dict[str, Any]) -> dict[str, str]:
    """abuse.ch asks every caller for an Auth-Key (RFC 0030); a download still works without one."""
    key = str(secret.get("auth_key") or "")
    return {"Auth-Key": key} if key else {}


# Malware families and CPU architectures that only infect routers, cameras and
# other embedded devices. Most of URLhaus is these, and a company of 20-500
# people never fetches them (RFC 0029).
IOT_TAGS = frozenset(
    {"mirai", "mozi", "gafgyt", "bashlite", "hajime", "tsunami", "mips", "mipsel", "arm", "arm7"}
    | {"sh4", "m68k", "sparc", "powerpc", "ppc"}
)


def urlhaus(settings: dict[str, Any], secret: dict[str, Any]) -> list[Indicator]:
    """abuse.ch URLhaus: URLs distributing malware.

    Each one is a `url` indicator. Its host is not: a payload on a shared host
    or a compromised site does not make every page there bad (DET-4). The CSV
    dump carries tags, and payloads for embedded devices are left out.
    """
    url = settings.get("url", "https://urlhaus.abuse.ch/downloads/csv_recent/")
    with _client(_abuse_ch(secret)) as http:
        resp = http.get(url)
        resp.raise_for_status()
        lines = [x.strip() for x in resp.text.splitlines() if x.strip() and not x.startswith("#")]
    out: list[Indicator] = []
    for row in csv.reader(lines):
        # A CSV row is id, dateadded, url, status, last_online, threat, tags, …;
        # a plain-text dump (`text_recent`) is one URL a line.
        link = (row[2] if len(row) > 6 else row[0] if row else "").strip()
        tags = (
            {t.strip().lower() for t in row[6].split(",") if t.strip()} if len(row) > 6 else set()
        )
        if "://" not in link or tags & IOT_TAGS:
            continue
        out.append(
            Indicator(
                type="url",
                value=link,
                source="abuse.ch/urlhaus",
                confidence=0.75,
                severity="high",
                description="hosting malware payloads",
                tags=["malware", "payload", *sorted(tags)[:5]],
                expires_at=datetime.now(UTC) + timedelta(days=14),
            )
        )
        if len(out) >= int(settings.get("limit", 2000)):
            break
    return out


def _otx_pulses(settings: dict[str, Any], secret: dict[str, Any]) -> list[dict[str, Any]]:
    api_key = secret.get("api_key")
    if not api_key:
        raise ConfigError("otx: the secret needs api_key")
    base = settings.get("url", "https://otx.alienvault.com/api/v1")
    since = (datetime.now(UTC) - timedelta(days=int(settings.get("days", 7)))).isoformat()
    with _client({"X-OTX-API-KEY": api_key}) as http:
        resp = http.get(f"{base}/pulses/subscribed", params={"modified_since": since, "limit": 50})
        resp.raise_for_status()
        return resp.json().get("results", [])


def otx(settings: dict[str, Any], secret: dict[str, Any]) -> list[Indicator]:
    """AlienVault OTX subscribed pulses."""
    kinds = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-SHA256": "sha256",
        "CVE": "cve",
    }
    out = []
    for pulse in _otx_pulses(settings, secret):
        for item in pulse.get("indicators", []):
            kind = kinds.get(item.get("type", ""))
            if not kind:
                continue
            out.append(
                Indicator(
                    type=kind,
                    value=str(item.get("indicator", "")),
                    source="otx",
                    confidence=0.6,
                    severity="medium",
                    description=pulse.get("name", "")[:200],
                    tags=["otx", *pulse.get("tags", [])[:5]],
                    expires_at=datetime.now(UTC) + timedelta(days=60),
                )
            )
    return [i for i in out if i.value]


def _misp(settings: dict[str, Any], secret: dict[str, Any], path: str, body: dict[str, Any]) -> Any:
    url = settings.get("url")
    api_key = secret.get("api_key")
    if not (url and api_key):
        raise ConfigError("misp: settings need url and the secret needs api_key")
    with _client({"Authorization": api_key, "Accept": "application/json"}) as http:
        resp = http.post(f"{str(url).rstrip('/')}/{path}", json=body)
        resp.raise_for_status()
        return resp.json()


def misp(settings: dict[str, Any], secret: dict[str, Any]) -> list[Indicator]:
    """A MISP instance the team already runs."""
    kinds = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "sha256": "sha256",
    }
    payload = _misp(
        settings,
        secret,
        "attributes/restSearch",
        {
            "returnFormat": "json",
            "type": list(kinds),
            "last": settings.get("last", "7d"),
            "limit": int(settings.get("limit", 1000)),
        },
    )
    out = []
    for attribute in (payload.get("response", {}) or {}).get("Attribute", []):
        kind = kinds.get(attribute.get("type", ""))
        if not kind:
            continue
        out.append(
            Indicator(
                type=kind,
                value=str(attribute.get("value", "")),
                source="misp",
                confidence=0.8,
                severity="high",
                description=str(attribute.get("comment", ""))[:200],
                tags=["misp"],
            )
        )
    return [i for i in out if i.value]


def indicators_in(
    text: str,
    source: str,
    confidence: float,
    severity: str = "medium",
    description: str = "",
    days: int = 90,
) -> list[Indicator]:
    """Every indicator a page names, each under its own type (DET-4).

    A URL stays a URL: its host is not stored as a domain or an address unless
    the page names that host on its own.
    """
    from shoc.detect import report

    found = report.extract(text, limit=5000, standalone=True)
    expires = datetime.now(UTC) + timedelta(days=days) if days > 0 else None
    columns = {
        "ip": found.ips,
        "domain": found.domains,
        "url": found.urls,
        "sha256": found.sha256,
        "md5": found.md5,
        "cve": found.cves,
    }
    return [
        Indicator(
            type=kind,
            value=value,
            source=source,
            confidence=confidence,
            severity=severity,
            description=description[:200],
            expires_at=expires,
        )
        for kind, values in columns.items()
        for value in values
    ]


def listing(settings: dict[str, Any], secret: dict[str, Any]) -> list[Indicator]:
    """Any URL that publishes indicators: a blocklist, a CSV, a page of IOCs."""
    from shoc.detect import report

    url = settings.get("url")
    if not url:
        raise ConfigError("list: settings need url")
    return indicators_in(
        report.get(url).text[: report.MAX_BYTES],
        source=f"list:{urlparse(url).hostname}",
        confidence=float(settings.get("confidence", 0.6)),
        severity=str(settings.get("severity", "medium")),
        description=str(settings.get("description", "")),
        days=int(settings.get("days", 30)),
    )


FEEDS = {
    "abuse_ch_feodo": feodo,
    "abuse_ch_urlhaus": urlhaus,
    "otx": otx,
    "misp": misp,
    "list": listing,
}


# -- report sources (DET-7) -------------------------------------------------
@dataclass
class ReportItem:
    """One report a source published. Empty `text` means: fetch `url` and read it.

    `summary`, `published` and `categories` are what the feed says about the
    item, which is what it is scored on before anybody reads it (RFC 0029).
    """

    url: str
    title: str = ""
    text: str = ""
    summary: str = ""
    published: datetime | None = None
    categories: list[str] = field(default_factory=list)


# A feed entry whose content runs past this is the report itself, so the page
# is not fetched a second time.
FULL_TEXT = 6_000
SUMMARY_CHARS = 1_500

# Query parameters that only say where a click came from.
_TRACKING = ("utm_", "fbclid", "gclid", "mc_cid", "mc_eid")


def canonical(url: str) -> str:
    """The URL a report is known by: lower-case host, no fragment, no tracking parameters."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url.strip())
    query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING)
    ]
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, urlencode(query), "")
    )


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _when(text: str) -> datetime | None:
    """An RSS (RFC 822) or Atom (ISO 8601) date, or None."""
    from email.utils import parsedate_to_datetime

    text = (text or "").strip()
    if not text:
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _text_of(children: dict[str, Any], *names: str) -> str:
    """The first of these child elements that has text, flattened from HTML."""
    from shoc.detect import report

    for name in names:
        child = children.get(name)
        if child is not None and (child.text or "").strip():
            return report.html_to_text(child.text or "")
    return ""


def rss(settings: dict[str, Any], secret: dict[str, Any]) -> list[ReportItem]:
    """An RSS 2.0 or Atom feed. Each entry's link is read as a report.

    The entry's summary, date and categories are kept for scoring, and an entry
    that carries the whole post is read from the feed rather than fetched.
    """
    from shoc.detect import report

    url = settings.get("url")
    if not url:
        raise ConfigError("rss: settings need url")
    # ElementTree resolves no external entity, and the expat bundled with
    # Python 3.12 refuses entity-expansion bombs.
    root = ElementTree.fromstring(report.get(url).content[: report.MAX_BYTES])
    items = []
    for node in root.iter():
        if _local(node.tag) not in ("item", "entry"):
            continue
        children: dict[str, Any] = {}
        for child in node:
            children.setdefault(_local(child.tag), child)
        links = [c for c in node if _local(c.tag) == "link"]
        link = next((c for c in links if c.get("rel") in (None, "alternate")), None)
        href = ((link.get("href") or link.text or "") if link is not None else "").strip()
        if not href:
            continue
        # RSS `content:encoded` is "encoded" once the namespace is dropped, Atom's
        # is "content"; RSS `description`, Atom `summary`.
        content = _text_of(children, "encoded", "content")
        summary = _text_of(children, "description", "summary") or content
        title = children.get("title")
        items.append(
            ReportItem(
                url=href,
                title=(title.text or "").strip() if title is not None else "",
                text=content if len(content) > FULL_TEXT else "",
                summary=summary[:SUMMARY_CHARS],
                published=_when(_text_of(children, "pubDate", "published", "updated", "date")),
                categories=[
                    (c.get("term") or c.text or "").strip()
                    for c in node
                    if _local(c.tag) == "category" and (c.get("term") or c.text or "").strip()
                ][:20],
            )
        )
    return items


def otx_pulses(settings: dict[str, Any], secret: dict[str, Any]) -> list[ReportItem]:
    """OTX pulses as reports: their description, references and indicators.

    A pulse names its tags, industries, countries, adversary, malware families
    and ATT&CK ids; those are its categories.
    """
    items = []
    for pulse in _otx_pulses(settings, secret):
        lines = [
            pulse.get("description", ""),
            "",
            "References:",
            *pulse.get("references", []),
            "",
            "Indicators:",
        ]
        lines += [f"{i.get('type')} {i.get('indicator')}" for i in pulse.get("indicators", [])]
        families = [
            str(m.get("display_name") or m) if isinstance(m, dict) else str(m)
            for m in pulse.get("malware_families", []) or []
        ]
        attack = [
            str(a.get("id") or a) if isinstance(a, dict) else str(a)
            for a in pulse.get("attack_ids", []) or []
        ]
        items.append(
            ReportItem(
                url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                title=str(pulse.get("name", ""))[:200],
                text="\n".join(str(x) for x in lines),
                summary=str(pulse.get("description", ""))[:SUMMARY_CHARS],
                published=_when(str(pulse.get("modified") or pulse.get("created") or "")),
                categories=[
                    str(c)
                    for c in (
                        *(pulse.get("tags") or []),
                        *(pulse.get("industries") or []),
                        *(pulse.get("targeted_countries") or []),
                        *([pulse["adversary"]] if pulse.get("adversary") else []),
                        *families,
                        *attack,
                    )
                ][:40],
            )
        )
    return items


def misp_events(settings: dict[str, Any], secret: dict[str, Any]) -> list[ReportItem]:
    """MISP events as reports: their info line and attributes; tags and galaxies as categories."""
    payload = _misp(
        settings,
        secret,
        "events/restSearch",
        {
            "returnFormat": "json",
            "last": settings.get("last", "7d"),
            "limit": int(settings.get("limit", 20)),
        },
    )
    items = []
    for wrapper in payload.get("response", []) if isinstance(payload, dict) else payload:
        event = wrapper.get("Event", wrapper)
        lines = [event.get("info", ""), "", "Attributes:"]
        lines += [
            f"{a.get('type')} {a.get('value')} {a.get('comment', '')}".strip()
            for a in event.get("Attribute", [])
        ]
        clusters = [
            str(c.get("value", ""))
            for g in event.get("Galaxy", []) or []
            for c in g.get("GalaxyCluster", []) or []
        ]
        items.append(
            ReportItem(
                url=f"{str(settings['url']).rstrip('/')}/events/view/{event.get('id')}",
                title=str(event.get("info", ""))[:200],
                text="\n".join(str(x) for x in lines),
                summary=str(event.get("info", ""))[:SUMMARY_CHARS],
                published=_when(str(event.get("date") or "")),
                categories=[
                    *[str(t.get("name", "")) for t in event.get("Tag", []) or []],
                    *clusters,
                ][:40],
            )
        )
    return items


REPORT_FEEDS = {
    "rss": rss,
    "otx_pulses": otx_pulses,
    "misp_events": misp_events,
}

# Feeds a new install gets for free: public, no key, no account. A default
# feed is an outbound connection nobody asked for, so the hosts these reach
# are named in the quick start and logged on the first refresh, and
# SHOC_INTEL_FEEDS=off turns them off.
DEFAULT_FEEDS = ("abuse_ch_feodo", "abuse_ch_urlhaus")

# The host each built-in feed contacts, so a deployment can be told what it
# will reach before it reaches it.
FEED_HOSTS = {
    "abuse_ch_feodo": "feodotracker.abuse.ch",
    "abuse_ch_urlhaus": "urlhaus.abuse.ch",
    "otx": "otx.alienvault.com",
    "misp": "the MISP instance you configure",
}


@dataclass(frozen=True)
class Preset:
    """A free report source shoc knows by name (RFC 0029). None is on by default."""

    name: str
    url: str
    # 2 is primary research, 1 a CERT; a source configured by URL is 0.
    grade: int = 2
    parser: str = "rss"


PRESETS = {
    p.name: p
    for p in (
        Preset(
            "microsoft_ti",
            "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        ),
        Preset("the_dfir_report", "https://thedfirreport.com/feed/"),
        Preset("huntress", "https://www.huntress.com/blog/rss.xml"),
        Preset("proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml"),
        Preset("push_security", "https://pushsecurity.com/rss.xml"),
        Preset("datadog_security_labs", "https://securitylabs.datadoghq.com/rss/feed.xml"),
        Preset("google_gtig", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
        Preset("wiz_research", "https://www.wiz.io/feed/tag/research/rss.xml"),
        Preset("stepsecurity", "https://www.stepsecurity.io/blog/rss.xml"),
        Preset("talos", "https://blog.talosintelligence.com/rss/"),
        Preset("cert_fr_alerts", "https://www.cert.ssi.gouv.fr/alerte/feed/", grade=1),
        Preset("cert_fr_cti", "https://www.cert.ssi.gouv.fr/cti/feed/", grade=1),
    )
}


def host_of(parser: str, settings: dict[str, Any]) -> str:
    """The host a source reaches: its configured URL, or the built-in one."""
    return urlparse(str(settings.get("url", ""))).hostname or FEED_HOSTS.get(parser, parser)


def default_feeds(setting: str = "default") -> tuple[str, ...]:
    """Which feeds run when nobody named one. `off` means shoc calls nobody."""
    value = (setting or "default").strip().lower()
    if value in ("off", "none", "0", "false"):
        return ()
    if value in ("", "default", "defaults"):
        return DEFAULT_FEEDS
    named = tuple(n.strip() for n in value.split(",") if n.strip())
    return tuple(n for n in named if n in FEEDS and n != "list")


# -- storage ----------------------------------------------------------------
def ours(conn: Conn, tenant_id: str) -> Callable[[str, str], bool]:
    """A test for values nobody may hand in as an indicator (DET-4, DET-7).

    Internal values, the addresses shoc calls out from, and the domains of the
    company's own operator and automation accounts (D78). A report or a person
    planting one of these would make shoc raise findings on itself.
    """
    from shoc.cases import own
    from shoc.detect import osint

    mine = {own.bare(v) for v in own.values(conn, tenant_id, "address", "operator", "automation")}
    domains = {v.rsplit("@", 1)[1] for v in mine if "@" in v}

    def test(value: str, kind: str) -> bool:
        if osint.is_internal(value, kind):
            return True
        if kind not in ("ip", "domain", "url", "email"):
            return False
        host = osint.host_of(value, kind)
        return host in mine or any(host == d or host.endswith("." + d) for d in domains)

    return test


def store_indicators(conn: Conn, tenant_id: str, indicators: list[Indicator]) -> int:
    """Insert or refresh indicators. A new one is left un-hunted for the retro-hunt."""
    stored = 0
    for ioc in indicators:
        row = fetch_one(
            conn,
            """INSERT INTO shoc.iocs
                   (tenant_id, type, value, source, confidence, severity, description, tags, expires_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, type, value) DO UPDATE SET
                   last_seen = now(),
                   confidence = GREATEST(shoc.iocs.confidence, EXCLUDED.confidence),
                   -- A second source can lengthen an indicator's life, never
                   -- shorten it: a report must not expire a feed's C2 address.
                   expires_at = CASE
                       WHEN shoc.iocs.expires_at IS NULL OR EXCLUDED.expires_at IS NULL THEN NULL
                       ELSE GREATEST(shoc.iocs.expires_at, EXCLUDED.expires_at) END
               RETURNING (xmax = 0) AS inserted""",
            (
                tenant_id,
                ioc.type,
                ioc.value.lower(),
                ioc.source,
                ioc.confidence,
                ioc.severity,
                ioc.description,
                ioc.tags,
                ioc.expires_at,
            ),
        )
        stored += 1 if row and row["inserted"] else 0
    return stored


def refresh(
    conn: Conn,
    tenant_id: str,
    feed: str,
    settings: dict[str, Any],
    secret: dict[str, Any],
    parser: str = "",
) -> FeedResult:
    """Pull one indicator source and store what it returns. A broken one is health, not an outage."""
    parser = parser or feed
    if parser not in FEEDS:
        raise ConfigError(f"unknown intel feed '{parser}' (have: {', '.join(sorted(FEEDS))})")
    result = FeedResult(feed=feed)
    try:
        indicators = FEEDS[parser](settings, secret)
        result.fetched = len(indicators)
        result.stored = store_indicators(conn, tenant_id, indicators)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    record_run(conn, tenant_id, feed, settings, result)
    return result


def record_run(
    conn: Conn, tenant_id: str, feed: str, settings: dict[str, Any], result: FeedResult
) -> None:
    execute(
        conn,
        """INSERT INTO shoc.intel_feeds (tenant_id, feed, settings, last_run_at, last_ok_at,
                                         last_error, indicators)
           VALUES (%s,%s,%s, now(), CASE WHEN %s::text IS NULL THEN now() END, %s, %s)
           ON CONFLICT (tenant_id, feed) DO UPDATE SET
               last_run_at = now(),
               last_ok_at = COALESCE(EXCLUDED.last_ok_at, shoc.intel_feeds.last_ok_at),
               last_error = EXCLUDED.last_error,
               indicators = shoc.intel_feeds.indicators + EXCLUDED.indicators""",
        (tenant_id, feed, json.dumps(settings), result.error, result.error, result.stored),
    )


def prune(conn: Conn, tenant_id: str) -> int:
    return execute(
        conn,
        "DELETE FROM shoc.iocs WHERE tenant_id = %s AND expires_at IS NOT NULL AND expires_at < now()",
        (tenant_id,),
    )


def indicators_for(
    conn: Conn, tenant_id: str, types: tuple[str, ...] = MATCHED, limit: int = 5000
) -> list[dict[str, Any]]:
    return fetch_all(
        conn,
        """SELECT type, value, source, confidence, severity, description, tags
           FROM shoc.iocs
           WHERE tenant_id = %s AND type = ANY(%s)
             AND (expires_at IS NULL OR expires_at > now())
           ORDER BY confidence DESC LIMIT %s""",
        (tenant_id, list(types), limit),
    )


# -- matching ---------------------------------------------------------------
def _finding_uid(tenant_id: str, rule_id: str, value: str, window_start: datetime) -> str:
    blob = f"{tenant_id}|{rule_id}|{value}|{window_start.isoformat()}"
    return "F-" + hashlib.sha256(blob.encode()).hexdigest()[:24]


def _open_finding(conn: Conn, tenant_id: str, kind: str, value: str) -> dict[str, Any] | None:
    """The finding this indicator already has open, forward or retro-hunted."""
    return fetch_one(
        conn,
        """SELECT finding_uid, rule_id, window_start FROM shoc.findings
           WHERE tenant_id = %s AND entity_key = %s AND status IN ('new', 'triage')
             AND (rule_id = %s OR rule_id = %s)
           ORDER BY last_seen DESC LIMIT 1""",
        (tenant_id, value, f"ioc_match:{kind}", f"ioc_retrohunt:{kind}"),
    )


def match_window(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    since: datetime,
    until: datetime | None = None,
    indicators: list[dict[str, Any]] | None = None,
    batch: int = 500,
    column: str = "time",
) -> list[dict[str, Any]]:
    """Find events in a window that touch a known indicator.

    The window is on event time, or on `ingested_at` for a detection cycle.

    The match is one SQL statement per batch of indicators rather than one per
    indicator, so a 5,000-entry feed costs ten queries, not five thousand.
    """
    until = until or datetime.now(UTC)
    pool = indicators if indicators is not None else indicators_for(conn, tenant_id)
    hits: list[dict[str, Any]] = []
    by_value = {i["value"].lower(): i for i in pool}
    values = list(by_value)
    for start in range(0, len(values), batch):
        chunk = values[start : start + batch]
        params: dict[str, Any] = {
            "tenant_id": tenant_id,
            "window_start": since,
            "window_end": until,
        }
        placeholders = []
        for index, value in enumerate(chunk):
            params[f"v{index}"] = value
            placeholders.append(f":v{index}")
        joined = ", ".join(placeholders)
        cols = sorted({c for type_cols in MATCH_COLUMNS.values() for c in type_cols})
        sql = (
            f"SELECT event_uid, time, {', '.join(cols)}, actor_user_name, "
            f"api_operation, metadata_product FROM {layout.EVENTS_TABLE} "
            f"WHERE tenant_id = :tenant_id AND {column} >= :window_start AND {column} < :window_end "
            f"AND ({' OR '.join(f'LOWER({c}) IN ({joined})' for c in cols)})"
            " ORDER BY time DESC LIMIT 500"
        )
        for row in store.query(sql, params, 500).rows:
            # A value counts only in a column its type belongs in: a domain
            # indicator never matches a URL that happens to equal it.
            indicator = next(
                (
                    by_value[v]
                    for c in cols
                    if (v := str(row.get(c) or "").lower()) in by_value
                    and c in MATCH_COLUMNS.get(by_value[v]["type"], ())
                ),
                None,
            )
            if indicator:
                hits.append({**row, "indicator": indicator})
    return hits


def findings_from_hits(
    conn: Conn, tenant_id: str, hits: list[dict[str, Any]], kind: str = "ioc_match"
) -> list[str]:
    """Turn indicator hits into findings, one per indicator value."""
    from shoc.cases import engine as case_engine
    from shoc.detect.engine import Finding, upsert

    grouped: dict[str, list[dict[str, Any]]] = {}
    for hit in hits:
        grouped.setdefault(hit["indicator"]["value"], []).append(hit)

    created: list[str] = []
    for value, rows in grouped.items():
        indicator = rows[0]["indicator"]
        times = [r["time"] for r in rows]
        entity = f"{ENTITY_KIND.get(indicator['type'], 'domain')}:{value}"
        rule_id, window_start = f"{kind}:{indicator['type']}", min(times)
        # Steady contact with a known-bad value grows the finding it already
        # has open; a new one opens only after that one is closed (DET-4).
        held = _open_finding(conn, tenant_id, indicator["type"], value)
        if held:
            rule_id, window_start = held["rule_id"], held["window_start"]
        finding = Finding(
            finding_uid=held["finding_uid"]
            if held
            else _finding_uid(tenant_id, rule_id, value, window_start),
            tenant_id=tenant_id,
            rule_id=rule_id,
            title=f"Traffic involving a known-bad {indicator['type']}: {value}",
            severity=indicator["severity"],
            confidence=float(indicator["confidence"]),
            entity_key=value,
            window_start=window_start,
            window_end=max(times),
            first_seen=min(times),
            last_seen=max(times),
            event_count=len(rows),
            event_uids=[str(r["event_uid"]) for r in rows[:20]],
            attack=["T1071"],
            evidence={
                "kind": kind,
                "indicator": {k: indicator[k] for k in ("type", "value", "source", "description")},
                "users": sorted(
                    {str(r.get("actor_user_name")) for r in rows if r.get("actor_user_name")}
                )[:10],
            },
            entities=sorted(
                {entity}
                | {f"user:{r['actor_user_name']}" for r in rows if r.get("actor_user_name")}
            ),
        )
        if upsert(conn, finding):
            case_engine.publish(
                conn,
                tenant_id,
                "finding.new",
                finding.finding_uid,
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "entity": value,
                    "source": indicator["source"],
                },
            )
        created.append(finding.finding_uid)
    return created


def retro_hunt(
    conn: Conn, store: EventStore, tenant_id: str, days: int = 90, limit: int = 500
) -> dict[str, Any]:
    """Search the retention window for indicators that arrived after the events did."""
    pending = fetch_all(
        conn,
        """SELECT type, value, source, confidence, severity, description, tags
           FROM shoc.iocs
           WHERE tenant_id = %s AND retro_hunted_at IS NULL AND type = ANY(%s)
           ORDER BY confidence DESC LIMIT %s""",
        (tenant_id, list(MATCHED), limit),
    )
    if not pending:
        return {"indicators": 0, "hits": 0, "findings": []}
    since = datetime.now(UTC) - timedelta(days=days)
    hits = match_window(conn, store, tenant_id, since, indicators=pending)
    findings = findings_from_hits(conn, tenant_id, hits, kind="ioc_retrohunt")
    execute(
        conn,
        """UPDATE shoc.iocs SET retro_hunted_at = now()
           WHERE tenant_id = %s AND type = ANY(%s) AND value = ANY(%s)""",
        (tenant_id, list(MATCHED), [i["value"] for i in pending]),
    )
    return {"indicators": len(pending), "hits": len(hits), "findings": findings}
