"""Which threat reports CTI reads, decided before a model is called (DET-7, RFC 0029).

A report source publishes far more than a company of 20-500 people needs, and
reading one costs the strong model 10,000 to 40,000 tokens. A CTI analyst skims
headlines against what the company runs and reads a few reports properly; this
module is the skimming. Each queued item is scored on its title, the summary and
categories its feed gave, and its age, against the products the company has
connected. Nothing here reads the report or calls a model.

The score is a sum the reason spells out:

- +3 for each connected product the item names, up to +9;
- +2 for each threat class that hits companies of this size, up to +4;
- -4 for each term that marks reporting about other targets;
- the source's grade, 0 to 2;
- -1 for every two days since publication.

At `READ` or more an item is read; between `TRIAGE` and `READ` the cheap model
is asked first; below `TRIAGE` it is skipped. The thresholds are starting
values, tuned from the scores logged on a real deployment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from shoc.db.pool import Conn, fetch_all, fetch_one

READ = 3.0
TRIAGE = 1.0

# The words a report uses for each product, and the connectors that mean the
# company runs it. A connector without an entry scores like a product the
# company does not run, so a new connector adds a line here.
PRODUCTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Microsoft 365": (
        ("m365", "entra", "defender", "defender_hunting"),
        (
            r"microsoft 365",
            r"office 365",
            r"\bm365\b",
            r"\bo365\b",
            r"exchange online",
            r"outlook",
            r"sharepoint",
            r"onedrive",
            r"microsoft teams",
        ),
    ),
    "Entra ID": (
        ("entra", "m365"),
        (r"\bentra\b", r"azure ad\b", r"azure active directory", r"\baad\b"),
    ),
    "Azure": (("azure_activity",), (r"\bazure\b",)),
    "Google Workspace": (
        ("google_workspace",),
        (r"google workspace", r"\bgmail\b", r"google drive", r"g suite"),
    ),
    "Google Cloud": (("gcp_audit",), (r"\bgcp\b", r"google cloud")),
    "Okta": (("okta",), (r"\bokta\b",)),
    "AWS": (
        ("aws_cloudtrail", "aws_guardduty", "cloudtrail_s3"),
        (r"\baws\b", r"amazon web services", r"cloudtrail", r"guardduty", r"\bs3 bucket"),
    ),
    "GitHub": (("github",), (r"\bgithub\b",)),
    "GitLab": (("gitlab",), (r"\bgitlab\b",)),
    "Cloudflare": (("cloudflare", "cloudflare_logs"), (r"\bcloudflare\b",)),
    "CrowdStrike": (("crowdstrike", "crowdstrike_fdr"), (r"crowdstrike", r"\bfalcon\b")),
    "Defender": (("defender", "defender_hunting"), (r"microsoft defender", r"\bdefender for\b")),
    "SentinelOne": (("sentinelone", "sentinelone_cloudfunnel"), (r"sentinelone",)),
    "Tailscale": (("tailscale",), (r"tailscale",)),
    "Stripe": (("stripe",), (r"\bstripe\b",)),
    "OpenAI": (("openai",), (r"\bopenai\b", r"chatgpt")),
    "Anthropic": (("anthropic",), (r"\banthropic\b",)),
    "Wazuh": (("wazuh",), (r"\bwazuh\b",)),
}

# What attacks companies of this size (connector-priority guidance): identity
# and mail first, ransomware through an endpoint second, cloud and CI third.
THREATS: dict[str, tuple[str, ...]] = {
    "infostealer": (r"(?:info)?stealer",),
    "business email compromise": (
        r"business email compromise",
        r"\bbec\b",
        r"invoice fraud",
        r"payment diversion",
    ),
    "adversary-in-the-middle": (
        r"adversary.in.the.middle",
        r"\baitm\b",
        r"phishing kit",
        r"phishing.as.a.service",
        r"\bphaas\b",
    ),
    "OAuth consent": (r"\boauth\b", r"consent phishing", r"illicit consent", r"device code"),
    "MFA fatigue": (r"mfa fatigue", r"mfa bombing", r"push (?:fatigue|bombing)"),
    "token theft": (r"session hijack", r"session token", r"token theft", r"cookie theft"),
    "password attacks": (r"password spray", r"credential stuffing", r"account takeover"),
    "ransomware": (r"ransomware", r"data extortion", r"\braas\b"),
    "initial access broker": (r"initial access broker",),
    "package supply chain": (r"supply.chain", r"\bnpm\b", r"\bpypi\b"),
}

# Reporting about targets a company of this size is not.
OFF_TARGET: dict[str, str] = {
    "ICS": r"\bics\b",
    "SCADA": r"\bscada\b",
    "PLC": r"\bplcs?\b",
    "satellite": r"\bsatellite",
    "telecom core": r"telecom",
    "mobile spyware": r"(?:android|ios|mobile) spyware",
    "embassy": r"\bembass(?:y|ies)\b",
    "ministry": r"\bministr(?:y|ies)\b",
    "election": r"\belections?\b",
}

# Words that say nothing about which story a title tells.
_STOP_WORDS = """the and for with from into over under after before about this that these
those how why what who new our your their its are was were has have been using used use via
amid threat threats attack attacks attacker attackers campaign campaigns malware analysis
report reports security research update updates part targets targeting targeted actor actors
group groups week weekly"""
_STOP = frozenset(_STOP_WORDS.split())
_WORD = re.compile(r"[a-z0-9][a-z0-9.\-]+")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SAME_STORY_DAYS = 14


@dataclass
class Profile:
    """What the company runs, as its connected sources say (RFC 0029)."""

    connectors: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    identities: int = 0
    clouds: list[str] = field(default_factory=list)

    def describe(self) -> str:
        """The company in two lines, for a prompt."""
        return (
            f"This company has {self.identities or 'an unknown number of'} identities in its "
            "logs and connects: "
            + (", ".join(self.products) or "no product shoc can name yet")
            + "."
            + (f" Cloud: {', '.join(self.clouds)}." if self.clouds else "")
        )


def profile(conn: Conn, tenant_id: str) -> Profile:
    """Read the company's profile from its sources and its last posture snapshot."""
    from shoc.ingest.connectors.base import connector_of

    connectors = sorted(
        {
            connector_of(str(r["source"]))
            for r in fetch_all(
                conn,
                """SELECT source FROM shoc.connector_config
                   WHERE tenant_id = %s AND enabled AND source NOT IN ('slack', 'llm')""",
                (tenant_id,),
            )
        }
    )
    products = [name for name, (sources, _) in PRODUCTS.items() if set(sources) & set(connectors)]
    snapshot = fetch_one(
        conn,
        """SELECT counts FROM shoc.posture_snapshots WHERE tenant_id = %s
           ORDER BY taken_at DESC LIMIT 1""",
        (tenant_id,),
    )
    counts = dict((snapshot or {}).get("counts") or {})
    clouds = [p for p in ("AWS", "Azure", "Google Cloud") if p in products]
    return Profile(
        connectors=connectors,
        products=products,
        identities=int(counts.get("user") or 0),
        clouds=clouds,
    )


def _hits(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(p, text) for p in patterns)


def score(
    title: str,
    summary: str,
    categories: list[str],
    published: datetime | None,
    grade: int,
    company: Profile,
    now: datetime | None = None,
) -> tuple[float, str]:
    """An item's score and the reason, from what its feed said about it."""
    text = " ".join([title, summary, *categories]).lower()
    named = [p for p in company.products if _hits(text, PRODUCTS[p][1])]
    threats = [t for t, patterns in THREATS.items() if _hits(text, patterns)]
    off = [label for label, pattern in OFF_TARGET.items() if re.search(pattern, text)]
    total = min(9, 3 * len(named)) + min(4, 2 * len(threats)) - 4 * len(off)
    total += max(0, min(2, grade))
    days = (
        max(0.0, ((now or datetime.now(UTC)) - published).total_seconds() / 86400)
        if published
        else 0.0
    )
    total -= int(days // 2)
    parts = []
    if named:
        parts.append("names " + ", ".join(named))
    if threats:
        parts.append(", ".join(threats))
    if off:
        parts.append("about " + ", ".join(off))
    if not (named or threats or off):
        parts.append("no product we run and no threat class we watch")
    if grade:
        parts.append(f"source grade {grade}")
    if days >= 2:
        parts.append(f"{int(days)} days old")
    return float(total), "; ".join(parts)


def words(title: str) -> set[str]:
    """A title's words, without the ones every title has."""
    return {w.strip(".-") for w in _WORD.findall(title.lower()) if w not in _STOP and len(w) > 2}


def cves(text: str) -> set[str]:
    return {c.upper() for c in _CVE.findall(text)}


def same_as(title: str, text: str, earlier: list[tuple[str, str, str]]) -> str:
    """The id of an earlier item telling the same story, or "".

    `earlier` is (id, title, text) for each report read or item queued in the
    last two weeks. The same story is three or more title words in common that
    are at least half of the shorter title, or two CVEs in common.
    """
    mine, my_cves = words(title), cves(f"{title} {text}")
    for uid, other_title, other_text in earlier:
        theirs = words(other_title)
        common = mine & theirs
        if len(common) >= 3 and len(common) * 2 >= min(len(mine), len(theirs)):
            return uid
        if len(my_cves & cves(f"{other_title} {other_text}")) >= 2:
            return uid
    return ""


def recent_reports(conn: Conn, tenant_id: str) -> list[tuple[str, str, str]]:
    """(report_uid, title, summary) for every report read in the last two weeks."""
    return [
        (str(r["report_uid"]), str(r["title"] or ""), str(r["summary"] or ""))
        for r in fetch_all(
            conn,
            """SELECT report_uid, title, summary FROM shoc.intel_reports
               WHERE tenant_id = %s AND digested_at > now() - %s * interval '1 day'""",
            (tenant_id, SAME_STORY_DAYS),
        )
    ]
