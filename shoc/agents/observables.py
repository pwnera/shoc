"""What a case actually contains, so a specialist is called by the evidence.

CTI used to be reachable only through a keyword. An agent had to write the word
"actor", "ransomware" or "indicator" in a sentence before CTI was invited, the
single interruption a round allowed went to whichever role came first in a
dictionary, and Challenger's terms — "benign", "expected", "normal for" — are in
almost every message anybody writes. A case about a file hash, a command line or
a technique mentions none of CTI's words, so the specialist with the most to say
never spoke at all.

The trigger therefore moves from what was said to what is in front of everybody.
This module reads the case's own events and findings and says what they contain:
hashes, external addresses, domains and URLs, CVEs, ATT&CK techniques, and the
command-line shapes that mean something to somebody who reads threat reports for
a living. An indicator is typed precisely — a URL is not a domain and a domain
is not an address — because everything downstream, from `intel.lookup` to a
blocklist, acts on the type.

Nothing here reaches the network. It reads the evidence, the indicators we have
already stored and the reports we have already digested; a fresh lookup is a
tool call CTI makes for itself.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from shoc.db.pool import Conn, fetch_all
from shoc.detect import osint, report

# Per kind, so one noisy event cannot fill a prompt with the same shape.
MAX_PER_KIND = 12

_HASHES = (
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
)
_URL = re.compile(r"\bhttps?://[^\s\"'<>|\\]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Command-line shapes that a threat report would name. This is not detection —
# the rules do that — it is "somebody who reads reports would recognise this",
# which is the question CTI is being asked.
_COMMANDS = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-noprofile",
    "-windowstyle hidden",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "iex(",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "schtasks",
    "vssadmin",
    "bcdedit",
    "wbadmin",
    "nltest",
    "dsquery",
    "net group",
    "net localgroup",
    "whoami /all",
    "reg add",
    "reg save",
    "sc create",
    "psexec",
    "/dev/tcp",
    "nohup",
    "base64 -d",
    "chmod +x",
    "curl -s",
    "wget -q",
    "msiexec /i http",
    "add-mppreference",
    "set-mppreference",
    "vaultcmd",
    "lsass",
)

# Field names whose value is a command line whatever the product calls it.
_COMMAND_FIELDS = ("cmd", "command", "process", "arg", "script", "query")


@dataclass(frozen=True)
class Observable:
    """One thing in the evidence somebody could research."""

    kind: str  # sha256, sha1, md5, ip, domain, url, cve, technique, command
    value: str
    where: str = ""  # the field it came out of, for a human reading the case

    def to_json(self) -> dict[str, str]:
        return asdict(self)


def _walk(value: Any, field: str = "") -> list[tuple[str, str]]:
    """Every string in a record, with the field name it sat under."""
    if isinstance(value, dict):
        return [
            pair
            for key, inner in value.items()
            for pair in _walk(inner, f"{field}.{key}" if field else str(key))
        ]
    if isinstance(value, (list, tuple)):
        return [pair for inner in value for pair in _walk(inner, field)]
    if value is None or isinstance(value, bool):
        return []
    return [(field, str(value))]


def _from_text(field: str, text: str) -> list[Observable]:
    out: list[Observable] = []
    lowered = text.lower()
    for url in _URL.findall(text):
        out.append(Observable("url", url.rstrip(".,);\"'"), field))
    for kind, pattern in _HASHES:
        out += [Observable(kind, h.lower(), field) for h in pattern.findall(text)]
    out += [
        Observable("ip", ip, field) for ip in _IPV4.findall(text) if osint.is_public_address(ip)
    ]
    # The rule report extraction keeps a name by, so a newer gTLD counts here too.
    out += [
        Observable("domain", d.lower(), field)
        for d in report._DOMAIN.findall(text)
        if report.is_domain(d, alone=d == text.strip())
    ]
    out += [Observable("cve", c.upper(), field) for c in _CVE.findall(text)]
    if any(hint in field.lower() for hint in _COMMAND_FIELDS) or len(text) > 60:
        out += [Observable("command", token, field) for token in _COMMANDS if token in lowered]
    return out


def of_case(
    findings: list[dict[str, Any]], events: list[dict[str, Any]], attack: list[str] | None = None
) -> list[Observable]:
    """Everything in this case somebody could look up, deduplicated and capped."""
    found: list[Observable] = [
        Observable("technique", t.upper(), "case.attack")
        for t in (attack or [])
        if _TECHNIQUE.fullmatch(str(t).strip())
    ]
    for finding in findings:
        found += [
            Observable("technique", str(t).upper(), "finding.attack")
            for t in (finding.get("attack") or [])
            if _TECHNIQUE.fullmatch(str(t).strip())
        ]
    for row in events:
        for field, text in _walk(row):
            if field.endswith("event_uid") or field == "uid":
                continue  # an event's own identifier is not an indicator
            found += _from_text(field, text)

    seen: set[tuple[str, str]] = set()
    counts: dict[str, int] = {}
    out: list[Observable] = []
    for item in found:
        key = (item.kind, item.value)
        if key in seen or counts.get(item.kind, 0) >= MAX_PER_KIND:
            continue
        seen.add(key)
        counts[item.kind] = counts.get(item.kind, 0) + 1
        out.append(item)
    return out


# Kinds that can be researched on their own merits. A bare technique cannot:
# almost every finding carries one, and "T1078 exists" is not intelligence.
RESEARCHABLE = ("sha256", "sha1", "md5", "ip", "domain", "url", "cve", "command")


def known(conn: Conn, tenant_id: str, items: list[Observable]) -> list[dict[str, Any]]:
    """What we have already stored about these — feeds first, then our own lookups."""
    values = [o.value for o in items if o.kind in RESEARCHABLE]
    if not values:
        return []
    rows = fetch_all(
        conn,
        """SELECT type, value, source, confidence, severity, description, tags,
                  first_seen, last_seen
           FROM shoc.iocs WHERE tenant_id = %s AND value = ANY(%s)
           ORDER BY last_seen DESC LIMIT 50""",
        (tenant_id, values),
    )
    # A URL's lookup is cached under what a third party was told: scheme, host
    # and path (DET-6). Its answer is reported under the URL in the case.
    told = {osint._shareable(o.value, "url").lower(): o.value for o in items if o.kind == "url"}
    cached = fetch_all(
        conn,
        """SELECT type, value, verdict, score, confidence, looked_up_at
           FROM shoc.intel_lookups WHERE tenant_id = %s AND value = ANY(%s)
           ORDER BY looked_up_at DESC LIMIT 50""",
        (tenant_id, sorted({*values, *told})),
    )
    return [{"from": "feed", **dict(r)} for r in rows] + [
        {"from": "lookup", **dict(r), "value": told.get(r["value"], r["value"])} for r in cached
    ]


def reports(
    conn: Conn, tenant_id: str, items: list[Observable], limit: int = 5
) -> list[dict[str, Any]]:
    """Reports we have read that describe what this case contains.

    A technique, a malware name or a command-line shape is how a case connects
    to something already published. Matching the technique array is exact;
    matching a command shape is a text search of the digest, which is how you
    would find it yourself.
    """
    techniques = sorted({o.value for o in items if o.kind == "technique"})
    terms = sorted({o.value for o in items if o.kind == "command"})
    if not techniques and not terms:
        return []
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    clauses = []
    if techniques:
        clauses.append("techniques && %(techniques)s")
        params["techniques"] = techniques
    for index, term in enumerate(terms[:6]):
        clauses.append(f"(summary ILIKE %(t{index})s OR title ILIKE %(t{index})s)")
        params[f"t{index}"] = f"%{term}%"
    where.append("(" + " OR ".join(clauses) + ")")
    return fetch_all(
        conn,
        f"""SELECT report_uid, title, url, actors, malware, campaigns, techniques,
                   relevance, digested_at
            FROM shoc.intel_reports WHERE {" AND ".join(where)}
            ORDER BY digested_at DESC LIMIT %(limit)s""",
        params,
    )


def worth_asking(items: list[Observable], matched: list[dict[str, Any]]) -> bool:
    """Whether CTI has anything to work with on this case.

    Something researchable in the evidence, or a report that already describes
    what the case looks like. Neither, and CTI is not asked: a turn that can only
    answer "nothing is known" is a turn nobody needed.
    """
    return bool(matched) or any(o.kind in RESEARCHABLE for o in items)
