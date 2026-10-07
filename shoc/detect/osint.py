"""On-demand indicator research (DET-6).

A feed answers *is this value on a list someone published?*, in advance and in
bulk. This module answers the question an analyst actually asks when an address
turns up in a case: **what is it?** Who owns it, what autonomous system it sits
in, whether it is a Tor exit or a cloud NAT gateway shared by half the internet,
what it resolves to, what abuse.ch has seen it doing, and whether it has ever
been in our own logs before.

Every source is one HTTP call and a parser, declared in `SOURCES` with the hosts
it is allowed to talk to and the indicator types it understands. They run in
parallel under a wall-clock budget, each returns a typed `Observation`, and the
observations are scored into one verdict that cites the sources behind it. A
source that fails is recorded as failed and the rest of the answer stands: a
broken upstream is health, not an outage.

Two guards are not configurable:

- a private, loopback, link-local or otherwise internal value is never sent to a
  third party — only the local sources run for it;
- a source only ever calls the hosts in its own declaration, so a value taken
  from a log or a report can never steer a lookup at an attacker-chosen URL.

v1 ships only sources that need no account, so research works on a fresh install
with no configuration. Keyed platforms (VirusTotal, AbuseIPDB, GreyNoise,
Shodan, urlscan, passive DNS) are additive: another entry in `SOURCES` behind a
credential, disabled until configured.
"""

from __future__ import annotations

import base64
import contextlib
import csv
import gzip
import io
import ipaddress
import json
import re
import socket
import time
from array import array
from bisect import bisect_right
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from shoc.db.pool import Conn, execute, fetch_all, fetch_one

TIMEOUT = httpx.Timeout(12.0, connect=5.0)
BUDGET_SECONDS = 25.0
CACHE_TTL = timedelta(hours=12)

KINDS = ("ip", "domain", "url", "sha256", "md5", "cve", "email")

VERDICTS = ("malicious", "suspicious", "unknown", "benign")

_HEX = re.compile(r"^[a-f0-9]+$", re.I)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.I)


# -- what is this thing -----------------------------------------------------
def classify(value: str) -> str:
    """Work out what kind of indicator a bare string is."""
    v = value.strip().strip(".").lower()
    if not v:
        return ""
    if _CVE.match(v):
        return "cve"
    if "://" in v:
        return "url"
    if "@" in v and _DOMAIN.match(v.split("@", 1)[-1]):
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HEX.match(v):
        return {64: "sha256", 32: "md5"}.get(len(v), "")
    if _DOMAIN.match(v):
        return "domain"
    return ""


def host_of(value: str, kind: str) -> str:
    """The host a URL or email hangs off, so host-based sources can be asked."""
    if kind == "url":
        return value.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    if kind == "email":
        return value.rsplit("@", 1)[-1].lower()
    return value.strip().lower()


# The ranges RFC 5737 and RFC 3849 reserve for documentation. Python calls them
# private, because nothing routes them — but they are not *ours*, they carry no
# information about a customer's network, and every fixture, eval and test in
# this repo is written with them (see CLAUDE.md). Treating them as internal
# would make research silently do nothing on all of our own test data.
DOCUMENTATION = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home.arpa", ".intranet")


def is_documentation(addr: Any) -> bool:
    return any(addr.version == net.version and addr in net for net in DOCUMENTATION)


def is_public_address(value: str) -> bool:
    """Is this an address it is safe — and useful — to research?"""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global or is_documentation(addr)


def is_internal(value: str, kind: str) -> bool:
    """Values we refuse to hand to a third party."""
    if kind in ("ip", "url", "domain", "email"):
        host = host_of(value, kind)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host.endswith(INTERNAL_SUFFIXES) or "." not in host
        return not is_public_address(host)
    return False


# -- the shape of an answer -------------------------------------------------
@dataclass
class Observation:
    """One source's answer about one value."""

    source: str
    ok: bool = True
    verdict: str = "unknown"
    weight: float = 0.0
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    # Answered from a downloaded list: the value was sent nowhere (RFC 0030).
    listed: bool = False


@dataclass
class Research:
    """Everything every source had to say, scored into one answer."""

    value: str = ""
    type: str = ""
    verdict: str = "unknown"
    score: float = 0.0
    confidence: float = 0.0
    owner: str = ""
    shared_infrastructure: bool = False
    internal: bool = False
    seen_in_our_logs: int = 0
    observations: list[Observation] = field(default_factory=list)
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)
    cached: bool = False
    elapsed_ms: int = 0
    summary: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "owner": self.owner,
            "shared_infrastructure": self.shared_infrastructure,
            "internal": self.internal,
            "seen_in_our_logs": self.seen_in_our_logs,
            "observations": [
                {
                    "source": o.source,
                    "ok": o.ok,
                    "verdict": o.verdict,
                    "summary": o.summary,
                    "data": o.data,
                    "error": o.error,
                    "listed": o.listed,
                }
                for o in self.observations
            ],
            "sources_ok": self.sources_ok,
            "sources_failed": self.sources_failed,
            "cached": self.cached,
            "elapsed_ms": self.elapsed_ms,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class Source:
    """A place to ask, and the only hosts it is allowed to ask.

    `key` names the lookup source whose account it needs (RFC 0030): it runs
    only when a person configured that key, is handed the secret as a third
    argument, and counts against that source's daily quota. `listed` marks a
    source that answers from a downloaded list and sends the value nowhere.
    """

    name: str
    kinds: tuple[str, ...]
    hosts: tuple[str, ...]
    fn: Callable[..., Observation]
    local: bool = False  # runs against our own data, safe for internal values
    key: str = ""
    listed: bool = False


@dataclass(frozen=True)
class Provider:
    """A lookup service that needs an account, and its default daily quota (RFC 0030)."""

    name: str
    hosts: tuple[str, ...]
    per_day: int
    answers: str
    # Its free tier is for non-commercial use, so configuring it takes the
    # person's word that the key is licensed for a business.
    licence: bool = False
    # The name the key goes under in the secret.
    secret_field: str = "api_key"


KEYED: dict[str, Provider] = {
    p.name: p
    for p in (
        Provider(
            "abuse_ch",
            ("threatfox-api.abuse.ch", "urlhaus-api.abuse.ch", "mb-api.abuse.ch"),
            2000,
            "IOCs reported to ThreatFox, URLhaus and MalwareBazaar",
            secret_field="auth_key",
        ),
        Provider(
            "ipapi_is",
            ("api.ipapi.is",),
            800,
            "VPN, proxy, Tor, datacenter and abuser flags for an address",
            secret_field="key",
        ),
        Provider(
            "abuseipdb",
            ("api.abuseipdb.com",),
            1000,
            "abuse reports and a confidence score for an address",
            licence=True,
        ),
        Provider(
            "greynoise",
            ("api.greynoise.io",),
            1000,
            "whether an address is an internet scanner or a common business service",
            licence=True,
        ),
        Provider(
            "shodan", ("api.shodan.io",), 100, "open ports and services on an address", licence=True
        ),
        Provider(
            "netlas", ("app.netlas.io",), 50, "open ports and services on an address", licence=True
        ),
        Provider(
            "virustotal",
            ("www.virustotal.com",),
            500,
            "antivirus engine verdicts for an address, domain, URL or file",
            licence=True,
        ),
        Provider(
            "urlscan", ("urlscan.io",), 500, "earlier scans of a URL or a domain", licence=True
        ),
    )
}


def _client(timeout: httpx.Timeout = TIMEOUT) -> httpx.Client:
    return httpx.Client(
        timeout=timeout, follow_redirects=True, headers={"User-Agent": "shoc/intel-research"}
    )


# -- downloaded lists (RFC 0030) ---------------------------------------------
# Answers that need no call per lookup. Each list is one download, kept per
# process until its TTL runs out. A new copy that is under half or over one
# and a half times the size of the last one is not trusted: the last one
# stays, and `LIST_WARNINGS` says why. A failed download keeps the last copy
# too. `warm()` loads them all, from the worker's intel job.
_LISTS: dict[str, tuple[datetime, Any]] = {}
_LIST_TTL = timedelta(hours=6)
_DAY = timedelta(days=1)
_WEEK = timedelta(days=7)
LIST_TIMEOUT = httpx.Timeout(120.0, connect=10.0)
LIST_WARNINGS: dict[str, str] = {}


def _size(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return 0


def _cached_list(key: str, build: Callable[[], Any], ttl: timedelta = _LIST_TTL) -> Any:
    hit = _LISTS.get(key)
    now = datetime.now(UTC)
    if hit and now - hit[0] < ttl:
        return hit[1]
    try:
        value = build()
    except Exception:
        if hit is None:
            raise
        LIST_WARNINGS[key] = "the download failed; kept the previous copy"
        _LISTS[key] = (now, hit[1])
        return hit[1]
    old, new = (_size(hit[1]) if hit else 0), _size(value)
    if hit and old >= 10 and not old / 2 <= new <= old * 1.5:
        LIST_WARNINGS[key] = f"kept the previous copy: it went from {old} to {new} entries"
        _LISTS[key] = (now, hit[1])
        return hit[1]
    LIST_WARNINGS.pop(key, None)
    _LISTS[key] = (now, value)
    return value


class Ranges:
    """Networks, each with a label. An address finds the most specific one holding it."""

    def __init__(self) -> None:
        self._nets: dict[int, dict[int, dict[int, str]]] = {4: {}, 6: {}}
        self._count = 0

    def add(self, cidr: str, label: str) -> None:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return
        table = self._nets[net.version].setdefault(net.prefixlen, {})
        if int(net.network_address) not in table:
            table[int(net.network_address)] = label
            self._count += 1

    def get(self, value: str) -> tuple[str, str] | None:
        """(network, label), or None."""
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        bits, n = addr.max_prefixlen, int(addr)
        nets = self._nets[addr.version]
        for length in sorted(nets, reverse=True):
            key = (n >> (bits - length)) << (bits - length)
            label = nets[length].get(key)
            if label is not None:
                return f"{ipaddress.ip_address(key)}/{length}", label
        return None

    def __len__(self) -> int:
        return self._count


class Spans:
    """Address ranges that are not networks (DB-IP's rows), found by bisection.

    The rows arrive sorted. IPv4 bounds are kept whole; IPv6 bounds keep their
    top 64 bits, which is as fine as any allocation DB-IP lists. The ASN and
    country tables together take about 10 MB.
    """

    def __init__(self) -> None:
        self._starts = {4: array("I"), 6: array("Q")}
        self._ends = {4: array("I"), 6: array("Q")}
        self._labels = {4: array("I"), 6: array("I")}
        self._names: list[str] = []
        self._index: dict[str, int] = {}

    @staticmethod
    def _key(value: str) -> tuple[int, int]:
        if ":" in value:
            return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, value)[:8], "big")
        return 4, int.from_bytes(socket.inet_pton(socket.AF_INET, value), "big")

    def add(self, start: str, end: str, label: str) -> None:
        try:
            version, low = self._key(start)
            _, high = self._key(end)
        except OSError:
            return
        if label not in self._index:
            self._index[label] = len(self._names)
            self._names.append(label)
        self._starts[version].append(low)
        self._ends[version].append(high)
        self._labels[version].append(self._index[label])

    def get(self, value: str) -> str | None:
        try:
            version, key = self._key(value)
        except OSError:
            return None
        at = bisect_right(self._starts[version], key) - 1
        if at >= 0 and key <= self._ends[version][at]:
            return self._names[self._labels[version][at]]
        return None

    def __len__(self) -> int:
        return len(self._starts[4]) + len(self._starts[6])


def _get(http: httpx.Client, url: str) -> httpx.Response:
    resp = http.get(url)
    resp.raise_for_status()
    return resp


def _tor_exits() -> set[str]:
    with _client() as http:
        resp = _get(http, "https://check.torproject.org/torbulkexitlist")
    return {line.strip() for line in resp.text.splitlines() if line.strip()}


def _cloud_networks() -> Ranges:
    """Published ranges of the clouds and CDNs: AWS, GCP, Cloudflare, Azure,
    Oracle, Fastly, GitHub and DigitalOcean. Each is labelled provider and scope."""
    nets = Ranges()

    def aws(http: httpx.Client) -> None:
        body = _get(http, "https://ip-ranges.amazonaws.com/ip-ranges.json").json()
        for p in body.get("prefixes", []) + body.get("ipv6_prefixes", []):
            nets.add(
                p.get("ip_prefix") or p.get("ipv6_prefix") or "", f"AWS\t{p.get('region', '')}"
            )

    def gcp(http: httpx.Client) -> None:
        body = _get(http, "https://www.gstatic.com/ipranges/cloud.json").json()
        for p in body.get("prefixes", []):
            nets.add(p.get("ipv4Prefix") or p.get("ipv6Prefix") or "", f"GCP\t{p.get('scope', '')}")

    def cloudflare(http: httpx.Client) -> None:
        for ver in ("v4", "v6"):
            for line in _get(http, f"https://www.cloudflare.com/ips-{ver}").text.splitlines():
                nets.add(line, f"Cloudflare\t{ver}")

    def azure(http: httpx.Client) -> None:
        # The weekly file's name changes; the download page links the current one.
        page = _get(http, "https://www.microsoft.com/en-us/download/details.aspx?id=56519").text
        found = re.search(
            r"https://download\.microsoft\.com/download/[^\"']+ServiceTags_Public_\d+\.json", page
        )
        if not found:
            raise ValueError("no Service Tags file linked")
        tags = _get(http, found.group(0)).json().get("values", [])
        # The services first, so an address is named by its service rather than
        # by the AzureCloud tag that holds every range.
        for tag in sorted(tags, key=lambda t: str(t.get("name", "")).startswith("AzureCloud")):
            name = str(tag.get("name", ""))
            if "." in name:  # a region's copy of a global tag
                continue
            for cidr in (tag.get("properties") or {}).get("addressPrefixes", []):
                nets.add(cidr, f"Azure\t{name}")

    def oracle(http: httpx.Client) -> None:
        body = _get(http, "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json").json()
        for region in body.get("regions", []):
            for c in region.get("cidrs", []):
                nets.add(c.get("cidr", ""), f"Oracle\t{region.get('region', '')}")

    def fastly(http: httpx.Client) -> None:
        body = _get(http, "https://api.fastly.com/public-ip-list").json()
        for cidr in body.get("addresses", []) + body.get("ipv6_addresses", []):
            nets.add(cidr, "Fastly\tCDN")

    def github(http: httpx.Client) -> None:
        body = _get(http, "https://api.github.com/meta").json()
        # `actions` is every Azure region's ranges, where GitHub's hosted runners
        # live; Azure's own tags name those better (an Entra sign-in is not CI).
        skip = ("ssh_keys", "commit_signing_keys", "actions")
        for service, cidrs in body.items():
            if isinstance(cidrs, list) and service not in skip:
                for cidr in cidrs:
                    nets.add(str(cidr), f"GitHub\t{service}")

    def digitalocean(http: httpx.Client) -> None:
        for row in csv.reader(
            _get(http, "https://digitalocean.com/geo/google.csv").text.splitlines()
        ):
            if row:
                nets.add(row[0], f"DigitalOcean\t{row[1] if len(row) > 1 else ''}")

    with _client(LIST_TIMEOUT) as http:
        for provider in (aws, gcp, cloudflare, azure, oracle, fastly, github, digitalocean):
            # One provider being down must not blind the others.
            with contextlib.suppress(Exception):
                provider(http)
    return nets


def _vpn_ranges() -> Ranges:
    """X4BNet's VPN and datacenter ranges (MIT)."""
    nets = Ranges()
    base = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output"
    with _client(LIST_TIMEOUT) as http:
        for kind in ("vpn", "datacenter"):
            for ver in ("ipv4", "ipv6"):
                for line in _get(http, f"{base}/{kind}/{ver}.txt").text.splitlines():
                    nets.add(line, kind)
    return nets


def _ndjson(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return [r for r in rows if isinstance(r, dict) and r.get("type") != "metadata"]


def _drop() -> Ranges:
    """Spamhaus DROP: netblocks hijacked or run by criminals. Free for any business."""
    nets = Ranges()
    with _client(LIST_TIMEOUT) as http:
        for ver in ("v4", "v6"):
            for row in _ndjson(_get(http, f"https://www.spamhaus.org/drop/drop_{ver}.json").text):
                nets.add(str(row.get("cidr", "")), str(row.get("sblid", "")))
    return nets


def _asn_drop() -> set[int]:
    with _client(LIST_TIMEOUT) as http:
        rows = _ndjson(_get(http, "https://www.spamhaus.org/drop/asndrop.json").text)
    return {int(r["asn"]) for r in rows if str(r.get("asn", "")).isdigit()}


def _dbip(kind: str) -> Spans:
    """DB-IP's free IP-to-ASN or IP-to-Country table (CC BY 4.0), this month's or last."""
    table = Spans()
    first = datetime.now(UTC).replace(day=1)
    with _client(LIST_TIMEOUT) as http:
        for month in (first, first - timedelta(days=1)):
            resp = http.get(
                f"https://download.db-ip.com/free/dbip-{kind}-lite-{month:%Y-%m}.csv.gz"
            )
            if resp.status_code == 200:
                break
        resp.raise_for_status()
    rows = csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(resp.content)), "utf-8"))
    for row in rows:
        if kind == "asn" and len(row) >= 4:
            table.add(row[0], row[1], f"{row[2]}\t{row[3]}")
        elif kind == "country" and len(row) >= 3:
            table.add(row[0], row[1], row[2])
    return table


# The MISP warninglists (CC0) that name values which are never an indicator:
# resolvers, sinkholes, CRL hosts, URL shorteners, the big providers' domains,
# empty-file hashes, and values reports get wrong. A URL is never matched by
# its host (DET-4), so no list applies to a URL.
WARNINGLISTS = (
    "common-ioc-false-positive",
    "ti-falsepositives",
    "empty-hashes",
    "security-provider-blogpost",
    "public-dns-v4",
    "public-dns-v6",
    "public-dns-hostname",
    "sinkholes",
    "url-shortener",
    "whats-my-ip",
    "crl-hostname",
    "crl-ip",
    "microsoft",
    "microsoft-office365",
    "google",
    "second-level-tlds",
)
_MISP_KINDS = {
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "ip-src": "ip",
    "ip-dst": "ip",
    "md5": "md5",
    "filename|md5": "md5",
    "sha256": "sha256",
    "filename|sha256": "sha256",
}


class Benign:
    """Values on a warninglist, by type, with the list's name."""

    def __init__(self) -> None:
        self.exact: dict[tuple[str, str], str] = {}
        self.suffix: dict[str, str] = {}
        self.networks = Ranges()

    def add(self, name: str, kind: str, list_type: str, value: str) -> None:
        value = value.strip().lower()
        if not value:
            return
        if list_type == "cidr" or (kind == "ip" and "/" in value):
            self.networks.add(value, name)
        elif kind == "domain" and (list_type == "hostname" or value.startswith(".")):
            self.suffix.setdefault(value.lstrip("."), name)
        else:
            self.exact.setdefault((kind, value), name)

    def get(self, value: str, kind: str) -> str:
        value = value.strip().lower()
        if kind == "ip":
            found = self.networks.get(value)
            return found[1] if found else self.exact.get(("ip", value), "")
        if kind == "domain":
            if (kind, value) in self.exact:
                return self.exact[(kind, value)]
            labels = value.split(".")
            for i in range(len(labels) - 1):
                name = self.suffix.get(".".join(labels[i:]))
                if name:
                    return name
            return ""
        return self.exact.get((kind, value), "") if kind in ("md5", "sha256") else ""

    def __len__(self) -> int:
        return len(self.exact) + len(self.suffix) + len(self.networks)


def _warninglists() -> Benign:
    benign = Benign()
    base = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
    with _client(LIST_TIMEOUT) as http:
        for name in WARNINGLISTS:
            body = _get(http, f"{base}/{name}/list.json").json()
            kinds = {
                _MISP_KINDS[a] for a in body.get("matching_attributes", []) if a in _MISP_KINDS
            }
            for value in body.get("list", []):
                for kind in kinds:
                    benign.add(name, kind, str(body.get("type", "string")), str(value))
    return benign


def _disposable() -> set[str]:
    url = (
        "https://raw.githubusercontent.com/disposable-email-domains/"
        "disposable-email-domains/main/disposable_email_blocklist.conf"
    )
    with _client(LIST_TIMEOUT) as http:
        text = _get(http, url).text
    return {line.strip().lower() for line in text.splitlines() if line.strip()}


def _rdap_bootstrap() -> dict[str, Any]:
    """IANA's RDAP bootstrap: which registry answers for a TLD or an address block."""
    tlds: dict[str, str] = {}
    blocks = Ranges()
    with _client(LIST_TIMEOUT) as http:
        for name in ("dns", "ipv4", "ipv6"):
            for keys, urls in (
                _get(http, f"https://data.iana.org/rdap/{name}.json").json().get("services", [])
            ):
                base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else "")
                for key in keys:
                    if name == "dns":
                        tlds[str(key).lower()] = base
                    else:
                        blocks.add(str(key), base)
    return {"dns": tlds, "ip": blocks, "size": len(tlds) + len(blocks)}


# Every list `warm()` loads, with how long each copy is kept.
LISTS: dict[str, tuple[Callable[[], Any], timedelta]] = {
    "tor": (_tor_exits, _LIST_TTL),
    "cloud": (_cloud_networks, _DAY),
    "vpn": (_vpn_ranges, _DAY),
    "drop": (_drop, _DAY),
    "asn_drop": (_asn_drop, _DAY),
    "dbip_asn": (lambda: _dbip("asn"), _WEEK),
    "dbip_country": (lambda: _dbip("country"), _WEEK),
    "warninglists": (_warninglists, _DAY),
    "disposable": (_disposable, _DAY),
    "rdap_bootstrap": (_rdap_bootstrap, _DAY),
}

# The hosts those lists come from, so a deployment is told before they are reached.
LIST_HOSTS = (
    "check.torproject.org",
    "ip-ranges.amazonaws.com",
    "www.gstatic.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "download.microsoft.com",
    "docs.oracle.com",
    "api.fastly.com",
    "api.github.com",
    "digitalocean.com",
    "raw.githubusercontent.com",
    "www.spamhaus.org",
    "download.db-ip.com",
    "data.iana.org",
)


def warm() -> dict[str, str]:
    """Load every list whose copy is missing or old; the warnings, by list."""
    for key, (build, ttl) in LISTS.items():
        try:
            _cached_list(key, build, ttl)
        except Exception as exc:
            LIST_WARNINGS[key] = f"not loaded: {type(exc).__name__}: {exc}"[:300]
    return dict(LIST_WARNINGS)


def _listed(key: str) -> Any:
    build, ttl = LISTS[key]
    return _cached_list(key, build, ttl)


def known_benign(value: str, kind: str) -> str:
    """The warninglist a value is on, or "".

    Reads the lists only if this process has them already: it is called while
    reading a report or adding an indicator, which must not wait on a download.
    """
    hit = _LISTS.get("warninglists")
    return hit[1].get(value, kind) if hit else ""


# -- sources ----------------------------------------------------------------
# A domain's RDAP answer, kept a week per process: registrations change slowly.
_RDAP: dict[str, tuple[datetime, dict[str, Any]]] = {}


def _rdap_url(host: str, kind: str) -> str:
    """The registry IANA names for this TLD or address block, else rdap.org."""
    try:
        boot = _listed("rdap_bootstrap")
    except Exception:
        boot = {"dns": {}, "ip": Ranges()}
    if kind == "ip":
        found = boot["ip"].get(host)
        base = found[1] if found else ""
    else:
        base = boot["dns"].get(host.rsplit(".", 1)[-1], "")
    path = "ip" if kind == "ip" else "domain"
    return f"{base.rstrip('/')}/{path}/{host}" if base else f"https://rdap.org/{path}/{host}"


def rdap(value: str, kind: str) -> Observation:
    """Who owns it, and for a domain how long they have owned it.

    Only a `registration` event is a registration date: `last changed` on an
    old domain is not its age (RFC 0030). A domain's answer is kept a week.
    """
    host = host_of(value, kind)
    kept = _RDAP.get(host) if kind != "ip" else None
    if kept and datetime.now(UTC) - kept[0] < _WEEK:
        body = kept[1]
    else:
        with _client() as http:
            body = _get(http, _rdap_url(host, kind)).json()
        if kind != "ip":
            if len(_RDAP) >= 5_000:
                _RDAP.clear()
            _RDAP[host] = (datetime.now(UTC), body)
    name = str(body.get("name") or "")
    country = str(body.get("country") or "")
    entities = [str(e.get("handle", "")) for e in body.get("entities", []) if e.get("handle")][:3]
    registered = next(
        (
            str(ev.get("eventDate", ""))
            for ev in body.get("events", [])
            if ev.get("eventAction") == "registration"
        ),
        "",
    )
    data = {
        "name": name,
        "country": country,
        "entities": entities,
        "registered": registered,
        "handle": str(body.get("handle", "")),
    }
    verdict, weight, note = "informational", 0.0, ""
    if kind == "domain" and registered:
        try:
            age = (
                datetime.now(UTC) - datetime.fromisoformat(registered.replace("Z", "+00:00"))
            ).days
            data["age_days"] = age
            if age < 30:
                verdict, weight = "suspicious", 1.5
                note = f", registered {age} day(s) ago"
        except ValueError:
            pass
    owner = name or (entities[0] if entities else "")
    return Observation(
        source="rdap",
        verdict=verdict,
        weight=weight,
        summary=f"registered to {owner or 'an undisclosed party'}"
        + (f" in {country}" if country else "")
        + note,
        data=data,
    )


def reverse_dns(value: str, kind: str) -> Observation:
    """What the address claims to be. Not proof, but it names the cloud."""
    try:
        name, _, _ = socket.gethostbyaddr(value)
    except OSError:
        return Observation(
            source="reverse_dns", verdict="informational", summary="no PTR record", data={"ptr": ""}
        )
    return Observation(
        source="reverse_dns",
        verdict="informational",
        summary=f"resolves back to {name}",
        data={"ptr": name},
    )


def resolve(value: str, kind: str) -> Observation:
    """What a domain points at right now."""
    host = host_of(value, kind)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return Observation(
            source="resolve", ok=False, error=str(exc), summary=f"{host} does not resolve"
        )
    addrs = sorted({str(info[4][0]) for info in infos})
    return Observation(
        source="resolve",
        verdict="informational",
        summary=f"{host} resolves to {', '.join(addrs[:4])}",
        data={"addresses": addrs},
    )


def cloud_ranges(value: str, kind: str) -> Observation:
    """Is this shared infrastructure? The answer that stops us blocking a CDN."""
    found = _listed("cloud").get(value)
    if found:
        net, label = found
        provider, _, scope = label.partition("\t")
        return Observation(
            source="cloud_ranges",
            verdict="informational",
            weight=0.0,
            summary=f"inside {provider} {scope} ({net}), shared infrastructure",
            data={"provider": provider, "scope": scope, "network": net, "shared": True},
        )
    return Observation(
        source="cloud_ranges",
        verdict="informational",
        summary="not in a published cloud or CDN range",
        data={"shared": False},
    )


def vpn_ranges(value: str, kind: str) -> Observation:
    """A VPN exit or a hosting provider's range. Either way, others share it (D35)."""
    found = _listed("vpn").get(value)
    if found:
        net, label = found
        return Observation(
            source="vpn_ranges",
            verdict="informational",
            summary=f"inside a {label} range ({net}), shared infrastructure",
            data={
                "provider": "VPN" if label == "vpn" else "hosting",
                "network": net,
                "shared": True,
            },
        )
    return Observation(
        source="vpn_ranges",
        verdict="informational",
        summary="not in a known VPN or datacenter range",
        data={"shared": False},
    )


def spamhaus_drop(value: str, kind: str) -> Observation:
    """Spamhaus DROP: a netblock hijacked or run by criminals."""
    found = _listed("drop").get(value)
    if found:
        net, sbl = found
        return Observation(
            source="spamhaus_drop",
            verdict="malicious",
            weight=4.0,
            summary=f"inside {net}, on Spamhaus DROP ({sbl})",
            data={"network": net, "sbl": sbl},
        )
    return Observation(source="spamhaus_drop", verdict="informational", summary="not on DROP")


def asn(value: str, kind: str) -> Observation:
    """Who routes the address: its autonomous system and country, from DB-IP Lite."""
    found = _listed("dbip_asn").get(value)
    try:
        country = _listed("dbip_country").get(value) or ""
    except Exception:  # the country table is a nicety; the ASN is the answer
        country = ""
    country = "" if country == "ZZ" else country
    if not found:
        return Observation(
            source="asn",
            verdict="informational",
            summary="no AS on record",
            data={"country": country},
        )
    number, _, name = found.partition("\t")
    data = {"asn": int(number), "as_name": name, "country": country}
    if int(number) in _listed("asn_drop"):
        return Observation(
            source="asn",
            verdict="malicious",
            weight=4.0,
            summary=f"AS{number} {name} is on Spamhaus ASN-DROP",
            data={**data, "asn_drop": True},
        )
    return Observation(
        source="asn",
        verdict="informational",
        summary=f"AS{number} {name}" + (f", {country}" if country else ""),
        data=data,
    )


def tor_exit(value: str, kind: str) -> Observation:
    """A published Tor exit: suspicious for a login, meaningless as a block target."""
    if value in _listed("tor"):
        return Observation(
            source="tor_exit",
            verdict="suspicious",
            weight=2.0,
            summary="a published Tor exit node",
            data={"tor_exit": True, "shared": True},
        )
    return Observation(
        source="tor_exit",
        verdict="informational",
        summary="not a Tor exit node",
        data={"tor_exit": False},
    )


def warninglist(value: str, kind: str) -> Observation:
    """On a list of values that are never an indicator: a resolver, a sinkhole, a CRL host."""
    name = _listed("warninglists").get(value, kind)
    if name:
        return Observation(
            source="warninglist",
            verdict="benign",
            weight=-1.5,
            summary=f"on the MISP warninglist {name}",
            data={"list": name},
        )
    return Observation(source="warninglist", verdict="informational", summary="on no warninglist")


def disposable_email(value: str, kind: str) -> Observation:
    """A throwaway mail domain: odd as a forwarding target or a new admin."""
    domain = host_of(value, kind)
    if domain in _listed("disposable"):
        return Observation(
            source="disposable_email",
            verdict="suspicious",
            weight=1.0,
            summary=f"{domain} is a disposable mail domain",
            data={"disposable": True},
        )
    return Observation(
        source="disposable_email",
        verdict="informational",
        summary="not a disposable mail domain",
        data={"disposable": False},
    )


# -- sources that need an account (RFC 0030) ---------------------------------
def _abuse_ch(http_secret: dict[str, Any]) -> httpx.Client:
    client = _client()
    client.headers["Auth-Key"] = str(http_secret.get("auth_key") or "")
    return client


def threatfox(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """abuse.ch ThreatFox: has anyone reported this exact value?

    ThreatFox stores addresses as ip:port, so an address matches its own
    entries with any port; a URL or a domain matches only itself.
    """
    body_in = (
        {"query": "search_hash", "hash": value}
        if kind in ("sha256", "md5")
        else {"query": "search_ioc", "search_term": value}
    )
    with _abuse_ch(secret) as http:
        resp = http.post("https://threatfox-api.abuse.ch/api/v1/", json=body_in)
        resp.raise_for_status()
        body = resp.json()
    rows = body.get("data") if body.get("query_status") == "ok" else []
    if kind not in ("sha256", "md5"):
        want = value.lower()
        rows = [
            r
            for r in rows or []
            if isinstance(r, dict)
            and (
                str(r.get("ioc", "")).lower() == want
                or (kind == "ip" and str(r.get("ioc", "")).lower().rsplit(":", 1)[0] == want)
            )
        ]
    if not rows:
        return Observation(
            source="threatfox", verdict="informational", summary="no ThreatFox report"
        )
    malware = sorted(
        {str(r.get("malware_printable", "")) for r in rows if r.get("malware_printable")}
    )
    return Observation(
        source="threatfox",
        verdict="malicious",
        weight=4.0,
        summary=f"reported to ThreatFox as {', '.join(malware) or 'malicious'}"
        f" ({len(rows)} report(s))",
        data={
            "reports": len(rows),
            "malware": malware[:5],
            "first_seen": str(rows[0].get("first_seen", "")),
        },
    )


def urlhaus(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """abuse.ch URLhaus. A URL is asked about as itself; what its host serves is
    context with `relation: host_of` and no weight, never the URL's verdict (DET-4)."""
    listed: dict[str, Any] = {}
    with _abuse_ch(secret) as http:
        if kind == "url":
            resp = http.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": value})
            resp.raise_for_status()
            listed = resp.json()
        hosted = http.post(
            "https://urlhaus-api.abuse.ch/v1/host/", data={"host": host_of(value, kind)}
        )
        hosted.raise_for_status()
        host = hosted.json()
    urls = (host.get("urls") or []) if host.get("query_status") == "ok" else []
    online = [u for u in urls if u.get("url_status") == "online"]
    on_host = {
        "urls": len(urls),
        "online": len(online),
        "tags": sorted({t for u in urls[:10] for t in (u.get("tags") or [])})[:8],
    }
    if kind == "url":
        if listed.get("query_status") == "ok":
            up = listed.get("url_status") == "online"
            return Observation(
                source="urlhaus",
                verdict="malicious",
                weight=4.0 if up else 3.0,
                summary=f"on URLhaus as {listed.get('threat') or 'malware'}"
                + (", still online" if up else ", offline now"),
                data={"status": listed.get("url_status"), "tags": listed.get("tags") or []},
            )
        return Observation(
            source="urlhaus",
            verdict="informational",
            summary="not on URLhaus"
            + (f"; its host serves {len(urls)} other listed URL(s)" if urls else ""),
            data={"relation": "host_of", **on_host} if urls else {},
        )
    if not urls:
        return Observation(source="urlhaus", verdict="informational", summary="no URLhaus record")
    return Observation(
        source="urlhaus",
        verdict="malicious" if online else "suspicious",
        weight=4.0 if online else 1.5,
        summary=f"{len(urls)} malware URL(s) on URLhaus, {len(online)} still online",
        data=on_host,
    )


def malwarebazaar(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """abuse.ch MalwareBazaar: is this file a known malware sample?"""
    with _abuse_ch(secret) as http:
        resp = http.post(
            "https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value}
        )
        resp.raise_for_status()
        body = resp.json()
    if body.get("query_status") != "ok" or not body.get("data"):
        return Observation(
            source="malwarebazaar", verdict="informational", summary="not on MalwareBazaar"
        )
    sample = body["data"][0]
    name = str(sample.get("signature") or sample.get("file_type") or "malware")
    return Observation(
        source="malwarebazaar",
        verdict="malicious",
        weight=4.0,
        summary=f"a known {name} sample on MalwareBazaar",
        data={
            "signature": str(sample.get("signature") or ""),
            "file_type": str(sample.get("file_type") or ""),
            "first_seen": str(sample.get("first_seen") or ""),
            "tags": (sample.get("tags") or [])[:8],
        },
    )


def ipapi_is(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """ipapi.is: VPN, proxy, Tor, datacenter or known abuser, and the AS behind it."""
    with _client() as http:
        resp = http.get("https://api.ipapi.is/", params={"q": value, "key": secret.get("key", "")})
        resp.raise_for_status()
        body = resp.json()
    flags = [f for f in ("vpn", "proxy", "tor", "datacenter", "abuser") if body.get(f"is_{f}")]
    company = str(
        (body.get("company") or {}).get("name") or (body.get("asn") or {}).get("org") or ""
    )
    return Observation(
        source="ipapi_is",
        verdict="suspicious" if "abuser" in flags else "informational",
        weight=1.5 if "abuser" in flags else 0.0,
        summary=(f"{', '.join(flags)} address" if flags else "no VPN, proxy or abuse flag")
        + (f" ({company})" if company else ""),
        data={
            "flags": flags,
            "company": company,
            "asn": (body.get("asn") or {}).get("asn"),
            "abuse": str((body.get("abuse") or {}).get("email") or ""),
            "shared": bool({"vpn", "proxy", "tor"} & set(flags)),
            "provider": company,
        },
    )


def abuseipdb(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    with _client() as http:
        resp = http.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": str(secret.get("api_key") or ""), "Accept": "application/json"},
        )
        resp.raise_for_status()
        body = resp.json().get("data") or {}
    score = int(body.get("abuseConfidenceScore") or 0)
    return Observation(
        source="abuseipdb",
        verdict="malicious" if score >= 75 else "suspicious" if score >= 25 else "informational",
        weight=3.0 if score >= 75 else 1.5 if score >= 25 else 0.0,
        summary=f"AbuseIPDB confidence {score}% from {body.get('totalReports', 0)} report(s)"
        + (f", {body.get('usageType')}" if body.get("usageType") else ""),
        data={
            "confidence": score,
            "reports": int(body.get("totalReports") or 0),
            "usage": str(body.get("usageType") or ""),
            "isp": str(body.get("isp") or ""),
        },
    )


def greynoise(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    with _client() as http:
        resp = http.get(
            f"https://api.greynoise.io/v3/community/{value}",
            headers={"key": str(secret.get("api_key") or "")},
        )
        if resp.status_code == 404:
            return Observation(
                source="greynoise", verdict="informational", summary="GreyNoise has not seen it"
            )
        resp.raise_for_status()
        body = resp.json()
    name = str(body.get("name") or "")
    if body.get("riot"):
        return Observation(
            source="greynoise",
            verdict="benign",
            weight=-1.0,
            summary=f"a common business service ({name or 'GreyNoise RIOT'})",
            data={"riot": True, "name": name},
        )
    classification = str(body.get("classification") or "unknown")
    return Observation(
        source="greynoise",
        verdict="suspicious" if classification == "malicious" else "informational",
        weight=2.0 if classification == "malicious" else -0.5 if classification == "benign" else 0,
        summary=f"scans the internet, classified {classification}" + (f" ({name})" if name else ""),
        data={"noise": bool(body.get("noise")), "classification": classification, "name": name},
    )


def _ports(source: str, ports: list[Any], org: str) -> Observation:
    ports = sorted({int(p) for p in ports if str(p).isdigit()})
    return Observation(
        source=source,
        verdict="informational",
        summary=(
            f"{len(ports)} open port(s): {', '.join(map(str, ports[:8]))}"
            if ports
            else "no open port on record"
        )
        + (f" ({org})" if org else ""),
        data={"ports": ports[:20], "org": org},
    )


def shodan(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    with _client() as http:
        resp = http.get(
            f"https://api.shodan.io/shodan/host/{value}",
            params={"key": str(secret.get("api_key") or ""), "minify": "true"},
        )
        if resp.status_code == 404:
            return _ports("shodan", [], "")
        resp.raise_for_status()
        body = resp.json()
    return _ports("shodan", body.get("ports") or [], str(body.get("org") or ""))


def netlas(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    with _client() as http:
        resp = http.get(
            f"https://app.netlas.io/api/host/{value}/",
            headers={"X-API-Key": str(secret.get("api_key") or "")},
        )
        if resp.status_code == 404:
            return _ports("netlas", [], "")
        resp.raise_for_status()
        body = resp.json()
    ports = [p.get("port") if isinstance(p, dict) else p for p in body.get("ports") or []]
    org = str((body.get("whois") or {}).get("net", {}).get("organization") or "")
    return _ports("netlas", ports, org)


def virustotal(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """VirusTotal's engine verdicts. Only read, never submitted: a submission is public."""
    path = {"ip": "ip_addresses", "domain": "domains", "url": "urls"}.get(kind, "files")
    ident = (
        base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if kind == "url" else value
    )
    with _client() as http:
        resp = http.get(
            f"https://www.virustotal.com/api/v3/{path}/{ident}",
            headers={"x-apikey": str(secret.get("api_key") or "")},
        )
        if resp.status_code == 404:
            return Observation(
                source="virustotal", verdict="informational", summary="VirusTotal has no record"
            )
        resp.raise_for_status()
        stats = (resp.json().get("data") or {}).get("attributes", {}).get(
            "last_analysis_stats"
        ) or {}
    bad = int(stats.get("malicious") or 0)
    return Observation(
        source="virustotal",
        verdict="malicious" if bad >= 3 else "suspicious" if bad else "informational",
        weight=4.0 if bad >= 3 else 1.5 if bad else 0.0,
        summary=f"{bad} engine(s) on VirusTotal call it malicious, "
        f"{int(stats.get('harmless') or 0)} harmless",
        data={
            k: int(stats.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected")
        },
    )


def urlscan(value: str, kind: str, secret: dict[str, Any]) -> Observation:
    """urlscan.io's earlier scans. Only searched, never scanned: a public scan publishes the URL."""
    clean = value.replace('"', "").replace("\\", "")
    query = f'page.url:"{clean}"' if kind == "url" else f"domain:{clean}"
    with _client() as http:
        resp = http.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 20},
            headers={"API-Key": str(secret.get("api_key") or "")},
        )
        resp.raise_for_status()
        results = resp.json().get("results") or []
    flagged = sum(
        1 for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")
    )
    return Observation(
        source="urlscan",
        verdict="suspicious" if flagged else "informational",
        weight=1.5 if flagged else 0.0,
        summary=f"{len(results)} earlier scan(s) on urlscan.io"
        + (f", {flagged} flagged malicious" if flagged else ""),
        data={"scans": len(results), "malicious": flagged},
    )


def epss(value: str, kind: str) -> Observation:
    """FIRST's exploit-prediction score: how likely is this CVE to be used?"""
    with _client() as http:
        resp = http.get("https://api.first.org/data/v1/epss", params={"cve": value.upper()})
        resp.raise_for_status()
        rows = resp.json().get("data", [])
    if not rows:
        return Observation(source="epss", verdict="informational", summary="no EPSS score")
    score = float(rows[0].get("epss", 0.0))
    percentile = float(rows[0].get("percentile", 0.0))
    return Observation(
        source="epss",
        verdict="malicious" if score >= 0.5 else ("suspicious" if score >= 0.1 else "benign"),
        weight=3.0 if score >= 0.5 else (1.0 if score >= 0.1 else -0.5),
        summary=f"EPSS {score:.1%} ({percentile:.0%} percentile) chance of exploitation "
        "in the next 30 days",
        data={"epss": score, "percentile": percentile},
    )


def nvd(value: str, kind: str) -> Observation:
    """The CVE record itself: what it is and how bad it scores."""
    with _client() as http:
        resp = http.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": value.upper()}
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
    if not items:
        return Observation(source="nvd", verdict="informational", summary="not in the NVD")
    cve = items[0].get("cve", {})
    descriptions = [
        d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"
    ]
    metrics = cve.get("metrics", {})
    cvss, severity = 0.0, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss = float(data.get("baseScore", 0.0))
            severity = str(data.get("baseSeverity", ""))
            break
    return Observation(
        source="nvd",
        verdict="informational",
        weight=1.0 if cvss >= 9.0 else 0.0,
        summary=f"CVSS {cvss} {severity}".strip()
        + (f" — {descriptions[0][:160]}" if descriptions else ""),
        data={
            "cvss": cvss,
            "severity": severity,
            "published": str(cve.get("published", "")),
            "description": descriptions[0][:500] if descriptions else "",
        },
    )


SOURCES: dict[str, Source] = {
    s.name: s
    for s in (
        # The registry IANA's bootstrap names for the TLD or block, else rdap.org.
        Source("rdap", ("ip", "domain", "url", "email"), ("data.iana.org", "rdap.org"), rdap),
        Source("reverse_dns", ("ip",), (), reverse_dns),
        Source("resolve", ("domain", "url", "email"), (), resolve),
        # Downloaded lists: the value goes nowhere (RFC 0030).
        Source("asn", ("ip",), ("download.db-ip.com", "www.spamhaus.org"), asn, listed=True),
        Source(
            "cloud_ranges",
            ("ip",),
            (
                "ip-ranges.amazonaws.com",
                "www.gstatic.com",
                "www.cloudflare.com",
                "www.microsoft.com",
                "download.microsoft.com",
                "docs.oracle.com",
                "api.fastly.com",
                "api.github.com",
                "digitalocean.com",
            ),
            cloud_ranges,
            listed=True,
        ),
        Source("vpn_ranges", ("ip",), ("raw.githubusercontent.com",), vpn_ranges, listed=True),
        Source("spamhaus_drop", ("ip",), ("www.spamhaus.org",), spamhaus_drop, listed=True),
        Source("tor_exit", ("ip",), ("check.torproject.org",), tor_exit, listed=True),
        Source(
            "warninglist",
            ("ip", "domain", "sha256", "md5"),
            ("raw.githubusercontent.com",),
            warninglist,
            listed=True,
        ),
        Source(
            "disposable_email",
            ("email",),
            ("raw.githubusercontent.com",),
            disposable_email,
            listed=True,
        ),
        Source("epss", ("cve",), ("api.first.org",), epss),
        Source("nvd", ("cve",), ("services.nvd.nist.gov",), nvd),
        # An account each, configured by a person, under a daily quota.
        Source(
            "threatfox",
            ("ip", "domain", "url", "sha256", "md5"),
            ("threatfox-api.abuse.ch",),
            threatfox,
            key="abuse_ch",
        ),
        Source(
            "urlhaus", ("ip", "domain", "url"), ("urlhaus-api.abuse.ch",), urlhaus, key="abuse_ch"
        ),
        Source(
            "malwarebazaar", ("sha256", "md5"), ("mb-api.abuse.ch",), malwarebazaar, key="abuse_ch"
        ),
        Source("ipapi_is", ("ip",), ("api.ipapi.is",), ipapi_is, key="ipapi_is"),
        Source("abuseipdb", ("ip",), ("api.abuseipdb.com",), abuseipdb, key="abuseipdb"),
        Source("greynoise", ("ip",), ("api.greynoise.io",), greynoise, key="greynoise"),
        Source("shodan", ("ip",), ("api.shodan.io",), shodan, key="shodan"),
        Source("netlas", ("ip",), ("app.netlas.io",), netlas, key="netlas"),
        Source(
            "virustotal",
            ("ip", "domain", "url", "sha256", "md5"),
            ("www.virustotal.com",),
            virustotal,
            key="virustotal",
        ),
        Source("urlscan", ("domain", "url"), ("urlscan.io",), urlscan, key="urlscan"),
    )
}


# -- our own data -----------------------------------------------------------
LOCAL = ("local_iocs", "history")


def local_iocs(conn: Conn, tenant_id: str, value: str, kind: str) -> Observation:
    """Is it on a feed we pull? A URL is judged by itself: its host on a feed is
    context (`relation: host_of`), not the URL's verdict (DET-4). An email is
    judged by its domain, which owns every mailbox under it."""
    rows = fetch_all(
        conn,
        """SELECT value, source, confidence, severity, description, tags, first_seen
           FROM shoc.iocs
           WHERE tenant_id = %s AND value = ANY(%s)
             AND (expires_at IS NULL OR expires_at > now())
           ORDER BY confidence DESC LIMIT 5""",
        # The value itself, and for a URL or an email the host it hangs off.
        (tenant_id, sorted({value.lower(), host_of(value, kind)})),
    )
    if kind == "url" and rows and not any(r["value"] == value.lower() for r in rows):
        feeds = sorted({str(r["source"]) for r in rows})
        return Observation(
            source="local_iocs",
            verdict="informational",
            summary=f"its host is on {', '.join(feeds)}; the URL itself is not",
            data={"relation": "host_of", "feeds": feeds},
        )
    if kind == "url":
        rows = [r for r in rows if r["value"] == value.lower()]
    if not rows:
        return Observation(
            source="local_iocs", verdict="informational", summary="not on any feed we pull"
        )
    best = max(float(r["confidence"]) for r in rows)
    feeds = sorted({str(r["source"]) for r in rows})
    return Observation(
        source="local_iocs",
        verdict="malicious",
        weight=4.0 * best,
        summary=f"on {len(feeds)} feed(s) we already pull: {', '.join(feeds)}",
        data={
            "feeds": feeds,
            "confidence": best,
            "descriptions": [str(r["description"]) for r in rows][:3],
        },
    )


def history(store: Any, tenant_id: str, value: str, kind: str) -> Observation:
    """Has this ever been in our own logs? The most important source we have."""
    from shoc.capabilities.events import EventQuery, build_query

    query = EventQuery(since="-90d", limit=500)
    if kind == "ip":
        query.src_ip = value
    else:
        query.contains = host_of(value, kind)
    sql, params, limit = build_query(query, tenant_id)
    rows = store.query(sql, params, limit).rows
    if not rows:
        return Observation(
            source="history",
            verdict="informational",
            summary="never seen in our logs in the last 90 days",
            data={"events": 0},
        )
    actors = sorted({str(r.get("actor_user_name") or "") for r in rows if r.get("actor_user_name")})
    return Observation(
        source="history",
        verdict="informational",
        summary=f"{len(rows)} event(s) in the last 90 days"
        + (f", involving {', '.join(actors[:3])}" if actors else ""),
        data={
            "events": len(rows),
            "actors": actors[:10],
            "event_uids": [str(r["event_uid"]) for r in rows[:20]],
        },
    )


# -- scoring ----------------------------------------------------------------
def score(observations: list[Observation]) -> tuple[str, float, float]:
    """Add the weights up and name the result. Positive is bad."""
    total = sum(o.weight for o in observations if o.ok)
    answered = [o for o in observations if o.ok and o.verdict != "informational"]
    if total >= 4.0:
        verdict = "malicious"
    elif total >= 1.5:
        verdict = "suspicious"
    elif total <= -0.5:
        verdict = "benign"
    else:
        verdict = "unknown"
    ok = [o for o in observations if o.ok]
    coverage = len(ok) / max(1, len(observations))
    strength = min(1.0, abs(total) / 5.0)
    confidence = round(0.2 + 0.4 * coverage + 0.4 * strength, 3) if answered or ok else 0.0
    return verdict, total, confidence


def _summarise(research: Research) -> str:
    lead = {
        "malicious": f"{research.value} is known-bad",
        "suspicious": f"{research.value} looks suspicious",
        "benign": f"{research.value} looks ordinary",
        "unknown": f"nothing conclusive is known about {research.value}",
    }[research.verdict]
    parts = [o.summary for o in research.observations if o.ok and o.weight != 0.0][:3]
    if research.shared_infrastructure:
        parts.insert(0, f"it is shared infrastructure ({research.owner or 'a cloud or CDN'})")
    if research.seen_in_our_logs:
        parts.append(f"it appears in {research.seen_in_our_logs} of our own event(s)")
    listed = sum(1 for o in research.observations if o.ok and o.listed)
    return (
        lead
        + (": " + "; ".join(parts) if parts else ".")
        + (
            f" [{len(research.sources_ok)} source(s) answered"
            + (f", {listed} from downloaded lists" if listed else "")
            + (f", {len(research.sources_failed)} failed]" if research.sources_failed else "]")
        )
    )


# -- the lookup ------------------------------------------------------------
def research(
    conn: Conn,
    store: Any,
    tenant_id: str,
    value: str,
    kind: str = "",
    *,
    refresh: bool = False,
    only: tuple[str, ...] = (),
    budget_seconds: float = BUDGET_SECONDS,
    master_key: str = "",
) -> Research:
    """Ask everything that can answer, in parallel, and score what comes back.

    A source that needs an account runs only when the tenant configured its
    key, and only while the key's daily quota has room (RFC 0030).
    """
    started = time.monotonic()
    value = value.strip().strip(".")
    kind = kind or classify(value)
    out = Research(value=value, type=kind)
    if not kind:
        out.summary = f"'{value}' is not an indicator type we recognise."
        return out

    out.internal = is_internal(value, kind)
    observations: list[Observation] = []

    # Our own data first: it is free, it is private, and it is the most relevant.
    # It is read fresh every time, so an indicator added or an event loaded a
    # minute ago is in the answer (DET-6).
    for name, fn in (
        ("local_iocs", lambda: local_iocs(conn, tenant_id, value, kind)),
        ("history", lambda: history(store, tenant_id, value, kind)),
    ):
        if only and name not in only:
            continue
        if name == "history" and kind not in ("ip", "domain", "url", "email"):
            continue
        try:
            observations.append(fn())
        except Exception as exc:
            observations.append(
                Observation(source=name, ok=False, error=f"{type(exc).__name__}: {exc}")
            )

    # Third parties, only for values it is safe to disclose. Their answers are
    # what the cache holds; a lookup limited to some sources is not cached.
    remote = None if refresh or only else _from_cache(conn, tenant_id, value, kind)
    out.cached = remote is not None
    if remote is not None:
        observations += remote
    elif not out.internal:
        remote = []
        keys = _keys(conn, tenant_id, master_key)
        chosen = []
        for source in SOURCES.values():
            if kind not in source.kinds or (only and source.name not in only):
                continue
            if source.key:
                if source.key not in keys:
                    continue
                refused = _take(conn, tenant_id, source.key, keys[source.key][1])
                if refused:
                    remote.append(Observation(source=source.name, ok=False, error=refused))
                    continue
            chosen.append(source)
        if chosen:
            with ThreadPoolExecutor(max_workers=min(8, len(chosen))) as pool:
                futures = {
                    pool.submit(_run_source, s, value, kind, keys[s.key][0] if s.key else None): s
                    for s in chosen
                }
                deadline = budget_seconds - (time.monotonic() - started)
                try:
                    for future in as_completed(futures, timeout=max(1.0, deadline)):
                        remote.append(future.result())
                except TimeoutError:
                    for future, source in futures.items():
                        if not future.done():
                            future.cancel()
                            remote.append(
                                Observation(
                                    source=source.name,
                                    ok=False,
                                    error=f"did not answer within {budget_seconds:.0f}s",
                                )
                            )
        for obs in remote:
            wait = obs.data.get("retry_after") if not obs.ok else None
            if wait and SOURCES.get(obs.source) and SOURCES[obs.source].key:
                _pause(conn, tenant_id, SOURCES[obs.source].key, int(wait))
        observations += remote
        if not only:
            _to_cache(conn, tenant_id, value, kind, remote)
    else:
        observations.append(
            Observation(
                source="disclosure_guard",
                verdict="informational",
                summary=f"{value} is internal, so it was not sent to any third party",
                data={"internal": True},
            )
        )

    out.observations = sorted(observations, key=lambda o: (-o.weight, o.source))
    out.sources_ok = [o.source for o in out.observations if o.ok]
    out.sources_failed = [o.source for o in out.observations if not o.ok]
    out.verdict, out.score, out.confidence = score(out.observations)
    for obs in out.observations:
        if obs.data.get("shared"):
            out.shared_infrastructure = True
            out.owner = out.owner or str(obs.data.get("provider") or "")
        if obs.source in ("rdap", "asn"):
            out.owner = out.owner or str(obs.data.get("name") or obs.data.get("as_name") or "")
        if obs.source == "history":
            out.seen_in_our_logs = int(obs.data.get("events") or 0)
    out.elapsed_ms = int((time.monotonic() - started) * 1000)
    out.summary = _summarise(out)
    return out


def _run_source(
    source: Source, value: str, kind: str, secret: dict[str, Any] | None = None
) -> Observation:
    try:
        obs = source.fn(value, kind, secret) if source.key else source.fn(value, kind)
        obs.listed = source.listed
        return obs
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            after = exc.response.headers.get("retry-after", "")
            return Observation(
                source=source.name,
                ok=False,
                error="rate limited (429); paused",
                data={"retry_after": int(after) if after.isdigit() else 3600},
            )
        return Observation(source=source.name, ok=False, error=f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        return Observation(source=source.name, ok=False, error=f"{type(exc).__name__}: {exc}")


def _keys(
    conn: Conn, tenant_id: str, master_key: str = ""
) -> dict[str, tuple[dict[str, Any], int]]:
    """The tenant's configured lookup keys: (secret, per_day) by source (RFC 0030)."""
    from shoc.db.secrets import open_secret

    rows = fetch_all(
        conn,
        "SELECT source, settings, secret FROM shoc.lookup_sources WHERE tenant_id = %s AND enabled",
        (tenant_id,),
    )
    if not rows:
        return {}
    if not master_key:
        from shoc.config import Config

        master_key = Config.load().master_key
    out: dict[str, tuple[dict[str, Any], int]] = {}
    for row in rows:
        provider = KEYED.get(str(row["source"]))
        if not provider or not row["secret"]:
            continue
        try:
            secret = open_secret(
                master_key, row["secret"], tenant_id, "lookup_sources", provider.name
            )
        except Exception:  # a key sealed under another master key is no key
            continue
        per_day = int((row["settings"] or {}).get("per_day") or provider.per_day)
        out[provider.name] = (secret, per_day)
    return out


def _take(conn: Conn, tenant_id: str, provider: str, per_day: int) -> str:
    """Count one call against today's quota; why not, when there is no room."""
    taken = fetch_one(
        conn,
        """INSERT INTO shoc.lookup_usage (tenant_id, day, source, calls)
           VALUES (%s, current_date, %s, 1)
           ON CONFLICT (tenant_id, day, source) DO UPDATE SET calls = shoc.lookup_usage.calls + 1
           WHERE shoc.lookup_usage.calls < %s
             AND (shoc.lookup_usage.paused_until IS NULL OR shoc.lookup_usage.paused_until < now())
           RETURNING calls""",
        (tenant_id, provider, per_day),
    )
    if taken:
        return ""
    row = (
        fetch_one(
            conn,
            """SELECT calls, paused_until FROM shoc.lookup_usage
           WHERE tenant_id = %s AND day = current_date AND source = %s""",
            (tenant_id, provider),
        )
        or {}
    )
    paused = row.get("paused_until")
    if paused and paused > datetime.now(UTC):
        return f"{provider} asked us to wait until {paused:%H:%M} UTC"
    return f"{provider}'s daily quota of {per_day} call(s) is used up"


def _pause(conn: Conn, tenant_id: str, provider: str, seconds: int) -> None:
    execute(
        conn,
        """INSERT INTO shoc.lookup_usage (tenant_id, day, source, paused_until)
           VALUES (%s, current_date, %s, now() + %s * interval '1 second')
           ON CONFLICT (tenant_id, day, source) DO UPDATE SET paused_until = EXCLUDED.paused_until""",
        (tenant_id, provider, max(1, min(seconds, 86_400))),
    )


def research_target(
    conn: Conn, store: Any, tenant_id: str, target_kind: str, target: str, **kw: Any
) -> Research | None:
    """Research the target of a proposed action, or None when it is not researchable.

    A hash is researched as the digest it is (RSP-5); a SHA-1, which no source
    here answers for, comes back as research that found nothing.
    """
    if target_kind == "hash":
        target_kind = classify(target) or "sha1"
    if target_kind not in ("ip", "domain", "url", "sha256", "md5", "sha1") or not target:
        return None
    try:
        return research(conn, store, tenant_id, target, target_kind, **kw)
    except Exception:
        return None


# -- cache ------------------------------------------------------------------
# The cache holds what third parties said, never what our own indicators and
# logs say: those change the moment a feed, `intel.add` or an ingest lands.
def _from_cache(conn: Conn, tenant_id: str, value: str, kind: str) -> list[Observation] | None:
    row = fetch_one(
        conn,
        """SELECT payload FROM shoc.intel_lookups
           WHERE tenant_id = %s AND type = %s AND value = %s AND expires_at > now()""",
        (tenant_id, kind, value.lower()),
    )
    if not row:
        return None
    payload = row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"])
    return [
        Observation(**o) for o in payload.get("observations", []) if o.get("source") not in LOCAL
    ]


def _to_cache(
    conn: Conn, tenant_id: str, value: str, kind: str, observations: list[Observation]
) -> None:
    verdict, total, confidence = score(observations)
    payload = {"observations": [asdict(o) for o in observations]}
    with contextlib.suppress(Exception):
        execute(
            conn,
            """INSERT INTO shoc.intel_lookups
                   (tenant_id, type, value, verdict, score, confidence, payload, expires_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s, now() + %s)
               ON CONFLICT (tenant_id, type, value) DO UPDATE SET
                   looked_up_at = now(), verdict = EXCLUDED.verdict, score = EXCLUDED.score,
                   confidence = EXCLUDED.confidence, payload = EXCLUDED.payload,
                   expires_at = EXCLUDED.expires_at""",
            (
                tenant_id,
                kind,
                value.lower(),
                verdict,
                total,
                confidence,
                json.dumps(payload),
                CACHE_TTL,
            ),
        )
