"""Reading a threat report (DET-7).

An analyst is handed a link to a vendor write-up and comes back with indicators,
techniques and a hunt. This module does the mechanical half of that: fetch the
thing, flatten it to plain text, undo the defanging every report applies to its
own indicators, and pull out the values a regular expression can find reliably.

It deliberately does **not** decide what the report means. That is the CTI
role's job, and the text it reads is untrusted — a report is a document written
by someone else, which may be quoting an attacker, and may itself be hostile.
Everything here returns data; nothing here is an instruction.

PDF needs `pip install shoc[pdf]`. HTML, markdown and plain text need nothing.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import time
import urllib.request
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from shoc.errors import ConfigError, ValidationError

MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT = 200_000
# A fetch follows at most this many redirects and reads for at most this long:
# a per-read timeout does not stop a server that trickles bytes.
REDIRECTS = 3
DEADLINE = 60.0

# Hosts whose "indicators" are the infrastructure of the report itself.
NOISE_DOMAINS = {
    "github.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "google.com",
    "microsoft.com",
    "virustotal.com",
    "any.run",
    "hybrid-analysis.com",
    "urlscan.io",
    "attack.mitre.org",
    "mitre.org",
    "cve.org",
    "nvd.nist.gov",
    "cisa.gov",
    "abuse.ch",
    "wikipedia.org",
    "schema.org",
    "w3.org",
    "creativecommons.org",
    "gravatar.com",
}

# Page furniture as well as code: a blog's menu, header, sidebar and footer are
# words the model would read and bill for (RFC 0029). Not `form`: some sites
# wrap the whole page in one.
_SCRIPT = re.compile(r"<(script|style|noscript|svg|nav|header|footer|aside)\b.*?</\1>", re.I | re.S)
_BLOCK = re.compile(r"</(p|div|li|tr|h[1-6]|section|article|br)\s*>", re.I)
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"[ \t\r\f\v]+")
_BLANK = re.compile(r"\n{3,}")

# Indicators, after refanging. A domain ends in any label shaped like a TLD and
# is kept only when that label is one (`_on_tld`).
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Hex and colons with at least two colons; `ipaddress` decides what is an address.
_IPV6 = re.compile(r"(?<![\w:.])(?=[0-9a-f:]*:[0-9a-f:]*:)[0-9a-f:]{2,39}(?![\w:]|\.\d)", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b", re.I
)

# The TLDs a report's domain is checked against before IANA's RDAP bootstrap is
# loaded, and those the bootstrap leaves out: every country code, the legacy
# generic ones, the new ones phishing uses most, and `test` and `example`,
# which fixtures use the way they use the documentation address ranges.
TLDS = frozenset(
    [
        "ac",
        "ad",
        "ae",
        "af",
        "ag",
        "ai",
        "al",
        "am",
        "ao",
        "aq",
        "ar",
        "as",
        "at",
        "au",
        "aw",
        "ax",
        "az",
        "ba",
        "bb",
        "bd",
        "be",
        "bf",
        "bg",
        "bh",
        "bi",
        "bj",
        "bm",
        "bn",
        "bo",
        "bq",
        "br",
        "bs",
        "bt",
        "bv",
        "bw",
        "by",
        "bz",
        "ca",
        "cc",
        "cd",
        "cf",
        "cg",
        "ch",
        "ci",
        "ck",
        "cl",
        "cm",
        "cn",
        "co",
        "cr",
        "cu",
        "cv",
        "cw",
        "cx",
        "cy",
        "cz",
        "de",
        "dj",
        "dk",
        "dm",
        "do",
        "dz",
        "ec",
        "ee",
        "eg",
        "er",
        "es",
        "et",
        "eu",
        "fi",
        "fj",
        "fk",
        "fm",
        "fo",
        "fr",
        "ga",
        "gb",
        "gd",
        "ge",
        "gf",
        "gg",
        "gh",
        "gi",
        "gl",
        "gm",
        "gn",
        "gp",
        "gq",
        "gr",
        "gs",
        "gt",
        "gu",
        "gw",
        "gy",
        "hk",
        "hm",
        "hn",
        "hr",
        "ht",
        "hu",
        "id",
        "ie",
        "il",
        "im",
        "in",
        "io",
        "iq",
        "ir",
        "is",
        "it",
        "je",
        "jm",
        "jo",
        "jp",
        "ke",
        "kg",
        "kh",
        "ki",
        "km",
        "kn",
        "kp",
        "kr",
        "kw",
        "ky",
        "kz",
        "la",
        "lb",
        "lc",
        "li",
        "lk",
        "lr",
        "ls",
        "lt",
        "lu",
        "lv",
        "ly",
        "ma",
        "mc",
        "md",
        "me",
        "mg",
        "mh",
        "mk",
        "ml",
        "mm",
        "mn",
        "mo",
        "mp",
        "mq",
        "mr",
        "ms",
        "mt",
        "mu",
        "mv",
        "mw",
        "mx",
        "my",
        "mz",
        "na",
        "nc",
        "ne",
        "nf",
        "ng",
        "ni",
        "nl",
        "no",
        "np",
        "nr",
        "nu",
        "nz",
        "om",
        "pa",
        "pe",
        "pf",
        "pg",
        "ph",
        "pk",
        "pl",
        "pm",
        "pn",
        "pr",
        "ps",
        "pt",
        "pw",
        "py",
        "qa",
        "re",
        "ro",
        "rs",
        "ru",
        "rw",
        "sa",
        "sb",
        "sc",
        "sd",
        "se",
        "sg",
        "sh",
        "si",
        "sj",
        "sk",
        "sl",
        "sm",
        "sn",
        "so",
        "sr",
        "ss",
        "st",
        "su",
        "sv",
        "sx",
        "sy",
        "sz",
        "tc",
        "td",
        "tf",
        "tg",
        "th",
        "tj",
        "tk",
        "tl",
        "tm",
        "tn",
        "to",
        "tr",
        "tt",
        "tv",
        "tw",
        "tz",
        "ua",
        "ug",
        "uk",
        "us",
        "uy",
        "uz",
        "va",
        "vc",
        "ve",
        "vg",
        "vi",
        "vn",
        "vu",
        "wf",
        "ws",
        "ye",
        "yt",
        "za",
        "zm",
        "zw",
        "xn--p1ai",
        "xn--fiqs8s",
        "xn--j1amh",
        "xn--90ais",
        "com",
        "net",
        "org",
        "info",
        "biz",
        "name",
        "pro",
        "mobi",
        "asia",
        "tel",
        "travel",
        "jobs",
        "cat",
        "coop",
        "aero",
        "museum",
        "int",
        "edu",
        "gov",
        "mil",
        "post",
        "xxx",
        "xyz",
        "top",
        "online",
        "site",
        "shop",
        "store",
        "club",
        "live",
        "icu",
        "link",
        "click",
        "lol",
        "sbs",
        "cfd",
        "vip",
        "app",
        "dev",
        "cloud",
        "zip",
        "mov",
        "tech",
        "space",
        "website",
        "fun",
        "buzz",
        "rest",
        "bond",
        "cyou",
        "monster",
        "quest",
        "beauty",
        "hair",
        "skin",
        "makeup",
        "autos",
        "boats",
        "homes",
        "yachts",
        "world",
        "today",
        "life",
        "news",
        "blog",
        "email",
        "digital",
        "network",
        "support",
        "services",
        "solutions",
        "company",
        "agency",
        "global",
        "group",
        "media",
        "one",
        "win",
        "bid",
        "loan",
        "work",
        "date",
        "racing",
        "download",
        "stream",
        "review",
        "party",
        "trade",
        "science",
        "men",
        "cam",
        "best",
        "uno",
        "ink",
        "kim",
        "ltd",
        "host",
        "press",
        "pics",
        "page",
        "help",
        "run",
        "tokyo",
        "lat",
        "locker",
        "mom",
        "bar",
        "test",
        "example",
    ]
)
# Real TLDs that are also file extensions: `invoice.zip`, `stealer.py` or
# `libcrypto.so` in prose is a file. Such a name counts only when the report
# defanged it, a URL or an address hangs off it, or it stands alone on its line,
# as in a list. So does a name written like code, `objShell.Run` or
# `ADODB.Stream`: a camelCase label, or a last label written `Capitalised`.
FILE_TLDS = frozenset(["zip", "mov", "py", "sh", "pl", "ps", "rs", "md", "one", "so", "cc", "app"])
_CODE = re.compile(r"[a-z][A-Z]|\.[A-Z][a-z][a-z0-9-]*$")
# Global unicast; `dead::beef` or `cafe::1` in code is reserved space.
_UNICAST_V6 = ipaddress.ip_network("2000::/3")
_URL = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


@dataclass
class Document:
    """A report, flattened."""

    url: str = ""
    title: str = ""
    text: str = ""
    content_type: str = ""
    bytes: int = 0
    truncated: bool = False

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or "pasted"


@dataclass
class Extraction:
    """What a regular expression can find in a report without interpreting it."""

    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(getattr(self, f)) for f in self.__dataclass_fields__)

    def contains(self, value: str) -> bool:
        """Was this value actually in the report, or did a model invent it?"""
        needle = value.strip().lower()
        return any(
            needle in (v.lower() for v in getattr(self, f)) for f in self.__dataclass_fields__
        )


# -- fetching ---------------------------------------------------------------
def guard(url: str) -> None:
    """Only public http(s); never an internal address (SSRF)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"a report URL must be http or https, not '{parsed.scheme}'")
    host = parsed.hostname or ""
    from shoc.detect.osint import INTERNAL_SUFFIXES, is_public_address

    try:
        ipaddress.ip_address(host)
        public = is_public_address(host)
    except ValueError:  # a name, not an address
        public = not (host.endswith(INTERNAL_SUFFIXES) or "." not in host)
    if not public:
        raise ValidationError(f"refusing to fetch from an internal host ({host})")


def vet(url: str) -> str:
    """`guard`, then DNS: the address to connect to, when every one the host
    resolves to is public. A public name can point at 127.0.0.1 or 10.0.0.5."""
    from shoc.detect.osint import is_public_address

    guard(url)
    target = httpx.URL(url)
    host = target.raw_host.decode("ascii")
    port = target.port or (443 if target.scheme == "https" else 80)
    try:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot resolve {host}") from exc
    addresses = [str(info[4][0]) for info in resolved]
    if not addresses or not all(is_public_address(a) for a in addresses):
        raise ValidationError(f"refusing to fetch from an internal host ({host})")
    # IPv4 first: a host without an IPv6 route cannot fall back once pinned.
    return min(addresses, key=lambda a: ":" in a)


def vet_redirect(response: httpx.Response) -> None:
    """A client's response hook: where a redirect points is vetted as a URL
    handed in is, before httpx follows it (SEC-1)."""
    if response.has_redirect_location:
        vet(str(response.request.url.join(response.headers["location"])))


class Pinned(httpx.BaseTransport):
    """A client's transport that connects each request, a redirect's included, to
    the address `vet` checked, with the name kept for Host and TLS, as `get` does:
    a name vetted and then resolved again by httpx could rebind inside (SEC-1).
    httpx ignores HTTPS_PROXY/ALL_PROXY once a client has its own transport, so
    a URL the environment proxies (`proxied`) is vetted here and sent to that
    proxy by name, as `get` sends it. Each name gets its own pool: a connection
    whose certificate was checked for one name is never reused for another
    name on the same address."""

    def __init__(self, connect: Callable[[str], httpx.BaseTransport] | None = None) -> None:
        # `connect(proxy)` opens a pool, direct when proxy is "".
        self.connect = connect or (lambda proxy: httpx.HTTPTransport(proxy=proxy or None))
        self.pools: dict[tuple[str, str], httpx.BaseTransport] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        address = vet(url)
        proxy = proxied(url)
        key = (proxy, request.url.raw_host.decode())
        if key not in self.pools:
            self.pools[key] = self.connect(proxy)
        if proxy:
            return self.pools[key].handle_request(request)
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=address),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": request.url.raw_host.decode()},
        )
        return self.pools[key].handle_request(pinned)

    def close(self) -> None:
        for pool in self.pools.values():
            pool.close()


def proxied(url: str) -> str:
    """The proxy the environment sends this URL through (HTTPS_PROXY, ALL_PROXY), or ""."""
    target = httpx.URL(url)
    proxies = urllib.request.getproxies()
    proxy = proxies.get(target.scheme) or proxies.get("all") or ""
    return "" if proxy and urllib.request.proxy_bypass(target.host) else proxy


def get(url: str) -> httpx.Response:
    """GET a URL somebody handed in, or a source somebody configured (SEC-1, DET-7).

    Each hop is vetted and the connection pinned to the address vetted, with
    the name kept for Host and TLS, so neither a redirect nor a second DNS
    answer reaches an internal address. Behind a proxy from the environment the
    hop is still vetted, but sent by name: an HTTPS tunnel would check the
    certificate against the address, and the proxy resolves the name again,
    so a rebinding between the two lookups is not caught there. At most
    `REDIRECTS` hops, `MAX_BYTES` of body and `DEADLINE` seconds for the whole
    fetch, connect and headers included; what comes back holds the capped body.
    """
    deadline = time.monotonic() + DEADLINE
    for _ in range(REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValidationError(f"{httpx.URL(url).host} took more than {DEADLINE:.0f}s")
        address = vet(url)
        target = httpx.URL(url)
        pin = not proxied(url)
        headers = {"Host": target.netloc.decode("ascii")} if pin else {}
        extensions = {"sni_hostname": target.raw_host.decode("ascii")} if pin else {}
        timeout = httpx.Timeout(min(30.0, remaining), connect=min(10.0, remaining))
        body = bytearray()
        # A client per hop: a pooled connection to one name is never reused for
        # another. Without a proxy the environment is ignored, so none is used.
        with (
            httpx.Client(
                timeout=timeout, headers={"User-Agent": "shoc/report-reader"}, trust_env=not pin
            ) as http,
            http.stream(
                "GET",
                target.copy_with(host=address) if pin else target,
                headers=headers,
                extensions=extensions,
            ) as resp,
        ):
            if resp.has_redirect_location:
                url = urljoin(url, resp.headers["location"])
                continue
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) >= MAX_BYTES:
                    break
                if time.monotonic() > deadline:
                    raise ValidationError(f"{target.host} took more than {DEADLINE:.0f}s")
        out = httpx.Response(
            resp.status_code,
            headers={"content-type": resp.headers.get("content-type", "")},
            content=bytes(body[:MAX_BYTES]),
            request=httpx.Request("GET", url),
        )
        out.raise_for_status()
        return out
    raise ValidationError(f"more than {REDIRECTS} redirects from {url}")


def text_of(resp: httpx.Response) -> str:
    """A fetched page as text: HTML flattened, anything else as it came."""
    raw = resp.text
    html_page = "html" in resp.headers.get("content-type", "") or "<" in raw[:2000]
    return html_to_text(raw) if html_page else raw


def fetch(url: str) -> Document:
    """Fetch a report and flatten it to text."""
    resp = get(url)
    body = resp.content
    content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    doc = Document(url=url, content_type=content_type, bytes=len(body))
    if content_type == "application/pdf" or url.lower().endswith(".pdf"):
        doc.text = pdf_to_text(body)
        doc.title = url.rsplit("/", 1)[-1]
    else:
        doc.title = title_of(resp.text)
        doc.text = text_of(resp)
    doc.truncated = len(body) >= MAX_BYTES
    if len(doc.text) > MAX_TEXT:
        doc.text, doc.truncated = doc.text[:MAX_TEXT], True
    return doc


def from_text(text: str, title: str = "") -> Document:
    """A report pasted straight in."""
    body = html_to_text(text) if "<html" in text[:2000].lower() else text
    return Document(
        url="",
        title=title or "pasted report",
        text=body[:MAX_TEXT],
        content_type="text/plain",
        bytes=len(text),
        truncated=len(body) > MAX_TEXT,
    )


def pdf_to_text(data: bytes) -> str:
    """PDF lives behind the [pdf] extra so the core dependency budget is unchanged."""
    import io

    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ConfigError(
            "reading a PDF needs the optional extra: pip install 'shoc[pdf]'"
        ) from exc
    reader = PdfReader(io.BytesIO(data))
    return "\n\n".join((page.extract_text() or "") for page in reader.pages)


def title_of(raw: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
    return html.unescape(_SPACE.sub(" ", match.group(1)).strip())[:200] if match else ""


def html_to_text(raw: str) -> str:
    """Strip HTML by hand. A parser would be a dependency; this is enough for prose."""
    text = _SCRIPT.sub(" ", raw)
    text = _BLOCK.sub("\n", text)
    text = _TAG.sub(" ", text)
    text = html.unescape(text)
    text = _SPACE.sub(" ", text)
    return _BLANK.sub("\n\n", text).strip()


# What the model reads of a report, at most: about 12,000 tokens (RFC 0029).
PROSE_LIMIT = 48_000


def for_model(text: str, found: Extraction, limit: int = PROSE_LIMIT) -> tuple[str, bool]:
    """The report's prose for the model, and whether it was cut.

    A line that is mostly values the pattern extraction found (an IOC table, a
    hash list) is left out: those values reach the model once, in the list of
    values found, rather than twice.
    """
    values = sorted(
        {
            v.lower()
            for name in ("ips", "domains", "urls", "sha256", "sha1", "md5", "emails")
            for v in getattr(found, name)
        },
        key=len,
        reverse=True,
    )
    kept = []
    for line in text.splitlines():
        plain = refang(line).lower().strip()
        if plain:
            covered = 0
            for value in values:
                if value in plain:
                    covered += len(value) * plain.count(value)
                    plain = plain.replace(value, " ")
            if covered and covered * 2 >= len(refang(line).strip()):
                continue
        kept.append(line)
    prose = "\n".join(kept)
    return (prose[:limit], True) if len(prose) > limit else (prose, False)


# -- refanging --------------------------------------------------------------
_REFANG = (
    # The markers reports wrap around a dot or an at-sign, and the spaces they
    # tend to be padded with — "abuse (at) evil [dot] example" is one address.
    (re.compile(r"\s*(?:\[\.?\]|\(\.?\)|\{\.?\}|\[dot\]|\(dot\)|\{dot\})\s*", re.I), "."),
    (re.compile(r"\s+\.\s+"), "."),
    (re.compile(r"\s*(?:\[:\]|\(:\))\s*", re.I), ":"),
    (re.compile(r"\s*(?:\[@?\]|\(@?\)|\[at\]|\(at\)|\{at\})\s*", re.I), "@"),
    (re.compile(r"\bhxxp(s?)\b", re.I), r"http\1"),
    (re.compile(r"\bh\[tt\]p(s?)\b", re.I), r"http\1"),
    (re.compile(r"\bmeow(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[://\]", re.I), "://"),
)


def refang(text: str) -> str:
    """Undo the defanging reports apply so their indicators are not clickable."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


# -- sharing ----------------------------------------------------------------
# A Traffic Light Protocol marking: 2.0's colours and 1.0's WHITE.
_TLP = re.compile(r"\bTLP:\s*(RED|AMBER\+STRICT|AMBER|GREEN|CLEAR|WHITE)\b", re.I)
# Markings whose values are not sent to a third-party lookup (DET-6).
RESTRICTED_TLP = ("red", "amber+strict", "amber")


def tlp_of(text: str) -> str:
    """The first TLP marking in a text or a tag (`tlp:amber`), lower case, or ""."""
    found = _TLP.search(text)
    return found.group(1).lower() if found else ""


# -- extraction -------------------------------------------------------------
def _routable_v6(value: str) -> bool:
    """A victim's internal address is not an indicator; a documentation one is."""
    from shoc.detect.osint import is_public_address

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 6 and address in _UNICAST_V6 and is_public_address(value)


def _interesting(domain: str) -> bool:
    d = domain.lower().strip(".")
    return not any(d == n or d.endswith("." + n) for n in NOISE_DOMAINS)


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:  # an unbalanced IPv6 bracket
        return ""


def _on_tld(domain: str) -> bool:
    """Does it end in a real TLD? IANA's bootstrap only if this process has it:
    extraction never downloads. `intel.digest` and `intel.add` start that load
    first when the default feeds are on."""
    from shoc.detect.osint import loaded

    tld = domain.rsplit(".", 1)[-1].lower()
    boot = loaded("rdap_bootstrap")
    return tld in TLDS or (boot is not None and tld in boot["dns"])


def is_domain(name: str, alone: bool = False) -> bool:
    """A name `extract` keeps with no other context: on a real TLD and, unless it
    stands alone in its field, neither a file name (`stealer.py`) nor code."""
    if not _on_tld(name):
        return False
    return alone or (name.rsplit(".", 1)[-1].lower() not in FILE_TLDS and not _CODE.search(name))


def extract(text: str, limit: int = 300, standalone: bool = False) -> Extraction:
    """Pull indicators out of report text. Deterministic, and never authoritative.

    `standalone` leaves out an address or a domain that only appears as the host
    of a URL or an email: a bad URL does not make its host bad.
    """
    from shoc.detect.osint import is_public_address

    body = refang(text)
    hosts = _EMAIL.sub(" ", _URL.sub(" ", body)) if standalone else body
    refanged = body.lower()
    hung = {_host(u) for u in _URL.findall(body)} | {
        e.rsplit("@", 1)[-1].lower() for e in _EMAIL.findall(body)
    }

    # Worked out once, not per name: a list feed can hold thousands of them.
    lines = {line.strip() for line in refanged.splitlines()}
    # A name written more often once refanged was defanged at least once.
    before = Counter(d.lower() for d in _DOMAIN.findall(text))
    after = Counter(d.lower() for d in _DOMAIN.findall(body))
    defanged = {d for d, n in after.items() if n > before[d]}
    # A name every mention of which is written like code.
    written: dict[str, bool] = {}
    for d in _DOMAIN.findall(hosts):
        written[d.lower()] = written.get(d.lower(), True) and bool(_CODE.search(d))

    def named(domain: str) -> bool:
        if not (_interesting(domain) and _on_tld(domain)):
            return False
        return (
            (domain.rsplit(".", 1)[-1] not in FILE_TLDS and not written.get(domain))
            or domain in defanged
            or domain in hung
            or domain in lines
        )

    def uniq(
        pattern: re.Pattern[str], keep=lambda v: True, lower: bool = True, source: str = body
    ) -> list[str]:
        seen: dict[str, None] = {}
        for match in pattern.findall(source):
            value = (match.lower() if lower else match).strip(".,;:")
            if value and keep(value) and value not in seen:
                seen[value] = None
            if len(seen) >= limit:
                break
        return list(seen)

    hashes32 = uniq(_MD5)
    hashes40 = uniq(_SHA1)
    hashes64 = uniq(_SHA256)
    # An IPv6 address is kept the way `ipaddress` writes it, as events store it.
    # A trailing colon is punctuation only when the address does not end in `::`.
    ipv6: dict[str, None] = {}
    for match in _IPV6.findall(hosts):
        value = next((v for v in (match, match.rstrip(":")) if _routable_v6(v)), "")
        if value and len(ipv6) < limit:
            ipv6[str(ipaddress.ip_address(value))] = None
    return Extraction(
        ips=list(dict.fromkeys(uniq(_IPV4, is_public_address, source=hosts) + list(ipv6))),
        domains=uniq(_DOMAIN, named, source=hosts),
        urls=uniq(_URL, lambda v: _interesting(_host(v)), lower=False),
        # A 64-character hash contains a 40- and a 32-character run; drop those.
        sha256=hashes64,
        sha1=[h for h in hashes40 if not any(h in s for s in hashes64)],
        md5=[h for h in hashes32 if not any(h in s for s in hashes64 + hashes40)],
        cves=[c.upper() for c in uniq(_CVE)],
        techniques=sorted({t.upper() for t in _ATTACK.findall(body)})[:limit],
        emails=uniq(_EMAIL, lambda v: _interesting(v.split("@")[-1])),
    )
