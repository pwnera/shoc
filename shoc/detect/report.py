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
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from shoc.errors import ConfigError, ValidationError

TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT = 200_000

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

# Indicators, after refanging.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|shop|club|live|icu|cc|tk|"
    r"co|uk|de|fr|nl|br|in|jp|us|eu|dev|app|cloud|pw|su|ml|ga|cf|gq|link|zip|mov)\b",
    re.I,
)
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


def get(url: str) -> httpx.Response:
    guard(url)
    with httpx.Client(
        timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": "shoc/report-reader"}
    ) as http:
        resp = http.get(url)
        resp.raise_for_status()
        return resp


def fetch(url: str) -> Document:
    """Fetch a report and flatten it to text."""
    resp = get(url)
    body = resp.content[:MAX_BYTES]
    content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    doc = Document(url=url, content_type=content_type, bytes=len(body))
    if content_type == "application/pdf" or url.lower().endswith(".pdf"):
        doc.text = pdf_to_text(body)
        doc.title = url.rsplit("/", 1)[-1]
    else:
        raw = body.decode(resp.encoding or "utf-8", errors="replace")
        doc.title = title_of(raw)
        doc.text = html_to_text(raw) if "<" in raw[:2000] else raw
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


# -- extraction -------------------------------------------------------------
def _routable(value: str) -> bool:
    """A victim's internal address is not an indicator; a documentation one is."""
    from shoc.detect.osint import is_public_address

    return is_public_address(value)


def _interesting(domain: str) -> bool:
    d = domain.lower().strip(".")
    return not any(d == n or d.endswith("." + n) for n in NOISE_DOMAINS)


def extract(text: str, limit: int = 300, standalone: bool = False) -> Extraction:
    """Pull indicators out of report text. Deterministic, and never authoritative.

    `standalone` leaves out an address or a domain that only appears as the host
    of a URL or an email: a bad URL does not make its host bad.
    """
    body = refang(text)
    hosts = _EMAIL.sub(" ", _URL.sub(" ", body)) if standalone else body

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
    return Extraction(
        ips=uniq(_IPV4, _routable, source=hosts),
        domains=uniq(_DOMAIN, _interesting, source=hosts),
        urls=uniq(_URL, lambda v: _interesting(urlparse(v).hostname or ""), lower=False),
        # A 64-character hash contains a 40- and a 32-character run; drop those.
        sha256=hashes64,
        sha1=[h for h in hashes40 if not any(h in s for s in hashes64)],
        md5=[h for h in hashes32 if not any(h in s for s in hashes64 + hashes40)],
        cves=[c.upper() for c in uniq(_CVE)],
        techniques=sorted({t.upper() for t in _ATTACK.findall(body)})[:limit],
        emails=uniq(_EMAIL, lambda v: _interesting(v.split("@")[-1])),
    )
