"""Reading a threat report: flattening, refanging and extraction (DET-7, RFC 0004)."""

from __future__ import annotations

import socket

import httpx
import pytest

from shoc.detect import report
from shoc.errors import ValidationError

SAMPLE = """
<html><head><title>Operation Example: cloud key theft</title></head>
<body>
<script>var tracking = "8.8.8.8";</script>
<p>The actor staged payloads on hxxps://cdn.malicious-example[.]top/p.bin and
called back to 203[.]0[.]113[.]4 and 198[.]51[.]100[.]77.</p>
<p>They exploited CVE-2026-1234 and used T1078.004 and T1098 for persistence.
Contact: abuse (at) malicious-example[.]top</p>
<p>Sample: 3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed
(also indexed on virustotal.com and github.com).</p>
<p>Victim infrastructure at 10.0.0.5 was not attacker-controlled.</p>
</body></html>
"""


@pytest.fixture(scope="module")
def found():
    return report.extract(report.html_to_text(SAMPLE))


def test_the_title_and_the_prose_survive_flattening():
    assert report.title_of(SAMPLE) == "Operation Example: cloud key theft"
    text = report.html_to_text(SAMPLE)
    assert "staged payloads" in text
    assert "<p>" not in text and "var tracking" not in text, "script content is not prose"


def test_defanged_indicators_are_refanged():
    assert report.refang("hxxps://evil[.]example") == "https://evil.example"
    assert report.refang("203[.]0[.]113[.]4") == "203.0.113.4"
    assert report.refang("abuse (at) evil[.]example") == "abuse@evil.example"


def test_the_indicators_the_report_publishes_are_found(found):
    assert "203.0.113.4" in found.ips and "198.51.100.77" in found.ips
    assert "malicious-example.top" in found.domains
    assert "CVE-2026-1234" in found.cves
    assert {"T1078.004", "T1098"} <= set(found.techniques)
    assert found.sha256 == ["3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed"]
    assert "abuse@malicious-example.top" in found.emails


def test_the_reports_own_infrastructure_is_not_an_indicator(found):
    assert "virustotal.com" not in found.domains
    assert "github.com" not in found.domains


def test_a_private_address_in_a_report_is_not_an_indicator(found):
    assert "10.0.0.5" not in found.ips, "a victim's internal address is not an IOC"


def test_a_shorter_hash_inside_a_longer_one_is_not_reported_twice(found):
    assert not found.sha1 and not found.md5


def test_contains_is_how_an_invented_indicator_is_caught(found):
    assert found.contains("203.0.113.4")
    assert found.contains("CVE-2026-1234")
    assert not found.contains("8.8.8.8"), "a value only the model produced must not verify"


def test_a_report_url_may_not_point_inside_the_network():
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/report",
        "http://intranet/advisory",
    ):
        with pytest.raises(ValidationError, match="refusing to fetch"):
            report.fetch(url)


def test_a_report_url_must_be_http():
    with pytest.raises(ValidationError, match="must be http"):
        report.fetch("file:///etc/passwd")


def test_pasted_text_needs_no_network():
    doc = report.from_text("Callback to 203.0.113.4", title="pasted advisory")
    assert doc.host == "pasted" and "203.0.113.4" in doc.text
    assert report.extract(doc.text).ips == ["203.0.113.4"]


# -- what the model reads (RFC 0029) ----------------------------------------
def test_page_furniture_is_not_read():
    page = (
        "<html><body><nav>Products Pricing Login</nav><header>Subscribe</header>"
        "<article><p>The actor phished admins.</p></article>"
        "<aside>Related posts</aside><footer>Copyright</footer></body></html>"
    )
    text = report.html_to_text(page)
    assert "phished admins" in text
    assert not any(w in text for w in ("Pricing", "Subscribe", "Related", "Copyright"))


def test_ioc_tables_reach_the_model_once_in_the_values_list():
    prose = (
        "The loader beacons to its C2 every hour.\n"
        "203.0.113[.]4 | C2 | 2026-09-01\n"
        "3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed loader.exe\n"
        "Block 203.0.113.4 at the edge if you see it.\n"
    )
    found = report.extract(prose)
    text, cut = report.for_model(prose, found)
    assert "beacons to its C2" in text and "Block 203.0.113.4 at the edge" in text
    assert "3f786850" not in text, "a hash line is the values list's job"
    assert not cut
    long_text, long_cut = report.for_model("word " * 20_000, report.extract(""), limit=1_000)
    assert long_cut and len(long_text) == 1_000


# -- which names are domains (DET-7, DET-4) ------------------------------------
NEW_TLDS = """The kit is served from login-verify[.]lol and portal.example-pay.sbs.
Its second stage calls 2001:db8::55 over IPv6, logged as [2001:db8:0:0::56].
Victims open invoice.zip and run stealer.py; neither is a domain.
The operators also registered dropbox.com.verify-account.lol and invoice[.]zip.
Build 12:30:45 on fe80::1, not an indicator.
The loader calls objShell.Run and ADODB.Stream, loads libcrypto.so and main.cc.
"""


def test_any_real_tld_and_an_ipv6_address_are_indicators(monkeypatch):
    from shoc.detect import osint

    monkeypatch.setattr(osint, "_LISTS", {})
    found = report.extract(NEW_TLDS)
    assert {"login-verify.lol", "portal.example-pay.sbs"} <= set(found.domains)
    assert "2001:db8::55" in found.ips and "2001:db8::56" in found.ips, "written as events are"
    assert "fe80::1" not in found.ips, "a link-local address is the victim's"
    assert "dropbox.com.verify-account.lol" in found.domains
    assert "dropbox.com" not in found.domains, "a look-alike is not the brand it imitates"
    assert found.contains("login-verify.lol") and found.contains("2001:db8::55")


def test_a_file_name_is_not_a_domain_unless_the_report_defangs_it(monkeypatch):
    from shoc.detect import osint

    monkeypatch.setattr(osint, "_LISTS", {})
    found = report.extract(NEW_TLDS)
    assert "stealer.py" not in found.domains
    # invoice.zip is named as a file and, defanged, as a domain: the domain stands.
    assert "invoice.zip" in found.domains
    prose = report.extract("Victims open invoice.zip and run loader.exe.")
    assert prose.domains == []
    listed = report.extract("evil-cdn.zip\n203.0.113.80\n")
    assert listed.domains == ["evil-cdn.zip"], "a list names one value per line"


def test_code_a_library_or_reserved_v6_is_not_an_indicator(monkeypatch):
    from shoc.detect import osint

    monkeypatch.setattr(osint, "_LISTS", {})
    found = report.extract(NEW_TLDS)
    for name in ("objshell.run", "adodb.stream", "libcrypto.so", "main.cc"):
        assert name not in found.domains, name
    assert report.extract("C2 at evil-panel[.]cc and evil-ops.run").domains == [
        "evil-panel.cc",
        "evil-ops.run",
    ]
    code = report.extract("if (x == dead::beef) return cafe::1; next hop 2001:db8:1:: and on")
    assert code.ips == ["2001:db8:1::"], "only global unicast, and a trailing :: is the address"


def test_a_tld_only_iana_knows_counts_once_its_bootstrap_is_loaded(monkeypatch):
    from shoc.detect import osint

    monkeypatch.setattr(osint, "_LISTS", {})
    assert report.extract("C2 at evil.newgtld").domains == []
    boot = {"dns": {"newgtld": "https://rdap.example.test/"}, "ip": osint.Ranges(), "size": 1}
    osint._LISTS["rdap_bootstrap"] = (osint.datetime.now(osint.UTC), boot)
    assert report.extract("C2 at evil.newgtld").domains == ["evil.newgtld"]


def test_a_list_page_keeps_new_tlds_and_ipv6_and_skips_file_names(monkeypatch):
    from shoc.detect import intel, osint

    monkeypatch.setattr(osint, "_LISTS", {})
    got = {(i.type, i.value) for i in intel.indicators_in(NEW_TLDS, "list:test", 0.6)}
    assert ("domain", "login-verify.lol") in got and ("ip", "2001:db8::55") in got
    assert ("domain", "stealer.py") not in got
    assert ("domain", "dropbox.com") not in got


# -- fetching a URL somebody handed in (SEC-1) --------------------------------
def _resolves(monkeypatch, names: dict[str, str]) -> None:
    def getaddrinfo(host, port, *args, **kwargs):
        if host not in names:
            raise socket.gaierror(f"no such name: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (names[host], port))]

    monkeypatch.setattr(report.socket, "getaddrinfo", getaddrinfo)


def _serves(monkeypatch, handler) -> list[httpx.Request]:
    seen: list[httpx.Request] = []
    real = httpx.Client

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(record)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(**{**kw, "transport": transport}))
    return seen


def test_a_fetch_connects_to_the_address_it_checked(monkeypatch):
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})
    seen = _serves(monkeypatch, lambda r: httpx.Response(200, text="Callback to 198.51.100.7"))
    assert "198.51.100.7" in report.fetch("https://blog.example.test/post").text
    [request] = seen
    assert request.url.host == "203.0.113.5", "no second DNS answer is asked for"
    assert request.headers["host"] == "blog.example.test"
    assert request.extensions["sni_hostname"] == "blog.example.test"


def test_a_redirect_to_the_metadata_service_is_refused(monkeypatch):
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})
    metadata = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    seen = _serves(monkeypatch, lambda r: httpx.Response(302, headers={"location": metadata}))
    with pytest.raises(ValidationError, match="refusing to fetch"):
        report.fetch("https://blog.example.test/r")
    assert [r.url.host for r in seen] == ["203.0.113.5"], "the redirect is never followed"


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5"])
def test_a_public_name_that_resolves_inside_is_refused(monkeypatch, address):
    _resolves(monkeypatch, {"rebind.example.test": address})
    seen = _serves(monkeypatch, lambda r: httpx.Response(200, text="internal admin page"))
    with pytest.raises(ValidationError, match="refusing to fetch"):
        report.get("https://rebind.example.test/")
    assert seen == []


def test_redirects_are_followed_by_hand_and_counted(monkeypatch):
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})

    def hop(request: httpx.Request) -> httpx.Response:
        at = int(request.url.path.strip("/"))
        if at < 3:
            return httpx.Response(302, headers={"location": f"/{at + 1}"})
        return httpx.Response(200, text="the post")

    _serves(monkeypatch, hop)
    assert report.get("https://blog.example.test/0").text == "the post"
    with pytest.raises(ValidationError, match=f"more than {report.REDIRECTS} redirects"):
        report.get("https://blog.example.test/-1")


def test_a_keyless_sources_redirect_connects_to_the_address_it_vetted(monkeypatch):
    """rdap.org sends a lookup on to a registry; httpx resolving that name again
    could reach an internal address the vetted one never was (SEC-1)."""
    from shoc.detect import osint

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers["host"] == "rdap.example.test":
            return httpx.Response(302, headers={"location": "https://registry.example.test/x"})
        return httpx.Response(200, json={"ok": True})

    names = {"rdap.example.test": "203.0.113.5", "registry.example.test": "198.51.100.9"}
    _resolves(monkeypatch, names)
    opened: list[str] = []
    mock = httpx.MockTransport(handler)
    pinned = report.Pinned(lambda proxy: opened.append(proxy) or mock)
    with httpx.Client(transport=pinned, follow_redirects=True) as http:
        resp = http.get("https://rdap.example.test/domain/x")
    assert resp.json() == {"ok": True} and resp.request.url.host == "registry.example.test"
    assert [r.url.host for r in seen] == ["203.0.113.5", "198.51.100.9"]
    assert opened == ["", ""], "each name has its own pool, so no TLS session crosses names"
    assert seen[1].headers["host"] == "registry.example.test"
    assert seen[1].extensions["sni_hostname"] == "registry.example.test"

    seen.clear()
    _resolves(monkeypatch, {**names, "registry.example.test": "10.0.0.5"})
    with (
        httpx.Client(transport=pinned, follow_redirects=True) as http,
        pytest.raises(ValidationError, match="internal host"),
    ):
        http.get("https://rdap.example.test/domain/x")
    assert [r.url.host for r in seen] == ["203.0.113.5"], "the rebound name is never connected to"
    with osint._client() as http:
        assert isinstance(http._transport, report.Pinned)
    with osint._client(redirects=False) as http:
        assert not isinstance(http._transport, report.Pinned), "a keyed source follows none"


def test_a_body_is_read_no_further_than_the_cap_or_the_deadline(monkeypatch):
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})
    _serves(monkeypatch, lambda r: httpx.Response(200, content=b"a" * 5000))
    monkeypatch.setattr(report, "MAX_BYTES", 1000)
    assert len(report.get("https://blog.example.test/big").content) == 1000
    assert report.fetch("https://blog.example.test/big").truncated
    monkeypatch.setattr(report, "MAX_BYTES", 10_000)
    monkeypatch.setattr(report, "DEADLINE", -1.0)
    with pytest.raises(ValidationError, match="took more than"):
        report.get("https://blog.example.test/slow")


def _behind_proxy(monkeypatch, no_proxy: str = "") -> list[dict]:
    """HTTPS_PROXY set; each client's arguments are recorded and its requests
    answered here, so nothing reaches a real proxy."""
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    if no_proxy:
        monkeypatch.setenv("NO_PROXY", no_proxy)
    clients: list[dict] = []
    real = httpx.Client
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text=f"from {r.url.host}"))

    def record(**kw):
        clients.append(kw)
        return real(**{**kw, "transport": transport, "trust_env": False})

    monkeypatch.setattr(httpx, "Client", record)
    return clients


def test_behind_a_proxy_the_name_is_vetted_and_sent_to_the_proxy(monkeypatch):
    """An HTTPS tunnel checks the certificate against the host it was given,
    so a pinned address would fail TLS there: the proxy gets the name."""
    clients = _behind_proxy(monkeypatch)
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})
    assert report.get("https://blog.example.test/post").text == "from blog.example.test"
    assert clients[0]["trust_env"] is True
    _resolves(monkeypatch, {"blog.example.test": "127.0.0.1"})
    with pytest.raises(ValidationError, match="refusing to fetch"):
        report.get("https://blog.example.test/post")
    assert len(clients) == 1, "a name that resolves inside is refused before any request"


def test_a_host_the_proxy_is_bypassed_for_is_pinned(monkeypatch):
    clients = _behind_proxy(monkeypatch, no_proxy="blog.example.test")
    _resolves(monkeypatch, {"blog.example.test": "203.0.113.5"})
    assert report.get("https://blog.example.test/post").text == "from 203.0.113.5"
    assert clients[0]["trust_env"] is False, "so httpx cannot route it to a proxy anyway"


def test_a_keyless_source_behind_a_proxy_reaches_it_by_name(monkeypatch):
    """httpx ignores HTTPS_PROXY once a client has a transport of its own, so
    Pinned sends a proxied request to the proxy itself, vetted first."""
    from shoc.detect import osint

    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    opened: list[str | None] = []
    seen: list[httpx.Request] = []

    def transport(proxy=None, **kwargs):
        opened.append(proxy)
        return httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200, text="ok"))

    monkeypatch.setattr(httpx, "HTTPTransport", transport)
    _resolves(monkeypatch, {"rdap.example.test": "203.0.113.5"})
    with osint._client() as http:
        assert http.get("https://rdap.example.test/domain/x").text == "ok"
    assert opened == ["http://proxy.example.test:3128"]
    assert [r.url.host for r in seen] == ["rdap.example.test"], "the proxy gets the name"
    _resolves(monkeypatch, {"rdap.example.test": "127.0.0.1"})
    with osint._client() as http, pytest.raises(ValidationError, match="internal host"):
        http.get("https://rdap.example.test/domain/x")
    assert len(seen) == 1, "a name that resolves inside is refused behind the proxy too"


def test_a_tlp_marking_is_read_from_text_or_a_tag():
    assert report.tlp_of("Distribution: TLP:AMBER+STRICT. Do not forward.") == "amber+strict"
    assert report.tlp_of("tlp:red") == "red" and report.tlp_of("TLP: GREEN") == "green"
    assert report.tlp_of("no marking") == ""
