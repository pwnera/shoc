"""Feed parsers (DET-4). Each one is pinned against a recorded response shape."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from shoc.detect import intel
from shoc.errors import ConfigError

_DAY = timedelta(days=1)
_RECENT = (datetime.now(UTC) - 5 * _DAY).strftime("%Y-%m-%d")
_OLD = (datetime.now(UTC) - 60 * _DAY).strftime("%Y-%m-%d")
# The file's own shape: a commented banner, then a quoted header line (DET-4).
FEODO_CSV = f"""################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2026-09-01 10:00:00","203.0.113.10","443","online","{_RECENT}","Dridex"
"2026-09-02 11:00:00","198.51.100.22","8080","offline","{_RECENT}","QakBot"
"2026-03-04 14:28:39","198.51.100.23","443","offline","{_OLD}","QakBot"
"""

URLHAUS = """# urlhaus
http://203.0.113.55/payload.exe
https://bad.example.test/loader.bin
"""


def transport(handler):
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def mock_http(monkeypatch):
    def install(body, content_type="text/plain"):
        def handler(request: httpx.Request) -> httpx.Response:
            if isinstance(body, (dict, list)):
                return httpx.Response(200, json=body)
            return httpx.Response(200, text=body, headers={"content-type": content_type})

        monkeypatch.setattr(
            intel, "_client", lambda headers=None, **_: httpx.Client(transport=transport(handler))
        )

    return install


def test_feodo_becomes_high_confidence_c2_addresses(mock_http):
    mock_http(FEODO_CSV)
    indicators = intel.feodo({}, {})
    assert [i.value for i in indicators] == ["203.0.113.10", "198.51.100.22"], (
        "the header is not an address, and a C2 last online two months ago is not kept"
    )
    assert all(i.type == "ip" and i.severity == "high" for i in indicators)
    assert "dridex" in indicators[0].tags and indicators[1].description.startswith("QakBot")
    offline = indicators[1].expires_at
    assert offline is not None and offline < datetime.now(UTC) + 26 * _DAY, (
        "an offline C2 expires 30 days after it was last seen online"
    )


def test_urlhaus_stores_each_url_as_a_url_never_its_host(mock_http):
    mock_http(URLHAUS)
    indicators = intel.urlhaus({}, {})
    assert {(i.type, i.value) for i in indicators} == {
        ("url", "http://203.0.113.55/payload.exe"),
        ("url", "https://bad.example.test/loader.bin"),
    }


def test_otx_and_misp_need_their_keys():
    with pytest.raises(ConfigError, match="api_key"):
        intel.otx({}, {})
    with pytest.raises(ConfigError, match="api_key"):
        intel.misp({"url": "https://misp.example"}, {})


def test_otx_maps_indicator_types(mock_http):
    mock_http(
        {
            "results": [
                {
                    "name": "Campaign X",
                    "tags": ["apt"],
                    "indicators": [
                        {"type": "IPv4", "indicator": "203.0.113.5"},
                        {"type": "domain", "indicator": "evil.example"},
                        {"type": "FileHash-MD5", "indicator": "ignored"},
                    ],
                }
            ]
        }
    )
    indicators = intel.otx({}, {"api_key": "k"})
    assert {(i.type, i.value) for i in indicators} == {
        ("ip", "203.0.113.5"),
        ("domain", "evil.example"),
    }


def test_the_default_feeds_need_no_account():
    assert set(intel.DEFAULT_FEEDS) == {"abuse_ch_feodo", "abuse_ch_urlhaus"}
    for name in intel.DEFAULT_FEEDS:
        assert name in intel.FEEDS and name in intel.FEED_HOSTS


def test_no_feed_reaches_cisa():
    """Removed deliberately: shoc carries no CISA feed."""
    assert "cisa_kev" not in intel.FEEDS
    assert not any("cisa" in host for host in intel.FEED_HOSTS.values())


def test_feeds_can_be_turned_off_entirely():
    assert intel.default_feeds("off") == ()
    assert intel.default_feeds("default") == intel.DEFAULT_FEEDS
    assert intel.default_feeds("abuse_ch_feodo,nonsense") == ("abuse_ch_feodo",)


# -- indicator lists and report sources (RFC 0016) --------------------------
IOC_PAGE = """Indicators seen in the campaign:
hxxp://files.example.com/drop/stage2.bin
c2.example.com
203.0.113.80
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor blog</title>
<item><title>Campaign A</title><link>https://blog.example.test/a</link></item>
<item><title>Campaign B</title><link>https://blog.example.test/b</link></item>
</channel></rss>"""

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>CERT</title>
<entry><title>Advisory 1</title>
  <link rel="self" href="https://cert.example.test/feed/1"/>
  <link rel="alternate" href="https://cert.example.test/advisory/1"/>
</entry>
</feed>"""


def _page(monkeypatch, body):
    from shoc.detect import report

    monkeypatch.setattr(
        report,
        "get",
        lambda url: httpx.Response(200, text=body, request=httpx.Request("GET", url)),
    )


def test_a_list_keeps_each_indicator_under_its_own_type(monkeypatch):
    _page(monkeypatch, IOC_PAGE)
    got = {(i.type, i.value) for i in intel.listing({"url": "https://iocs.example.test/"}, {})}
    assert ("url", "http://files.example.com/drop/stage2.bin") in got
    assert ("domain", "c2.example.com") in got and ("ip", "203.0.113.80") in got
    assert ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in got
    # The URL's host was not named on its own, so it is not a bad domain.
    assert ("domain", "files.example.com") not in got


def test_a_list_needs_a_url():
    with pytest.raises(ConfigError, match="url"):
        intel.listing({}, {})


def test_rss_and_atom_entries_become_report_links(monkeypatch):
    _page(monkeypatch, RSS)
    items = intel.rss({"url": "https://blog.example.test/feed"}, {})
    assert [(i.url, i.title) for i in items] == [
        ("https://blog.example.test/a", "Campaign A"),
        ("https://blog.example.test/b", "Campaign B"),
    ]
    _page(monkeypatch, ATOM)
    items = intel.rss({"url": "https://cert.example.test/feed"}, {})
    assert [i.url for i in items] == ["https://cert.example.test/advisory/1"]


def test_otx_pulses_carry_their_own_text(mock_http):
    mock_http(
        {
            "results": [
                {
                    "id": "abc",
                    "name": "Campaign X",
                    "description": "Phishing wave",
                    "references": ["https://blog.example.test/x"],
                    "indicators": [{"type": "domain", "indicator": "evil.example"}],
                }
            ]
        }
    )
    [item] = intel.otx_pulses({}, {"api_key": "k"})
    assert item.url == "https://otx.alienvault.com/pulse/abc"
    assert "Phishing wave" in item.text and "evil.example" in item.text


def test_a_list_is_never_a_default_feed():
    assert intel.default_feeds("list,abuse_ch_feodo") == ("abuse_ch_feodo",)


def test_misp_events_become_reports_with_their_attributes(mock_http):
    mock_http(
        {
            "response": [
                {
                    "Event": {
                        "id": "42",
                        "info": "Phishing kit targeting SaaS admins",
                        "Attribute": [
                            {
                                "type": "domain",
                                "value": "login-portal.example",
                                "comment": "kit host",
                            },
                            {"type": "ip-dst", "value": "203.0.113.90"},
                        ],
                    }
                }
            ]
        }
    )
    [item] = intel.misp_events({"url": "https://misp.example.test/"}, {"api_key": "k"})
    assert item.url == "https://misp.example.test/events/view/42"
    assert item.title == "Phishing kit targeting SaaS admins"
    assert "domain login-portal.example kit host" in item.text
    assert "ip-dst 203.0.113.90" in item.text


def test_misp_events_need_a_url_and_a_key():
    with pytest.raises(ConfigError, match="api_key"):
        intel.misp_events({"url": "https://misp.example.test"}, {})


# -- what a feed says about an item, for scoring (RFC 0029) -----------------
RICH_RSS = """<?xml version="1.0"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
<item><title>AiTM kit targets Microsoft 365</title>
  <link>https://blog.example.test/aitm?utm_source=rss&amp;id=7#top</link>
  <description>&lt;p&gt;A phishing kit steals &lt;b&gt;session tokens&lt;/b&gt;.&lt;/p&gt;</description>
  <pubDate>Mon, 05 Oct 2026 08:00:00 +0000</pubDate>
  <category>Phishing</category><category>AiTM</category>
  <content:encoded><![CDATA[<p>FULLTEXT</p>]]></content:encoded>
</item></channel></rss>"""


def test_rss_keeps_the_summary_date_and_categories(monkeypatch):
    _page(monkeypatch, RICH_RSS)
    [item] = intel.rss({"url": "https://blog.example.test/feed"}, {})
    assert item.summary == "A phishing kit steals session tokens ."
    assert item.published is not None and item.published.isoformat().startswith("2026-10-05T08")
    assert item.categories == ["Phishing", "AiTM"]
    assert item.text == "", "a short content block is a teaser; the page is fetched"

    _page(monkeypatch, RICH_RSS.replace("FULLTEXT", "word " * 2000))
    [whole] = intel.rss({"url": "https://blog.example.test/feed"}, {})
    assert len(whole.text) > intel.FULL_TEXT, "the whole post comes from the feed"


def test_a_report_url_loses_its_tracking_parameters():
    assert (
        intel.canonical("HTTPS://Blog.Example.test/aitm?utm_source=rss&id=7&fbclid=x#top")
        == "https://blog.example.test/aitm?id=7"
    )


def test_otx_pulses_bring_their_structured_fields(mock_http):
    mock_http(
        {
            "results": [
                {
                    "id": "p1",
                    "name": "Okta session theft",
                    "description": "Stolen session cookies",
                    "tags": ["okta"],
                    "industries": ["Technology"],
                    "malware_families": [{"display_name": "Lumma"}],
                    "attack_ids": [{"id": "T1539"}],
                    "modified": "2026-10-04T10:00:00",
                    "indicators": [],
                }
            ]
        }
    )
    [item] = intel.otx_pulses({}, {"api_key": "k"})
    assert {"okta", "Technology", "Lumma", "T1539"} <= set(item.categories)
    assert item.summary == "Stolen session cookies" and item.published is not None


URLHAUS_CSV = """# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-05 10:00:00","http://203.0.113.55:4444/bin.sh","online","","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/1/","r"
"2","2026-10-05 10:01:00","https://bad.example.test/invoice.exe","online","","malware_download","exe,RemcosRAT","https://urlhaus.abuse.ch/url/2/","r"
"""


def test_urlhaus_leaves_out_payloads_for_embedded_devices(mock_http):
    mock_http(URLHAUS_CSV)
    [kept] = intel.urlhaus({}, {})
    assert kept.value == "https://bad.example.test/invoice.exe" and "remcosrat" in kept.tags


def test_the_abuse_ch_key_rides_along_when_there_is_one(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=FEODO_CSV)

    monkeypatch.setattr(
        intel,
        "_client",
        lambda headers=None: httpx.Client(transport=transport(handler), headers=headers or {}),
    )
    intel.feodo({}, {"auth_key": "k1"})
    intel.feodo({}, {})
    assert seen[0].headers.get("Auth-Key") == "k1" and "Auth-Key" not in seen[1].headers


def test_every_preset_is_an_https_rss_feed_with_a_grade():
    assert intel.PRESETS, "shoc names some free report sources"
    for name, preset in intel.PRESETS.items():
        assert preset.url.startswith("https://") and preset.parser == "rss", name
        assert preset.grade in (1, 2), name
        assert "cisa" not in preset.url, "shoc carries no CISA feed (D57)"


# -- what a feed hands over: every page, only live values (DET-4) -----------
def _routed(monkeypatch, handler):
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(
        intel,
        "_client",
        lambda headers=None, follow_redirects=True: httpx.Client(
            transport=transport(record), follow_redirects=follow_redirects
        ),
    )
    return seen


def _pulse(value: str, **item) -> dict:
    return {"name": "Pulse", "indicators": [{"type": "IPv4", "indicator": value, **item}]}


def test_otx_reads_every_page_on_its_own_host(monkeypatch):
    base = "https://otx.alienvault.com/api/v1"
    pages = {
        "1": {"results": [_pulse("203.0.113.1")], "next": f"{base}/pulses/subscribed?page=2"},
        "2": {"results": [_pulse("203.0.113.2")], "next": None},
    }
    _routed(monkeypatch, lambda r: httpx.Response(200, json=pages[r.url.params.get("page", "1")]))
    out = intel.otx({}, {"api_key": "k"})
    assert [i.value for i in out] == ["203.0.113.1", "203.0.113.2"]
    assert not getattr(out, "short", "")

    pages["1"]["next"] = "https://elsewhere.example.test/pulses/subscribed?page=2"
    seen = _routed(monkeypatch, lambda r: httpx.Response(200, json=pages["1"]))
    out = intel.otx({}, {"api_key": "k"})
    assert len(seen) == 1, "the API key never goes to another host"
    assert getattr(out, "short", "").startswith("truncated")

    pages["1"]["next"] = f"{base}/pulses/subscribed?page=2"
    seen = _routed(monkeypatch, lambda r: httpx.Response(200, json=pages["1"]))
    out = intel.otx({"pages": 3}, {"api_key": "k"})
    assert len(seen) == 3 and "3 pages" in getattr(out, "short", "")
    reports = intel.otx_pulses({"pages": 3}, {"api_key": "k"})
    assert "3 pages" in getattr(reports, "short", ""), "the report pull says so too"

    pages["1"]["next"] = "http://otx.alienvault.com/api/v1/pulses/subscribed?page=2"
    seen = _routed(
        monkeypatch, lambda r: httpx.Response(200, json=pages[r.url.params.get("page", "1")])
    )
    out = intel.otx({}, {"api_key": "k"})
    assert [r.url.scheme for r in seen] == ["https", "https"], "never over http"
    assert len(out) == 2 and not getattr(out, "short", "")


def test_a_feed_redirect_is_an_error_and_the_key_stays_home(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "elsewhere.example.test":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(302, headers={"location": "https://elsewhere.example.test/x"})

    seen = _routed(monkeypatch, handler)
    with pytest.raises(httpx.HTTPStatusError):
        intel.otx({}, {"api_key": "k"})
    with pytest.raises(httpx.HTTPStatusError):
        intel.misp({"url": "https://misp.example.test"}, {"api_key": "k"})
    assert all(r.url.host != "elsewhere.example.test" for r in seen)


def test_otx_leaves_out_retired_indicators(monkeypatch):
    later = (datetime.now(UTC) + 10 * _DAY).replace(microsecond=0)
    pulse = {
        "name": "Pulse",
        "indicators": [
            {"type": "IPv4", "indicator": "203.0.113.1", "is_active": 0},
            {"type": "IPv4", "indicator": "203.0.113.2", "expiration": _OLD},
            {"type": "IPv4", "indicator": "203.0.113.3", "expiration": later.isoformat()},
        ],
    }
    _routed(monkeypatch, lambda r: httpx.Response(200, json={"results": [pulse]}))
    [kept] = intel.otx({}, {"api_key": "k"})
    assert kept.value == "203.0.113.3" and kept.expires_at == later


def test_misp_asks_for_published_detection_values_page_by_page(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        page = json.loads(request.content)["page"]
        values = ["203.0.113.1", "203.0.113.2"] if page == 1 else ["203.0.113.3"]
        attributes = [{"type": "ip-dst", "value": v} for v in values]
        return httpx.Response(200, json={"response": {"Attribute": attributes}})

    seen = _routed(monkeypatch, handler)
    settings = {"url": "https://misp.example.test", "limit": 2}
    out = intel.misp(settings, {"api_key": "k"})
    bodies = [json.loads(r.content) for r in seen]
    assert [b["page"] for b in bodies] == [1, 2], "a short page is the last"
    assert all(b["to_ids"] and b["published"] and b["enforceWarninglist"] for b in bodies)
    assert [i.value for i in out] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert not getattr(out, "short", "")
    assert all(i.confidence < 0.8 and i.expires_at for i in out), (
        "a MISP value meets no action floor alone, and it expires"
    )

    out = intel.misp({**settings, "pages": 1}, {"api_key": "k"})
    assert getattr(out, "short", "").startswith("truncated")
    out = intel.misp({**settings, "severity": "High"}, {"api_key": "k"})
    assert {i.severity for i in out} == {"high"}
    out = intel.misp({**settings, "severity": "severe"}, {"api_key": "k"})
    assert {i.severity for i in out} == {"high"}, "a severity findings cannot order is not kept"


def test_a_value_is_stored_the_way_events_write_it():
    assert intel.normalise("ip", "2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert intel.normalise("ip", "203.0.113.0/24") == "", "a CIDR is not an address"
    assert intel.normalise("domain", "Evil.Example.TEST.") == "evil.example.test"
    assert intel.normalise("url", "HTTPS://Bad.example.test/x") == "https://bad.example.test/x"


# -- a page read as text, without its own furniture (DET-4) --------------------
ADVISORY = """<html><head><script src="https://cdn.example.net/app.js"></script>
<link href="https://fonts.example.net/css" rel="stylesheet"></head><body>
<nav><a href="https://cert.example.test/">Home</a></nav>
<p>The actor used hxxp://files.example.com/drop/stage2.bin and 203.0.113.80.</p>
<p>Write to https://www.cert.example.test/contact or cert.example.test.</p>
</body></html>"""


def test_an_html_page_is_read_as_text_without_its_own_host(monkeypatch):
    _page(monkeypatch, ADVISORY)
    kept, own = intel.from_page(
        "https://www.cert.example.test/advisory/1", source="import:cert", confidence=0.8
    )
    assert {(i.type, i.value) for i in kept} == {
        ("url", "http://files.example.com/drop/stage2.bin"),
        ("ip", "203.0.113.80"),
    }, "no script, stylesheet or menu link is an indicator"
    assert sorted(own) == ["cert.example.test", "https://www.cert.example.test/contact"]


def test_a_feed_entry_that_is_not_a_web_page_is_not_a_report(monkeypatch):
    _page(monkeypatch, RSS.replace("https://blog.example.test/b", "javascript:alert(1)"))
    items = intel.rss({"url": "https://blog.example.test/feed"}, {})
    assert [i.url for i in items] == ["https://blog.example.test/a"]


# -- sharing terms (DET-6) ---------------------------------------------------
def test_a_tlp_red_pulse_is_not_pulled_and_amber_keeps_its_marking(monkeypatch):
    red = {**_pulse("203.0.113.1"), "tlp": "red"}
    amber = {**_pulse("203.0.113.2"), "tlp": "amber"}
    _routed(monkeypatch, lambda r: httpx.Response(200, json={"results": [red, amber]}))
    assert [(i.value, i.tlp) for i in intel.otx({}, {"api_key": "k"})] == [("203.0.113.2", "amber")]
    [item] = intel.otx_pulses({}, {"api_key": "k"})
    assert item.text.startswith("TLP:AMBER") and item.categories[0] == "tlp:amber"


def test_misp_leaves_tlp_red_on_the_server_and_keeps_the_marking(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        tagged = {"type": "ip-dst", "value": "203.0.113.1", "Tag": [{"name": "tlp:amber"}]}
        return httpx.Response(200, json={"response": {"Attribute": [tagged]}})

    seen = _routed(monkeypatch, handler)
    [ioc] = intel.misp({"url": "https://misp.example.test"}, {"api_key": "k"})
    body = json.loads(seen[0].content)
    assert body["tags"] == ["!tlp:red"] and body["includeEventTags"] == 1
    assert ioc.tlp == "amber"


def test_a_misp_tag_filter_keeps_tlp_red_out_unless_it_names_it():
    assert intel._misp_tags({"tags": "apt28"}) == ["apt28", "!tlp:red"]
    assert intel._misp_tags({"tags": ["apt28", "phishing"]}) == ["apt28", "phishing", "!tlp:red"]
    assert intel._misp_tags({"tags": ["TLP:RED"]}) == ["TLP:RED"], "a person asked for it"
    assert intel._misp_tags({}) == ["!tlp:red"]


def test_a_feed_with_a_key_follows_no_redirect(monkeypatch):
    """httpx drops only Authorization on a redirect to another host (priv-18)."""
    seen: list[httpx.Request] = []
    real = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://elsewhere.example.test/x"})

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(**{**kw, "transport": mock}))
    with pytest.raises(httpx.HTTPStatusError):
        intel.feodo({}, {"auth_key": "k1"})
    assert [r.url.host for r in seen] == ["feodotracker.abuse.ch"]
