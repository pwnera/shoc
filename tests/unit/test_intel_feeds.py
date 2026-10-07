"""Feed parsers (DET-4). Each one is pinned against a recorded response shape."""

from __future__ import annotations

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
            intel, "_client", lambda headers=None: httpx.Client(transport=transport(handler))
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
