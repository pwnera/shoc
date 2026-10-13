"""Indicator research: classification, disclosure guards and scoring (DET-6, RFC 0004)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from shoc.detect import osint
from shoc.detect.osint import Observation


@pytest.mark.parametrize(
    "value,kind",
    [
        ("203.0.113.4", "ip"),
        ("2001:db8::1", "ip"),
        ("evil-login.example", "domain"),
        ("https://evil-login.example/a?b=c", "url"),
        ("CVE-2026-1234", "cve"),
        ("a" * 64, "sha256"),
        ("b" * 32, "md5"),
        ("attacker@evil-login.example", "email"),
        # Internationalised names, as phishing registers them (DET-4).
        ("login-bank.xn--p1ai", "domain"),
        ("xn--pple-43d.com", "domain"),
        ("not an indicator", ""),
        ("", ""),
    ],
)
def test_a_bare_string_is_classified(value, kind):
    assert osint.classify(value) == kind


@pytest.mark.parametrize(
    "value,kind",
    [
        ("10.1.2.3", "ip"),
        ("192.168.0.1", "ip"),
        ("127.0.0.1", "ip"),
        ("169.254.169.254", "ip"),  # the cloud metadata service
        ("fileserver.internal", "domain"),
        ("intranet", "domain"),
        ("https://192.168.1.1/admin", "url"),
        ("http://app.localhost/hook", "url"),
        ("n8n.ns.svc", "domain"),
    ],
)
def test_internal_values_are_never_disclosed(value, kind):
    assert osint.is_internal(value, kind), f"{value} must not be sent to a third party"


@pytest.mark.parametrize("value,kind", [("203.0.113.4", "ip"), ("evil-login.example", "domain")])
def test_public_values_may_be_researched(value, kind):
    assert not osint.is_internal(value, kind)


def test_a_url_and_an_email_are_asked_about_by_host():
    assert osint.host_of("https://evil-login.example:8443/x", "url") == "evil-login.example"
    assert osint.host_of("attacker@evil-login.example", "email") == "evil-login.example"


def test_a_urls_host_is_parsed_not_split():
    assert osint.host_of("https://user:pw@evil-login.example/x", "url") == "evil-login.example"
    assert osint.host_of("https://ana@acme.example/x", "url") == "acme.example"
    assert osint.host_of("http://[2001:db8::7]:8080/x", "url") == "2001:db8::7"
    assert not osint.is_internal("http://[2001:db8::7]/x", "url"), "a documentation address"
    assert osint.host_of("http://[2001:db8::7/x", "url") == ""
    assert osint.is_internal("http://[2001:db8::7/x", "url"), "a URL with no host is not sent"


def test_a_third_party_is_never_told_a_urls_query_or_user():
    shared = osint._shareable(
        "https://ana:pw@files.example.test/doc/1?X-Amz-Signature=abc&token=s3cret#frag", "url"
    )
    assert shared == "https://files.example.test/doc/1"
    assert osint._shareable("203.0.113.4", "ip") == "203.0.113.4"


def test_only_a_domain_is_resolved():
    assert osint.SOURCES["resolve"].kinds == ("domain",)


def test_history_searches_where_the_matcher_looks():
    sql, params, _ = osint.seen_query("t1", "203.0.113.4", "ip")
    assert "LOWER(src_endpoint_ip) = :indicator" in sql
    assert "LOWER(dst_endpoint_ip) = :indicator" in sql
    assert params["indicator"] == "203.0.113.4" and params["tenant_id"] == "t1"
    sql, _, _ = osint.seen_query("t1", "c2.example.test", "domain")
    assert "dns_query_hostname" in sql and "dst_endpoint_domain" in sql
    sql, _, _ = osint.seen_query("t1", "a" * 64, "sha256")
    assert "process_hash_sha256" in sql and "file_hash_sha256" in sql
    sql, params, _ = osint.seen_query("t1", "ana@acme.example", "email")
    assert "LOWER(actor_user_name) = :indicator" in sql
    assert "LOWER(dns_query_hostname) = :mail_host" in sql
    assert params["mail_host"] == "acme.example"
    _, params, _ = osint.seen_query("t1", "2001:0DB8:0:0::55", "ip")
    assert params["indicator"] == "2001:db8::55", "a long IPv6 form finds the stored one"
    sql, params, _ = osint.seen_query("t1", "loader", "text")
    assert "LIKE :needle" in sql and "indicator" not in params


def test_every_source_declares_the_hosts_it_may_call():
    for name, source in osint.SOURCES.items():
        assert source.kinds, f"{name} applies to no indicator type"
        # Only the two DNS sources talk to the resolver rather than to a URL.
        if name not in ("reverse_dns", "resolve"):
            assert source.hosts, f"{name} may call any host; declare the ones it needs"


def test_nothing_known_is_unknown_not_benign():
    verdict, score, confidence = osint.score(
        [Observation(source="local_iocs", verdict="informational")]
    )
    assert verdict == "unknown" and score == 0.0
    assert confidence < 0.7, "an answer nobody contributed to must not be confident"


def test_one_strong_source_is_enough_to_call_it_malicious():
    verdict, score, _ = osint.score(
        [
            Observation(source="threatfox", verdict="malicious", weight=4.0),
            Observation(source="rdap", verdict="informational"),
        ]
    )
    assert verdict == "malicious" and score == 4.0


def test_a_failed_source_does_not_count_towards_the_verdict():
    verdict, _, confidence = osint.score(
        [
            Observation(
                source="threatfox", ok=False, verdict="malicious", weight=4.0, error="timeout"
            ),
            Observation(source="rdap", verdict="informational"),
        ]
    )
    assert verdict == "unknown", "a source that failed must not decide the answer"
    assert confidence < 0.7


def test_two_weak_signals_add_up_to_suspicious():
    verdict, score, _ = osint.score(
        [
            Observation(source="tor_exit", verdict="suspicious", weight=2.0),
            Observation(source="rdap", verdict="suspicious", weight=1.5),
        ]
    )
    assert verdict == "suspicious" and score == 3.5


def test_a_documentation_address_is_researchable():
    # Every fixture, eval and test in this repo uses RFC 5737 ranges. Python
    # calls them private; research must not skip them.
    for value in ("203.0.113.4", "192.0.2.10", "198.51.100.77", "2001:db8::1"):
        assert osint.is_public_address(value), f"{value} must be researchable"
        assert not osint.is_internal(value, "ip")


def test_the_summary_names_shared_infrastructure_first():
    research = osint.Research(
        value="203.0.113.4",
        type="ip",
        verdict="unknown",
        shared_infrastructure=True,
        owner="Cloudflare",
        observations=[Observation(source="cloud_ranges", summary="inside Cloudflare v4")],
        sources_ok=["cloud_ranges"],
    )
    assert "shared infrastructure" in osint._summarise(research)
    assert "Cloudflare" in osint._summarise(research)


# -- source parsers, against recorded response shapes (DET-6) ----------------
@pytest.fixture
def answers(monkeypatch):
    """Every source's HTTP call answered from a table keyed by host and path, or by
    host alone, never the network. `sent` keeps each request's headers."""
    import httpx

    table: dict[str, object] = {}
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        body = table.get(f"{request.url.host}{request.url.path}", table.get(request.url.host))
        if body is None:
            return httpx.Response(404)
        if isinstance(body, str):
            return httpx.Response(200, text=body)
        return httpx.Response(200, json=body)

    monkeypatch.setattr(
        osint,
        "_client",
        lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_RDAP", {})
    table["__sent__"] = sent
    return table


def test_rdap_names_the_owner_and_flags_a_new_domain(answers):
    from datetime import UTC, datetime, timedelta

    fresh = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    answers["data.iana.org"] = {"services": [[["example"], ["https://rdap.example.test/"]]]}
    answers["rdap.example.test"] = {
        "name": "EVIL-LOGIN",
        "country": "NL",
        "handle": "D1",
        "entities": [{"handle": "REG-1"}],
        "events": [{"eventAction": "registration", "eventDate": fresh}],
    }
    obs = osint.rdap("evil-login.example", "domain")
    assert obs.verdict == "suspicious" and obs.weight == 1.5
    assert obs.data["age_days"] == 3 and "EVIL-LOGIN" in obs.summary
    assert answers["__sent__"][-1].url.host == "rdap.example.test", "IANA's registry, not rdap.org"


def test_an_old_domain_changed_last_week_is_not_young(answers):
    from datetime import UTC, datetime, timedelta

    changed = (datetime.now(UTC) - timedelta(days=6)).isoformat()
    answers["rdap.org"] = {
        "name": "OLD-CO",
        "events": [
            {"eventAction": "last changed", "eventDate": changed},
            {"eventAction": "registration", "eventDate": "2012-03-01T00:00:00Z"},
        ],
    }
    obs = osint.rdap("old-company.example", "domain")
    assert obs.verdict == "informational" and obs.data["registered"].startswith("2012")


def test_threatfox_sends_the_key_and_matches_only_this_value(answers):
    answers["threatfox-api.abuse.ch"] = {
        "query_status": "ok",
        "data": [
            {"ioc": "203.0.113.4:443", "malware_printable": "Lumma Stealer", "first_seen": "x"},
            {"ioc": "203.0.113.44:80", "malware_printable": "Other"},
        ],
    }
    obs = osint.threatfox("203.0.113.4", "ip", {"auth_key": "k1"})
    assert obs.verdict == "malicious" and obs.data["malware"] == ["Lumma Stealer"]
    assert answers["__sent__"][-1].headers["Auth-Key"] == "k1"
    answers["threatfox-api.abuse.ch"] = {"query_status": "no_result"}
    assert osint.threatfox("203.0.113.4", "ip", {"auth_key": "k1"}).weight == 0.0


def test_a_url_is_judged_by_itself_not_by_its_host(answers):
    host = {
        "query_status": "ok",
        "urls": [{"url_status": "online", "tags": ["exe"]}, {"url_status": "offline"}],
    }
    answers["urlhaus-api.abuse.ch/v1/host/"] = host
    answers["urlhaus-api.abuse.ch/v1/url/"] = {"query_status": "no_results"}
    obs = osint.urlhaus("http://shared.example.test/page.html", "url", {"auth_key": "k"})
    assert obs.verdict == "informational" and obs.weight == 0.0
    assert obs.data["relation"] == "host_of" and obs.data["urls"] == 2

    answers["urlhaus-api.abuse.ch/v1/url/"] = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
    }
    listed = osint.urlhaus("http://shared.example.test/a.exe", "url", {"auth_key": "k"})
    assert listed.verdict == "malicious" and listed.weight == 4.0

    assert osint.urlhaus("bad.example.test", "domain", {"auth_key": "k"}).data == {
        "urls": 2,
        "online": 1,
        "tags": ["exe"],
    }


def test_malwarebazaar_names_the_family(answers):
    answers["mb-api.abuse.ch"] = {
        "query_status": "ok",
        "data": [{"signature": "LummaStealer", "file_type": "exe", "tags": ["stealer"]}],
    }
    obs = osint.malwarebazaar("a" * 64, "sha256", {"auth_key": "k"})
    assert obs.verdict == "malicious" and "LummaStealer" in obs.summary


def test_epss_and_nvd_describe_a_cve(answers):
    answers["api.first.org"] = {"data": [{"epss": "0.72", "percentile": "0.99"}]}
    assert osint.epss("CVE-2026-1234", "cve").verdict == "malicious"
    answers["services.nvd.nist.gov"] = {
        "vulnerabilities": [
            {
                "cve": {
                    "published": "2026-01-01",
                    "descriptions": [{"lang": "en", "value": "Auth bypass in a VPN appliance"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }
    obs = osint.nvd("CVE-2026-1234", "cve")
    assert obs.data["cvss"] == 9.8 and obs.weight == 1.0 and "VPN" in obs.summary


def test_tor_exits_and_cloud_ranges_mark_shared_infrastructure(answers):
    answers["check.torproject.org"] = "203.0.113.9\n198.51.100.1\n"
    assert osint.tor_exit("203.0.113.9", "ip").data["shared"]
    answers["ip-ranges.amazonaws.com"] = {
        "prefixes": [{"ip_prefix": "198.51.100.0/24", "region": "eu-west-1"}]
    }
    answers["www.gstatic.com"] = {"prefixes": []}
    answers["www.cloudflare.com"] = ""
    obs = osint.cloud_ranges("198.51.100.20", "ip")
    assert obs.data["shared"] and obs.data["provider"] == "AWS"
    assert obs.data["scope"] == "eu-west-1"
    assert not osint.cloud_ranges("203.0.113.20", "ip").data["shared"]


def test_azure_is_named_by_its_service_not_azurecloud(answers):
    link = "https://download.microsoft.com/download/1/2/ServiceTags_Public_20261001.json"
    answers["www.microsoft.com"] = f'<a href="{link}">download</a>'
    answers["download.microsoft.com"] = {
        "values": [
            {"name": "AzureCloud", "properties": {"addressPrefixes": ["198.51.100.0/24"]}},
            {
                "name": "AzureActiveDirectory",
                "properties": {"addressPrefixes": ["198.51.100.0/26"]},
            },
            {
                "name": "AzureCloud.westeurope",
                "properties": {"addressPrefixes": ["203.0.113.0/24"]},
            },
        ]
    }
    assert osint.cloud_ranges("198.51.100.7", "ip").data["scope"] == "AzureActiveDirectory"
    assert osint.cloud_ranges("198.51.100.200", "ip").data["scope"] == "AzureCloud"
    assert not osint.cloud_ranges("203.0.113.5", "ip").data["shared"], "regional copies skipped"


# -- downloaded lists (RFC 0030) ----------------------------------------------
def test_ranges_find_the_most_specific_network():
    nets = osint.Ranges()
    nets.add("198.51.100.0/24", "wide")
    nets.add("198.51.100.0/28", "narrow")
    nets.add("2001:db8::/32", "v6")
    assert nets.get("198.51.100.3") == ("198.51.100.0/28", "narrow")
    assert nets.get("198.51.100.99") == ("198.51.100.0/24", "wide")
    assert nets.get("2001:db8::5") == ("2001:db8::/32", "v6")
    assert nets.get("203.0.113.1") is None and nets.get("not an ip") is None
    assert len(nets) == 3


def test_spans_find_the_row_holding_an_address():
    rows = osint.Spans()
    rows.add("198.51.100.0", "198.51.100.127", "64500\tExample Net")
    rows.add("198.51.100.128", "198.51.100.255", "64501\tOther Net")
    rows.add("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "64502\tV6 Net")
    assert rows.get("198.51.100.5") == "64500\tExample Net"
    assert rows.get("198.51.100.200") == "64501\tOther Net"
    assert rows.get("2001:db8:1::1") == "64502\tV6 Net"
    assert rows.get("203.0.113.1") is None


def test_a_list_that_halves_overnight_is_not_trusted(monkeypatch):
    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_REFUSED", {})
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    full = set(map(str, range(100)))
    assert osint._cached_list("demo", lambda: full) == full
    stale = osint._LISTS["demo"][0] - osint._DAY
    osint._LISTS["demo"] = (stale, full)
    assert osint._cached_list("demo", lambda: {"1", "2"}) == full
    assert "kept the previous copy" in osint.LIST_WARNINGS["demo"]


def _age(by):
    """Move every kept copy, and every refusal, back by `by`."""
    for key, (at, value) in list(osint._LISTS.items()):
        osint._LISTS[key] = (at - by, value)
    for key, (at, size) in list(osint._REFUSED.items()):
        osint._REFUSED[key] = (at - by, size)


def test_a_size_that_holds_for_two_ttls_is_taken(monkeypatch):
    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_REFUSED", {})
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    full, grown = set(map(str, range(100))), set(map(str, range(300)))
    ttl = osint._DAY
    assert osint._cached_list("demo", lambda: full, ttl) == full
    for _ in range(2):
        _age(ttl)
        assert osint._cached_list("demo", lambda: grown, ttl) == full, "one swing is not trusted"
    _age(ttl)
    assert osint._cached_list("demo", lambda: grown, ttl) == grown
    assert "took the new copy" in osint.LIST_WARNINGS["demo"] and not osint._REFUSED


def test_a_size_off_the_refused_one_starts_the_count_again(monkeypatch):
    """A truncated download after two TTLs of growth does not replace the list (D123)."""
    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_REFUSED", {})
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    full, grown = set(map(str, range(100))), set(map(str, range(300)))
    ttl = osint._DAY
    assert osint._cached_list("demo", lambda: full, ttl) == full
    for _ in range(2):
        _age(ttl)
        assert osint._cached_list("demo", lambda: grown, ttl) == full
    _age(ttl)
    assert osint._cached_list("demo", lambda: {"1", "2", "3"}, ttl) == full, "not the size refused"
    _age(ttl)
    assert osint._cached_list("demo", lambda: grown, ttl) == full, "the count started again"
    assert "kept the previous copy" in osint.LIST_WARNINGS["demo"]


def test_a_cloud_missing_from_the_first_load_is_taken_when_it_answers(monkeypatch):
    """A first copy without Azure locked the cloud ranges until a restart (DET-6, RSP-5)."""
    import contextlib
    from types import SimpleNamespace

    import httpx

    up = {"azure": False}
    service_tags = "https://download.microsoft.com/download/7/ServiceTags_Public_20261012.json"
    front_door = ["203.0.113.0/24"] + [f"2001:db8:{i:x}::/48" for i in range(40)]

    def fake_get(http, url):
        if "amazonaws" in url:
            prefixes = [{"ip_prefix": "198.51.100.0/24", "region": "eu-west-1"}]
            return SimpleNamespace(json=lambda: {"prefixes": prefixes})
        if up["azure"] and "details.aspx" in url:
            return SimpleNamespace(text=f'<a href="{service_tags}">')
        if up["azure"] and url == service_tags:
            tag = {"name": "AzureFrontDoor", "properties": {"addressPrefixes": front_door}}
            return SimpleNamespace(json=lambda: {"values": [tag]})
        raise httpx.ConnectError("down")

    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_REFUSED", {})
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    monkeypatch.setattr(osint, "_get", fake_get)
    monkeypatch.setattr(osint, "_client", lambda timeout=None: contextlib.nullcontext())

    first = osint._listed("cloud")
    assert first.get("198.51.100.7") == ("198.51.100.0/24", "AWS\teu-west-1")
    assert first.get("203.0.113.7") is None
    assert "not loaded" in osint.LIST_WARNINGS["cloud:azure"]

    up["azure"] = True
    _age(osint._DAY)
    full = osint._listed("cloud")
    assert full.get("203.0.113.7") == ("203.0.113.0/24", "Azure\tAzureFrontDoor")
    assert "cloud:azure" not in osint.LIST_WARNINGS

    up["azure"] = False
    _age(osint._DAY)
    kept = osint._listed("cloud")
    assert kept.get("203.0.113.7"), "a provider that fails keeps its last copy"
    assert "kept the previous copy" in osint.LIST_WARNINGS["cloud:azure"]


def test_warninglists_match_each_type_their_own_way():
    benign = osint.Benign()
    benign.add("google", "domain", "hostname", "google.com")
    benign.add("microsoft", "domain", "string", ".aadrm.com")
    benign.add("second-level-tlds", "domain", "string", "co.uk")
    benign.add("public-dns-v4", "ip", "cidr", "198.51.100.0/24")
    benign.add("empty-hashes", "sha256", "string", "E" * 64)
    assert benign.get("mail.google.com", "domain") == "google"
    assert benign.get("x.aadrm.com", "domain") == "microsoft"
    assert benign.get("co.uk", "domain") == "second-level-tlds"
    assert benign.get("evil.co.uk", "domain") == "", "an exact entry is not a suffix"
    assert benign.get("198.51.100.53", "ip") == "public-dns-v4"
    assert benign.get("e" * 64, "sha256") == "empty-hashes"
    assert benign.get("https://mail.google.com/x", "url") == "", "a URL is not its host"


def test_known_benign_never_downloads(monkeypatch):
    monkeypatch.setattr(osint, "_LISTS", {})
    assert osint.known_benign("google.com", "domain") is None, "not loaded is not benign-free"
    assert osint.known_benign("https://google.com/x", "url") == "", "no list checks a URL"
    benign = osint.Benign()
    benign.add("google", "domain", "hostname", "google.com")
    osint._LISTS["warninglists"] = (osint.datetime.now(osint.UTC), benign)
    assert osint.known_benign("google.com", "domain") == "google"


def test_drop_and_asn_drop_say_malicious(monkeypatch):
    from datetime import UTC, datetime

    drop = osint.Ranges()
    drop.add("203.0.113.0/24", "SBL1")
    asn = osint.Spans()
    asn.add("198.51.100.0", "198.51.100.255", "64666\tBulletproof Ltd")
    now = datetime.now(UTC)
    monkeypatch.setattr(
        osint,
        "_LISTS",
        {
            "drop": (now, drop),
            "dbip_asn": (now, asn),
            "dbip_country": (now, osint.Spans()),
            "asn_drop": (now, {64666}),
        },
    )
    assert osint.spamhaus_drop("203.0.113.9", "ip").weight == 4.0
    found = osint.asn("198.51.100.9", "ip")
    assert found.verdict == "malicious" and found.data["asn"] == 64666


def test_every_keyed_source_names_a_provider_with_a_quota():
    keyed = [s for s in osint.SOURCES.values() if s.key]
    assert keyed, "the keyed sources are registered"
    for source in keyed:
        provider = osint.KEYED[source.key]
        assert provider.per_day > 0 and set(source.hosts) <= set(provider.hosts)
    for source in osint.SOURCES.values():
        assert not (source.key and source.listed), "a keyed source sends the value out"


def test_a_refused_key_is_not_repeated_in_the_error_or_cached(monkeypatch):
    """Shodan and ipapi.is take their key in the query string (priv-1)."""
    import httpx

    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401 if request.url.host == "api.shodan.io" else 403)

    monkeypatch.setattr(
        osint, "_client", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(refuse))
    )
    shodan = osint._run_source(
        osint.SOURCES["shodan"], "203.0.113.7", "ip", {"api_key": "SHODAN-SECRET"}
    )
    ipapi = osint._run_source(
        osint.SOURCES["ipapi_is"], "203.0.113.7", "ip", {"key": "IPAPI-SECRET"}
    )
    assert not shodan.ok and shodan.error == "HTTP 401 from api.shodan.io"
    assert not ipapi.ok and ipapi.error == "HTTP 403 from api.ipapi.is"

    written: list[tuple] = []
    monkeypatch.setattr(osint, "execute", lambda conn, sql, params: written.append(params))
    answer = Observation(source="rdap", summary="registered to EXAMPLE-NET")
    osint._to_cache(cast(Any, None), "t1", "203.0.113.7", "ip", [shodan, ipapi, answer])
    (params,) = written
    assert "SECRET" not in params[6] and '"shodan"' not in params[6]
    assert '"rdap"' in params[6]
    written.clear()
    osint._to_cache(cast(Any, None), "t1", "203.0.113.7", "ip", [shodan, ipapi])
    assert written == [], "nothing but failures is not an answer to keep"


def test_a_list_is_loaded_beside_the_caller(monkeypatch):
    benign = osint.Benign()
    benign.add("google", "domain", "hostname", "google.com")
    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_LOADING", {})
    monkeypatch.setattr(osint, "_FAILED", {})
    monkeypatch.setitem(osint.LISTS, "warninglists", (lambda: benign, osint._DAY))
    assert osint.known_benign("google.com", "domain") is None
    assert osint.load_soon("warninglists", wait=5.0)
    assert osint.known_benign("google.com", "domain") == "google"
    assert osint.load_soon("warninglists"), "loaded once, answered from then on"


def test_a_list_that_failed_to_load_is_not_waited_for_again_at_once(monkeypatch):
    """A blocked egress costs one wait, not one per poll (RFC 0030)."""
    tries: list[int] = []

    def down():
        tries.append(1)
        raise OSError("no route")

    monkeypatch.setattr(osint, "_LISTS", {})
    monkeypatch.setattr(osint, "_LOADING", {})
    monkeypatch.setattr(osint, "_FAILED", {})
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    monkeypatch.setitem(osint.LISTS, "warninglists", (down, osint._DAY))
    assert not osint.load_soon("warninglists", wait=5.0)
    assert not osint.load_soon("warninglists", wait=5.0) and tries == [1]
    osint._FAILED["warninglists"] -= osint._RETRY
    assert not osint.load_soon("warninglists", wait=5.0) and tries == [1, 1]


def test_a_source_redirect_inside_is_refused_and_a_keyed_source_follows_none(monkeypatch):
    """A source may follow a redirect only to a public address (SEC-1), and one
    that carries a key follows none: httpx keeps a custom key header (priv-18)."""
    import httpx

    from shoc.errors import ValidationError

    seen: list[httpx.Request] = []
    real = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(**{**kw, "transport": mock}))
    with osint._client() as http, pytest.raises(ValidationError, match="internal host"):
        http.get("https://api.first.org/data/v1/epss")
    assert [r.url.host for r in seen] == ["api.first.org"]

    seen.clear()
    obs = osint._run_source(osint.SOURCES["threatfox"], "203.0.113.7", "ip", {"auth_key": "k1"})
    assert not obs.ok and obs.error == "HTTP 302 from threatfox-api.abuse.ch"
    assert [r.url.host for r in seen] == ["threatfox-api.abuse.ch"]
