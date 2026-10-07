"""Indicator research: classification, disclosure guards and scoring (DET-6, RFC 0004)."""

from __future__ import annotations

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
    monkeypatch.setattr(osint, "LIST_WARNINGS", {})
    full = set(map(str, range(100)))
    assert osint._cached_list("demo", lambda: full) == full
    stale = osint._LISTS["demo"][0] - osint._DAY
    osint._LISTS["demo"] = (stale, full)
    assert osint._cached_list("demo", lambda: {"1", "2"}) == full
    assert "kept the previous copy" in osint.LIST_WARNINGS["demo"]


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
    assert osint.known_benign("google.com", "domain") == ""
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
