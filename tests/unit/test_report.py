"""Reading a threat report: flattening, refanging and extraction (DET-7, RFC 0004)."""

from __future__ import annotations

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
