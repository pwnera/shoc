"""What a case contains, extracted from its own evidence (AGT-2, RFC 0010).

The point of this module is that CTI stops depending on somebody using one of
its keywords in a sentence. These tests hold that line: a hash, a command line
and a technique are found in the events, an internal address is not offered for
research, and a bare technique is not on its own a reason to spend a turn.
"""

from __future__ import annotations

from shoc.agents import observables


def kinds(items: list[observables.Observable], kind: str) -> list[str]:
    return [o.value for o in items if o.kind == kind]


def test_a_hash_a_domain_and_a_url_are_typed_separately():
    """A URL is not a domain and a domain is not an address (threat indicators)."""
    events = [
        {
            "file": {"sha256": "A" * 64, "name": "update.exe"},
            "url": {"full": "http://malicious.example.com/a.bin"},
            "src_endpoint": {"ip": "203.0.113.55"},
        }
    ]
    found = observables.of_case([], events)
    assert kinds(found, "sha256") == ["a" * 64]
    assert kinds(found, "url") == ["http://malicious.example.com/a.bin"]
    assert kinds(found, "ip") == ["203.0.113.55"]
    # The host inside the URL is a derivation, but it is still a domain in its
    # own right and typed as one — never as the URL, and never as an address.
    assert "malicious.example.com" in kinds(found, "domain")


def test_an_internal_address_is_not_offered_for_research():
    events = [{"src_endpoint": {"ip": "10.1.2.3"}, "dst_endpoint": {"ip": "127.0.0.1"}}]
    assert kinds(observables.of_case([], events), "ip") == []


def test_a_command_line_is_an_observable_even_with_no_indicator_in_it():
    """The shape is the intelligence: no address, no hash, still something CTI knows."""
    events = [
        {
            "process": {
                "cmd_line": "powershell.exe -nop -w hidden -enc SQBFAFgA... ; certutil -urlcache"
            }
        }
    ]
    found = kinds(observables.of_case([], events), "command")
    assert "-enc" in found and "certutil" in found and "-nop" in found


def test_techniques_come_off_the_findings_and_the_case():
    found = observables.of_case(
        [{"attack": ["T1078.004", "not-a-technique"]}], [], attack=["T1059"]
    )
    assert sorted(kinds(found, "technique")) == ["T1059", "T1078.004"]


def test_a_technique_alone_does_not_buy_cti_a_turn():
    """Almost every finding carries one, and "T1078 exists" is not intelligence."""
    only_technique = observables.of_case([{"attack": ["T1078"]}], [])
    assert not observables.worth_asking(only_technique, [])
    # A report that actually describes the technique is a different matter.
    assert observables.worth_asking(only_technique, [{"report_uid": "R-1"}])


def test_anything_researchable_buys_a_turn():
    events = [{"file": {"sha256": "b" * 64}}]
    assert observables.worth_asking(observables.of_case([], events), [])


def test_one_noisy_event_cannot_fill_the_prompt():
    events = [{"src_endpoint": {"ip": f"203.0.113.{i}"}} for i in range(100)]
    assert len(kinds(observables.of_case([], events), "ip")) == observables.MAX_PER_KIND
