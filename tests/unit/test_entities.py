"""Entity kinds on findings, and which of them join findings into a case (RSP-2, RFC 0026)."""

from __future__ import annotations

from shoc.cases.engine import _cluster
from shoc.detect.engine import entities_of


def test_a_session_key_names_its_role_and_an_edr_row_its_device_and_hashes():
    row = {
        "actor_user_name": "web-role",
        "actor_user_type": "AssumedRole",
        "actor_session_uid": "ASIAEXAMPLEINSTANCE1",
        "device_uid": "i-0abc123def4567890",
    }
    assert entities_of(row) == [
        "device:i-0abc123def4567890",
        "key:ASIAEXAMPLEINSTANCE1",
        "role:web-role",
        "user:web-role",
    ]
    edr = {"device_uid": "dev-1", "process_hash_sha256": "aa" * 32, "file_hash_sha256": "bb" * 32}
    assert entities_of(edr) == [
        "device:dev-1",
        f"file_hash:{'bb' * 32}",
        f"process_hash:{'aa' * 32}",
    ]


def test_a_sign_in_session_is_not_a_key():
    """Okta's and Entra's session ids name a sign-in; their mappings say so, and
    a case is not titled with a session GUID as if it were a leaked key (DET-11)."""
    from shoc.ingest import ocsf

    okta = {"metadata_product": "Okta System Log", "actor_session_uid": "102abcSESSION"}
    entra = {"metadata_product": "Microsoft Entra ID", "actor_session_uid": "00000000-d601"}
    cloudtrail = {"metadata_product": "AWS CloudTrail", "actor_session_uid": "AKIAIOSFODNN7EXAMPLE"}
    assert entities_of(okta) == ["session:102abcSESSION"]
    assert entities_of(entra) == ["session:00000000-d601"]
    assert entities_of(cloudtrail) == ["key:AKIAIOSFODNN7EXAMPLE"]
    bare = {"actor_session_uid": "AKIAIOSFODNN7EXAMPLE"}
    assert entities_of(bare) == ["key:AKIAIOSFODNN7EXAMPLE"], "no product: the key it always was"
    row = ocsf.load_mapping("entra").map_record(
        {"id": "s-1", "userPrincipalName": "jane@example.com", "correlationId": "c-1"}, "t1"
    )
    assert row["actor_session_uid"] is None, "a correlation id is one request, not a session"


def test_m365_and_cloud_funnel_sessions_and_azure_correlation_ids():
    """The other mappings that fill actor.session.uid say what it is (hunt-23)."""
    from shoc.ingest import ocsf

    m365 = {"metadata_product": "Microsoft 365", "actor_session_uid": "00000000-a1"}
    funnel = {"metadata_product": "SentinelOne Cloud Funnel", "actor_session_uid": "0x3e7"}
    assert entities_of(m365) == ["session:00000000-a1"]
    assert entities_of(funnel) == ["session:0x3e7"]
    row = ocsf.load_mapping("azure_activity").map_record(
        {"eventDataId": "a-1", "caller": "jane@example.com", "correlationId": "c-1"}, "t1"
    )
    assert row["actor_session_uid"] is None, "a correlation id is one request, not a session"


def test_an_iam_user_is_not_a_role():
    assert not [
        e
        for e in entities_of({"actor_user_name": "support", "actor_user_type": "IAMUser"})
        if e.startswith("role:")
    ]


def test_a_shared_hash_or_role_does_not_join_two_cases_but_a_device_does():
    powershell = "cc" * 32
    a = {"entities": [f"process_hash:{powershell}", "role:web-role", "host:LAPTOP-1"]}
    b = {"entities": [f"process_hash:{powershell}", "role:web-role", "host:LAPTOP-2"]}
    assert len(_cluster([a, b])) == 2
    c = {"entities": ["device:dev-1", "user:jdoe"]}
    d = {"entities": ["device:dev-1", "user:jane.doe@example.com"]}
    assert len(_cluster([c, d])) == 1


def test_two_people_signing_in_on_an_iphone_are_not_one_case():
    """Identity sources name the user's device, and iOS 16 calls every iPhone
    "iPhone", so a rule finding carries no device name to link on (RSP-2)."""
    from shoc.detect.compiler import EVIDENCE_COLUMNS
    from shoc.ingest import ocsf

    mapping = ocsf.load_mapping("entra")
    rows = [
        mapping.map_record(
            {
                "id": f"s-{n}",
                "userPrincipalName": user,
                "ipAddress": ip,
                "deviceDetail": {"displayName": "iPhone"},
            },
            "t1",
        )
        for n, (user, ip) in enumerate(
            (("jane@example.com", "198.51.100.7"), ("john@example.com", "203.0.113.9"))
        )
    ]
    assert [r["device_hostname"] for r in rows] == ["iPhone", "iPhone"]
    findings = [{"entities": entities_of({c: r.get(c) for c in EVIDENCE_COLUMNS})} for r in rows]
    assert len(_cluster(findings)) == 2


def test_a_finding_names_its_remote_peer_only_when_it_is_on_the_internet():
    """An inbound probe's target is the instance's private address, the same
    172.31.0.0/16 in every default VPC, and would join unrelated accounts."""
    assert entities_of({"class_uid": 2004, "dst_endpoint_ip": "203.0.113.50"}) == [
        "ip:203.0.113.50"
    ]
    assert entities_of({"class_uid": 2004, "dst_endpoint_ip": "172.31.5.9"}) == []
    assert entities_of({"class_uid": 6003, "dst_endpoint_ip": "203.0.113.50"}) == []
