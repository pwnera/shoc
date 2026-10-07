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
