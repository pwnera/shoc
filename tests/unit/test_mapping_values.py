"""What each event kind maps to, for the sources with no test file of their own (ING-3)."""

from __future__ import annotations

import json

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES

# (source, event_uid) -> the columns that event must carry.
EXPECTED = {
    ("openai", "audit_log-xxx_20260920"): {
        "activity_id": 1,
        "severity_id": 2,
        "api_operation": "api_key.created",
        "actor_user_name": "mallory@example.com",
        "actor_session_uid": "key_xxxx",
        "src_endpoint_ip": "203.0.113.44",
        "src_endpoint_location_country": "US",
        "resource_uid": "proj_abc",
        "time": "2026-09-21T14:13:20+00:00",
    },
    ("openai", "audit_log-login_failed_20260920"): {
        "activity_id": 99,
        "status": "Failure",
        "severity_id": 2,
        "status_code": "invalid_credentials",
        "actor_user_name": "bob@example.com",
        "src_endpoint_ip": "198.51.100.7",
        "src_endpoint_asn": "64501",
    },
    # Usage is banded by order of magnitude of the hour's output tokens.
    ("openai", "openai-usage-key_xxxx-proj_abc-2026-09-20T02:00:00+00:00"): {
        "activity_id": 2,
        "severity_id": 2,
        "api_operation": "usage",
        "actor_session_uid": "key_xxxx",
        "time": "2026-09-20T02:00:00+00:00",
    },
    ("openai", "openai-usage-key_batch-proj_abc-2026-09-20T03:00:00+00:00"): {
        "severity_id": 3,
        "actor_session_uid": "key_batch",
    },
    ("anthropic", "apikey_01Rj2N8SVvo6BePZj99NhmiT"): {
        "activity_id": 1,
        "severity_id": 2,
        "message": "prod-backend",
        "actor_user_name": "user_01WCz1FkmYMm4gnmykNKUu3Q",
        "resource_uid": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ",
    },
    ("anthropic", "anthropic-usage-apikey_01Rj2N8SVvo6BePZj99NhmiT--2026-09-20T02:00:00+00:00"): {
        "activity_id": 2,
        "severity_id": 2,
        "actor_session_uid": "apikey_01Rj2N8SVvo6BePZj99NhmiT",
    },
    ("anthropic", "activity_01H"): {
        "activity_id": 1,
        "api_operation": "platform_api_key_created",
        "actor_user_name": "mallory@example.com",
        "actor_session_uid": "apikey_01New",
        "src_endpoint_ip": "203.0.113.44",
        "cloud_account_uid": "org_01",
    },
    ("stripe", "accact_1SdeybAiQNL8swvtMHyVtfCU"): {
        "activity_id": 1,
        "severity_id": 2,
        "actor_user_name": "user@example.com",
        "resource_uid": "mk_1SdeybAiQNL8swvtMHyVtfCU",
        "cloud_account_uid": "acct_1SdeybAiQNL8swvt",
    },
    ("stripe", "evt_3PfakeCardTest0001"): {
        "status": "Failure",
        "status_code": "card_declined",
        "resource_uid": "ch_3PfakeCharge0001",
        "actor_user_name": "tester@example.net",
        "cloud_account_uid": "stripe",
    },
    ("stripe", "accact_1SdeybAiQNL8swvtUserRole01"): {
        "activity_id": 3,
        "severity_id": 2,
        "actor_session_uid": "rk_live_fakeRestricted01",
        "resource_uid": "new-admin@example.org",
    },
    ("stripe", "evt_3PfakeFraudWarning01"): {
        "severity_id": 3,
        "resource_uid": "ch_3PfakeCharge0002",
    },
    # Wazuh levels 0-15 fold into the five OCSF severities.
    ("wazuh", "wz-1"): {
        "class_uid": 2004,
        "severity_id": 4,
        "actor_user_name": "admin",
        "src_endpoint_ip": "203.0.113.77",
        "resource_uid": "001",
        "status_code": "sshd",
    },
    ("wazuh", "wz-2"): {
        "severity_id": 2,
        "actor_user_name": "deploy",
        "src_endpoint_ip": "10.1.2.6",
    },
    ("wazuh", "wz-3"): {"severity_id": 3, "message": "Integrity checksum changed."},
    ("wazuh", "wz-4"): {"severity_id": 5, "api_operation": "ransomware", "resource_uid": "003"},
    ("gcp_audit", "gcp-1"): {
        "class_uid": 6003,
        "activity_id": 1,
        "severity_id": 3,
        "actor_user_name": "dana@example.com",
        "cloud_account_uid": "example-prod",
    },
    ("gcp_audit", "gcp-2"): {"activity_id": 99, "status": "Failure", "status_code": "7"},
    ("gcp_audit", "ofj3qoe4mbih"): {"activity_id": 4, "severity_id": 3},
    ("gcp_audit", "2f93b0a6-f932-4d91-ad61-785ae9587360"): {"activity_id": 3},
    ("gcp_audit", "-tn3jrd3lko"): {"class_uid": 3001, "activity_id": 11, "severity_id": 3},
    ("gcp_audit", "-nahbepd4l1x"): {"class_uid": 3002, "activity_id": 1, "status": "Failure"},
    ("gcp_audit", "nlgrf8d6ygj"): {"class_uid": 2004, "severity_id": 4},
}


def _rows(source: str) -> dict[str, dict]:
    records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
    mapping = ocsf.load_mapping(source)
    return {row["event_uid"]: row for row in (mapping.map_record(r, "t1") for r in records)}


@pytest.mark.parametrize(("source", "uid"), sorted(EXPECTED))
def test_an_event_kind_maps_to_its_values(source, uid):
    row = _rows(source)[uid]
    assert {k: row[k] for k in EXPECTED[source, uid]} == EXPECTED[source, uid]
