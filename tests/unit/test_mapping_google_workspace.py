"""Workspace values read from named event parameters (ING-3)."""

from __future__ import annotations

import pytest

from shoc.ingest import ocsf


def _challenge(status):
    return {
        "id": {"time": "2026-09-20T10:00:00Z", "uniqueQualifier": "1", "applicationName": "login"},
        "actor": {"email": "jane@example.com"},
        "events": [
            {
                "type": "login",
                "name": "login_challenge",
                "parameters": [
                    {"name": "login_type", "value": "google_password"},
                    {"name": "login_challenge_method", "multiValue": ["idv_preregistered_phone"]},
                    {"name": "login_challenge_status", "value": status},
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("passed", "Success"),
        ("incorrect_answer_entered", "Failure"),
        ("Challenge Passed.", "Success"),
        ("Challenge Failed.", "Failure"),
    ],
)
def test_challenge_outcome(status, expected):
    row = ocsf.load_mapping("google_workspace").map_record(_challenge(status), "t1")
    assert (row["class_uid"], row["activity_name"], row["status"]) == (3002, "Preauth", expected)


def test_chromeos_event_names_its_device():
    record = {
        "id": {"time": "2026-09-20T10:00:00Z", "uniqueQualifier": "2", "applicationName": "chrome"},
        "actor": {"callerType": "USER", "profileId": "user1"},
        "events": [
            {
                "type": "CHROME_OS_LOGIN_LOGOUT_TYPE",
                "name": "CHROME_OS_LOGIN_FAILURE_EVENT",
                "parameters": [
                    {"name": "TIMESTAMP", "intValue": "1730800000000"},
                    {"name": "DEVICE_NAME", "value": "laptop-01.example.com"},
                    {"name": "DIRECTORY_DEVICE_ID", "value": "dev-1"},
                ],
            }
        ],
    }
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert (row["class_uid"], row["status"]) == (3002, "Failure")
    assert (row["device_hostname"], row["device_uid"]) == ("laptop-01.example.com", "dev-1")


def _token(name: str = "authorize") -> dict:
    return {
        "id": {
            "time": "2026-10-01T23:20:07Z",
            "uniqueQualifier": "3",
            "applicationName": "token",
            "customerId": "C01",
        },
        "actor": {"email": "admin@example.com", "profileId": "1"},
        "ipAddress": "203.0.113.10",
        "events": [
            {
                "type": "auth",
                "name": name,
                "parameters": [
                    {"name": "client_id", "value": "100000000000000000001"},
                    {"name": "app_name", "value": "backup tool"},
                    {"name": "client_type", "value": "WEB"},
                ],
            }
        ],
    }


def test_an_oauth_grant_names_the_client_it_authorised():
    row = ocsf.load_mapping("google_workspace").map_record(_token(), "t1")
    assert row["resource_uid"] == "100000000000000000001"


def test_reading_one_named_parameter_keeps_the_others():
    """RFC 0021: `client_id` was read, so it leaves `unmapped`; `app_name` and
    `client_type` were not, and their values must stay there."""
    row = ocsf.load_mapping("google_workspace").map_record(_token(), "t1")
    (event,) = row["unmapped"]["events"]
    kept = {p["name"]: p.get("value") for p in event["parameters"]}
    assert kept == {"app_name": "backup tool", "client_type": "WEB"}


def test_domain_wide_delegation_names_the_client():
    record = {
        "id": {"time": "2026-10-01T10:00:00Z", "uniqueQualifier": "4", "applicationName": "admin"},
        "actor": {"email": "admin@example.com"},
        "events": [
            {
                "type": "DOMAIN_SETTINGS",
                "name": "AUTHORIZE_API_CLIENT_ACCESS",
                "parameters": [{"name": "API_CLIENT_NAME", "value": "100000000000000000002"}],
            }
        ],
    }
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert (row["class_uid"], row["resource_uid"]) == (3005, "100000000000000000002")


def _admin(name: str, *params: tuple[str, str]) -> dict:
    return {
        "id": {"time": "2026-10-01T10:00:00Z", "uniqueQualifier": "5", "applicationName": "admin"},
        "actor": {"email": "admin@example.com"},
        "events": [
            {
                "type": "SECURITY_SETTINGS",
                "name": name,
                "parameters": [{"name": k, "value": v} for k, v in params],
            }
        ],
    }


def test_every_parameter_is_readable_by_name():
    """RFC 0023: the setting, the old and new value, and the org unit, by name."""
    record = _admin(
        "ALLOW_STRONG_AUTHENTICATION",
        ("SETTING_NAME", "2SV"),
        ("OLD_VALUE", "true"),
        ("NEW_VALUE", "false"),
        ("ORG_UNIT_NAME", "Sales"),
    )
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert row["unmapped"]["params"] == {
        "SETTING_NAME": "2SV",
        "OLD_VALUE": "true",
        "NEW_VALUE": "false",
        "ORG_UNIT_NAME": "Sales",
    }
    assert row["severity_id"] == 1, "the new value is read by name, not carried as severity"


def test_an_oauth_grant_carries_its_scopes():
    record = _token()
    record["events"][0]["parameters"].append(
        {"name": "scope", "multiValue": ["openid", "https://mail.google.com/"]}
    )
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert row["unmapped"]["params"]["scope"] == ["openid", "https://mail.google.com/"]


def test_an_out_of_domain_forward_names_the_destination():
    record = {
        "id": {"time": "2026-10-01T10:00:00Z", "uniqueQualifier": "6", "applicationName": "login"},
        "actor": {"email": "jane@example.com"},
        "events": [
            {
                "type": "email_forwarding_change",
                "name": "email_forwarding_out_of_domain",
                "parameters": [
                    {"name": "email_forwarding_destination_address", "value": "drop@example.org"}
                ],
                "resourceIds": ["RESOURCE_ID1"],
            }
        ],
    }
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert (row["class_uid"], row["resource_uid"]) == (3001, "drop@example.org")


def test_a_google_sign_in_carries_country_and_asn():
    record = {
        "id": {"time": "2026-10-01T10:00:00Z", "uniqueQualifier": "7", "applicationName": "login"},
        "actor": {"email": "jane@example.com"},
        "ipAddress": "203.0.113.30",
        "networkInfo": {"ipAsn": [64500], "regionCode": "PT", "subdivisionCode": "PT-11"},
        "events": [
            {
                "type": "login",
                "name": "login_success",
                "parameters": [{"name": "login_type", "value": "google_password"}],
            }
        ],
    }
    row = ocsf.load_mapping("google_workspace").map_record(record, "t1")
    assert (row["src_endpoint_location_country"], row["src_endpoint_asn"]) == ("PT", "64500")
