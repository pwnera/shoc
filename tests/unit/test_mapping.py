from __future__ import annotations

import json

import pytest

from shoc.ingest import ocsf
from shoc.store import ocsf as layout
from tests.support import expand


def test_cloudtrail_record_maps_to_ocsf():
    mapping = ocsf.load_mapping("aws_cloudtrail")
    record = expand(
        [
            {
                "eventID": "abc",
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "eu-west-1",
                "sourceIPAddress": "203.0.113.10",
                "recipientAccountId": "123456789012",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "deploy-ci",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/deploy-ci",
                },
            }
        ],
        "aws_cloudtrail",
    )[0]
    row = mapping.map_record(record, "t1")
    assert row["class_uid"] == 6003
    assert row["api_operation"] == "GetObject"
    assert row["actor_user_name"] == "deploy-ci"
    assert row["actor_session_uid"] == "AKIAIOSFODNN7EXAMPLE"
    assert row["cloud_region"] == "eu-west-1"
    assert row["activity_name"] == "Read"
    assert row["raw"]["eventName"] == "GetObject"
    assert set(row) == set(layout.COLUMN_NAMES)


def test_failed_call_becomes_a_failure_with_higher_severity():
    mapping = ocsf.load_mapping("aws_cloudtrail")
    record = expand([{"eventName": "GetObject", "errorCode": "AccessDenied"}], "aws_cloudtrail")[0]
    row = mapping.map_record(record, "t1")
    assert row["status"] == "Failure" and row["severity_id"] == 2


def test_okta_and_github_records_map():
    okta_row = ocsf.load_mapping("okta").map_record(
        expand(
            [
                {
                    "uuid": "u1",
                    "eventType": "user.session.start",
                    "actor": {"id": "00u", "alternateId": "jane@example.com"},
                    "client": {"ipAddress": "198.51.100.5"},
                    "outcome": {"result": "FAILURE"},
                }
            ],
            "okta",
        )[0],
        "t1",
    )
    assert okta_row["actor_user_name"] == "jane@example.com"
    assert okta_row["status"] == "Failure"

    gh_row = ocsf.load_mapping("github").map_record(
        expand([{"_document_id": "g1", "action": "repo.access", "actor": "mallory"}], "github")[0],
        "t1",
    )
    assert gh_row["api_operation"] == "repo.access"
    assert gh_row["metadata_product"] == "GitHub Audit Log"


def test_records_without_an_id_get_a_stable_one():
    mapping = ocsf.load_mapping("github")
    record = {"action": "repo.access", "actor": "m", "@timestamp": 1758000000000}
    assert (
        mapping.map_record(record, "t")["event_uid"] == mapping.map_record(record, "t")["event_uid"]
    )


def test_a_wildcard_path_takes_the_first_list_item_that_resolves():
    record = {
        "evidence": [
            {"@odata.type": "deviceEvidence", "mdeDeviceId": "dev-1"},
            {
                "@odata.type": "userEvidence",
                "userAccount": {"userPrincipalName": "marc@example.com"},
            },
        ]
    }
    assert ocsf.dig(record, "evidence[*].userAccount.userPrincipalName") == "marc@example.com"
    assert ocsf.dig(record, "evidence[*].mdeDeviceId") == "dev-1"
    assert ocsf.dig(record, "evidence[*].missing") is None
    assert ocsf.dig({"evidence": []}, "evidence[*].x") is None
    assert ocsf.dig({"a": {"b": [1, 2]}}, "a.b[*]") == 1
    assert ocsf.dig({"a": "text"}, "a[*].b") is None


def test_an_entra_sign_in_maps_from_the_event_hub_envelope_too():
    """A diagnostic-setting export wraps the Graph record in `properties`."""
    mapping = ocsf.load_mapping("entra")
    row = mapping.map_record(
        {
            "time": "2026-09-20T05:10:14.1875602Z",
            "category": "SignInLogs",
            "operationName": "Sign-in activity",
            "resultType": "50126",
            "callerIpAddress": "203.0.113.7",
            "tenantId": "tid-1",
            "properties": {
                "id": "sign-in-1",
                "userPrincipalName": "marc@example.com",
                "userId": "u-1",
                "appDisplayName": "Azure Portal",
                "ipAddress": "203.0.113.7",
                "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
                "location": {"countryOrRegion": "FR"},
            },
        },
        "t1",
    )
    assert row["event_uid"] == "sign-in-1"
    assert row["time"].startswith("2026-09-20T05:10:14")
    assert row["actor_user_name"] == "marc@example.com"
    assert row["src_endpoint_ip"] == "203.0.113.7"
    assert row["src_endpoint_location_country"] == "FR"
    assert row["status"] == "Failure" and row["severity_id"] == 2
    assert row["class_uid"] == 3002


def test_an_object_where_ocsf_wants_text_survives_as_json():
    """GitLab's `details.with` is an object; a TEXT column must still load."""
    row = ocsf.load_mapping("gitlab").map_record(
        {
            "id": 9001,
            "created_at": "2026-09-20T10:00:00.000Z",
            "author_id": 1,
            "entity_type": "Project",
            "details": {
                "author_name": "Dana Ops",
                "with": {"protocol": "http", "action": "git-upload-pack"},
                "entity_path": "acme/platform",
            },
        },
        "t1",
    )
    assert row["api_operation"] == "git-upload-pack"
    assert all(
        not isinstance(value, (dict, list))
        for column, value in row.items()
        if column not in layout.JSON_COLUMNS
    )


def test_a_gitlab_event_is_named_by_its_audit_event_type():
    import json

    from tests.support import FIXTURES

    records = json.loads((FIXTURES / "mappings" / "gitlab.json").read_text())
    rows = [ocsf.load_mapping("gitlab").map_record(r, "t1") for r in records]
    assert [r["api_operation"] for r in rows] == [
        "member_updated",
        "deploy_key_added",
        "member_created",
        "project_access_token_created",
        "protected_branch_removed",
    ]
    assert rows[0]["actor_user_name"] == "dana@example.com"
    assert rows[4]["resource_uid"] == "acme/platform/api" and rows[4]["severity_id"] == 3


def test_a_batch_of_rows_sharing_one_event_uid_is_reported(caplog):
    """A mapping pointed at a repeated field silently discards events (ING-3)."""
    import logging

    from shoc.ingest import batch

    rows = [
        {"event_uid": "REDACTED_GUID", "time": f"2026-09-20T10:00:{n:02d}+00:00"} for n in range(20)
    ]
    with caplog.at_level(logging.WARNING, logger="shoc.ingest.batch"):
        path, count = batch.write_batch(rows)
    path.unlink(missing_ok=True)
    assert count == 20
    assert "distinct event_uid" in caplog.text


def test_unmapped_keeps_the_siblings_of_a_field_the_mapping_read():
    mapping = ocsf.load_mapping("okta")
    row = mapping.map_record(
        {
            "uuid": "u1",
            "published": "2026-01-01T00:00:00.000Z",
            "eventType": "user.session.start",
            "client": {
                "ipAddress": "203.0.113.5",
                "zone": "OffNetwork",
                "device": "Computer",
            },
            "debugContext": {"debugData": {"dtHash": "deadbeef"}},
        },
        "t1",
    )
    # `client.ipAddress` was read; the rest of the block is still visible.
    assert row["unmapped"]["client"] == {"zone": "OffNetwork", "device": "Computer"}
    assert "ipAddress" not in row["unmapped"]["client"]
    assert row["unmapped"]["debugContext"]["debugData"]["dtHash"] == "deadbeef"
    assert row["raw"]["client"]["ipAddress"] == "203.0.113.5"


def test_a_block_the_mapping_read_entirely_leaves_nothing_behind():
    mapping = ocsf.load_mapping("okta")
    row = mapping.map_record(
        {
            "uuid": "u2",
            "published": "2026-01-01T00:00:00.000Z",
            "client": {"ipAddress": "203.0.113.6"},
        },
        "t1",
    )
    assert "client" not in row["unmapped"]


def test_a_keyed_list_is_written_as_an_object_a_rule_can_read_by_name():
    """RFC 0023: no portable JSON path picks a list item by key, so ingest does."""
    from dataclasses import replace

    mapping = replace(
        ocsf.load_mapping("google_workspace"),
        keyed={
            "params": {
                "path": "events[*].parameters",
                "key": "name",
                "value": ["value", "intValue", "boolValue", "multiValue"],
            },
            "deltas": {
                "path": "protoPayload.serviceData.policyDelta.bindingDeltas",
                "key": ["action", "role"],
            },
            "props": {"path": "targetResources[*].modifiedProperties", "key": "displayName"},
        },
    )
    row = mapping.map_record(
        {
            "id": {
                "time": "2026-01-01T00:00:00.000Z",
                "uniqueQualifier": "1",
                "applicationName": "admin",
            },
            "actor": {"email": "admin@example.com"},
            "events": [
                {
                    "name": "CHANGE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Marketplace allow-all"},
                        {"name": "NEW_VALUE", "boolValue": True},
                        {"name": "NEW_VALUE", "value": "ignored: the first item wins"},
                        {"name": "ORG_UNIT_NAME"},
                        {"name": "OAUTH.SCOPES", "multiValue": ["a", "b"]},
                    ],
                }
            ],
            "protoPayload": {
                "serviceData": {
                    "policyDelta": {
                        "bindingDeltas": [
                            {
                                "action": "REMOVE",
                                "role": "roles/owner",
                                "member": "user:old@example.com",
                            },
                            {
                                "action": "ADD",
                                "role": "roles/owner",
                                "member": "user:new@example.org",
                            },
                        ]
                    }
                }
            },
            "targetResources": [
                {
                    "modifiedProperties": [
                        {
                            "displayName": "Role.DisplayName",
                            "oldValue": None,
                            "newValue": '"Global Administrator"',
                        },
                    ]
                }
            ],
        },
        "t1",
    )
    assert row["unmapped"]["params"] == {
        "SETTING_NAME": "Marketplace allow-all",
        "NEW_VALUE": True,
        "OAUTH_SCOPES": ["a", "b"],
    }
    assert row["unmapped"]["deltas"] == {
        "REMOVE": {"roles_owner": {"member": "user:old@example.com"}},
        "ADD": {"roles_owner": {"member": "user:new@example.org"}},
    }
    assert row["unmapped"]["props"]["Role_DisplayName"]["newValue"] == '"Global Administrator"'
    assert layout.column_for("unmapped.params.NEW_VALUE")
    assert layout.column_for("unmapped.props.Role_DisplayName.newValue")


def test_a_keyed_list_needs_a_path_a_key_and_a_plain_alias(tmp_path):
    from shoc.errors import ConfigError

    path = tmp_path / "x.yaml"
    for keyed in ({"a.b": {"path": "p", "key": "k"}}, {"a": {"path": "p"}}):
        path.write_text(json.dumps({"source": "x", "keyed": keyed}))
        with pytest.raises(ConfigError, match="keyed list"):
            ocsf.Mapping.from_file(path)
