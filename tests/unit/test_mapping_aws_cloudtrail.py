"""CloudTrail classes that a reader would not guess from the event alone (ING-3)."""

from __future__ import annotations

from shoc.ingest import ocsf


def _row(**record):
    return ocsf.load_mapping("aws_cloudtrail").map_record({"eventID": "ct", **record}, "t1")


def test_a_failed_console_sign_in_is_a_failure_and_not_a_missing_mfa():
    row = _row(
        eventType="AwsConsoleSignIn",
        eventName="ConsoleLogin",
        responseElements={"ConsoleLogin": "Failure"},
        additionalEventData={"MFAUsed": "No"},
    )
    assert (row["class_uid"], row["status"]) == (3002, "Failure")
    assert row["status_code"] != "no_mfa"


def test_a_service_name_in_source_ip_does_not_land_in_the_ip_column():
    row = _row(
        eventName="AssumeRole",
        eventSource="sts.amazonaws.com",
        sourceIPAddress="lambda.amazonaws.com",
        userIdentity={"type": "AWSService", "invokedBy": "lambda.amazonaws.com"},
    )
    assert row["class_uid"] == 3002 and row["activity_name"] == "Authentication Ticket"
    assert row["src_endpoint_ip"] is None
    assert row["actor_invoked_by"] == "lambda.amazonaws.com"


def test_an_insight_is_a_detection_finding():
    row = _row(
        eventType="AwsCloudTrailInsight",
        recipientAccountId="111111111111",
        insightDetails={
            "state": "Start",
            "eventName": "GetBucketPolicy",
            "eventSource": "s3.amazonaws.com",
        },
    )
    assert row["class_uid"] == 2004 and row["api_operation"] == "GetBucketPolicy"
