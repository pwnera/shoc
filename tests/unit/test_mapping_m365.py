"""Office 365 record types land in the OCSF class their RecordType calls for (ING-3)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES

RECORDS = json.loads((FIXTURES / "mappings" / "m365.json").read_text())


def row(operation: str) -> dict[str, Any]:
    record = next(r for r in RECORDS if r["Operation"] == operation)
    return ocsf.load_mapping("m365").map_record(record, "t1")


@pytest.mark.parametrize(
    ("operation", "class_uid", "activity_id"),
    [
        ("UserLoggedIn", 3002, 1),
        ("Add member to role.", 3005, 1),
        ("Update group.", 3006, 99),
        ("SendAs", 4009, 1),
        ("TIMailData", 4009, 2),
        ("TIUrlClickData", 4002, 3),
        ("FileDownloaded", 6001, 2),
        ("SharingSet", 6001, 8),
        ("SearchQueryPerformed", 6001, 5),
        ("MailItemsAccessed", 6003, 2),
        ("AlertTriggered", 2004, 1),
        ("AlertEntityGenerated", 2004, 2),
        ("FileMalwareDetected", 2004, 1),
    ],
)
def test_record_type_picks_the_class(operation, class_uid, activity_id):
    mapped = row(operation)
    assert (mapped["class_uid"], mapped["activity_id"]) == (class_uid, activity_id)
    assert mapped["type_uid"] == class_uid * 100 + activity_id


def test_a_failed_sign_in_fails_whatever_result_status_says():
    # UserLoginFailed records carry ResultStatus "Success": the status of the
    # audit write, not of the sign-in.
    mapped = row("UserLoginFailed")
    assert mapped["status"] == "Failure" and mapped["status_code"] == "500121"


def test_a_compliance_cmdlet_that_errored_failed():
    record = next(r for r in RECORDS if r["Operation"] == "New-InboxRule")
    mapped = ocsf.load_mapping("m365").map_record({**record, "ResultStatus": "Error"}, "t1")
    assert mapped["status"] == "Failure"


def test_alert_severity_comes_from_the_record():
    assert row("AlertTriggered")["severity_id"] == 1  # Severity: Informational
    assert row("MCAS_ALERT_ANUBIS_DETECTION_VELOCITY")["severity_id"] == 3  # AlertSeverity: Medium


def test_a_mailbox_rule_is_an_api_call_worth_a_look():
    mapped = row("New-InboxRule")
    assert (mapped["class_uid"], mapped["activity_id"], mapped["severity_id"]) == (6003, 1, 3)


def test_a_sign_in_names_its_user_agent_and_application():
    mapped = row("UserLoggedIn")
    assert mapped["http_user_agent"].startswith("Mozilla/5.0 (X11; Linux x86_64)")
    assert mapped["actor_invoked_by"] == "00000000-0052-4052-8052-000000000052"
