"""GitHub webhook events that have no audit-log twin (ING-2, ING-3)."""

from __future__ import annotations

from shoc.ingest import ocsf


def _row(event, action="", **fields):
    record = {
        "action": f"{event}.{action}".strip("."),
        "repo": "example-org/example-app",
        "webhook": {"event": event, "action": action, "delivery": "d"},
        **fields,
    }
    return ocsf.load_mapping("github").map_record(record, "t1")


def test_a_push_names_its_ref_and_a_force_push_stands_out():
    row = _row("push", ref="refs/heads/main", forced=False, compare="https://github.com/c")
    assert (row["class_uid"], row["activity_name"], row["severity_id"]) == (6003, "Update", 1)
    assert row["message"] == "refs/heads/main"
    assert row["http_request_url"] == "https://github.com/c"
    assert _row("push", ref="refs/heads/main", forced=True)["severity_id"] == 3
    assert _row("push", ref="refs/heads/old", deleted=True)["activity_name"] == "Delete"


def test_a_workflow_run_is_a_scheduled_job_with_its_conclusion():
    run = {"name": "Deploy", "path": ".github/workflows/deploy.yml", "conclusion": "failure"}
    row = _row("workflow_run", "completed", workflow_run=run)
    assert (row["class_uid"], row["activity_name"]) == (1006, "End")
    assert (row["status"], row["status_code"]) == ("Failure", "failure")
    assert row["file_path"] == ".github/workflows/deploy.yml"
    assert _row("workflow_run", "requested", workflow_run=run)["activity_name"] == "Create"


def test_only_a_self_hosted_runner_becomes_a_host():
    hosted = {"workflow_name": "CI", "labels": ["ubuntu-latest"], "runner_name": "GitHub Actions 7"}
    own = {**hosted, "labels": ["self-hosted", "linux"], "runner_name": "build-01"}
    assert _row("workflow_job", "in_progress", workflow_job=hosted)["device_hostname"] is None
    assert _row("workflow_job", "in_progress", workflow_job=own)["device_hostname"] == "build-01"


def test_a_dependabot_alert_is_a_vulnerability_finding_at_the_advisory_severity():
    alert = {
        "state": "open",
        "security_advisory": {"summary": "s", "severity": "critical"},
        "dependency": {"manifest_path": "package-lock.json"},
    }
    row = _row("dependabot_alert", "created", alert=alert)
    assert (row["class_uid"], row["activity_name"], row["severity_id"]) == (2002, "Create", 5)
    assert row["file_path"] == "package-lock.json"
    fixed = _row("dependabot_alert", "fixed", alert={**alert, "state": "fixed"})
    assert (fixed["activity_name"], fixed["severity_id"]) == ("Close", 1)
