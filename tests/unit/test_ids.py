"""Stored ids keep their form: they are database keys, so one helper may not move them."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from shoc.ids import make_id

WHEN = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _old(prefix: str, blob: str, length: int = 20) -> str:
    """How every site built its id before `make_id`."""
    return prefix + hashlib.sha256(blob.encode()).hexdigest()[:length]


def test_each_id_is_the_one_stored_before():
    from shoc.agents import detection_engineer
    from shoc.cases import actions, engine, playbooks

    assert engine.make_uid("t1", "user:alice@example.com", "2026-10-01") == _old(
        "CASE-", "t1|user:alice@example.com|2026-10-01"
    )
    assert actions.make_uid("t1", "okta.suspend_user", "alice", None) == _old(
        "ACT-", "t1|okta.suspend_user|alice|"
    )
    assert playbooks.run_uid("t1", "contain_leaked_cloud_key", "CASE-1") == _old(
        "RUN-", "t1|contain_leaked_cloud_key|CASE-1"
    )
    assert detection_engineer.item_uid("t1", "defect", "aws_access_key_created") == _old(
        "DBL-", "t1|defect|aws_access_key_created"
    )
    assert make_id("POS-", "t1", f"{WHEN:%Y-%m-%dT%H}") == _old("POS-", "t1|2026-10-01T12")


def test_a_finding_uid_is_24_characters_after_its_prefix():
    """Rules and indicator matches share it, so one finding never gets two dedup keys."""
    from shoc.detect.engine import finding_uid

    uid = finding_uid("t1", "aws_access_key_created", "key:AKIAEXAMPLE", WHEN)
    assert uid == _old("F-", f"t1|aws_access_key_created|key:AKIAEXAMPLE|{WHEN.isoformat()}", 24)
    assert len(uid) == 2 + 24
