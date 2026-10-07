"""Fixture helpers shared by the rule tests, the conformance suite and the evals."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from shoc.ingest.replay import ID_FIELD, TIME_FIELD, expand

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

# A fixture record may name another source than its product's with `_source`:
# one endpoint rule reads Falcon, Defender and SentinelOne telemetry.
SOURCE_KEY = "_source"

__all__ = [
    "FIXTURES",
    "ID_FIELD",
    "TIME_FIELD",
    "audit_seq",
    "audit_trail",
    "dsn",
    "expand",
    "fixture_rows",
    "fixture_source",
    "load_fixture",
    "malicious_case",
]


def malicious_case(conn: Any, tenant_id: str, scenario: str, store: Any = None) -> str:
    """Replay an eval scenario and rule its first case malicious, with citations."""
    from evals.run import SCENARIOS, replay
    from shoc.cases import engine
    from shoc.db.pool import fetch_one

    replay(SCENARIOS / scenario, tenant_id=tenant_id, store=store)
    row = fetch_one(
        conn,
        """SELECT c.case_uid, f.event_uids FROM shoc.cases c
           JOIN shoc.findings f ON f.case_uid = c.case_uid AND f.tenant_id = c.tenant_id
           WHERE c.tenant_id = %s LIMIT 1""",
        (tenant_id,),
    )
    assert row, f"{scenario} must open a case"
    engine.set_verdict(
        conn, tenant_id, row["case_uid"], "malicious", 0.95, scenario, list(row["event_uids"])
    )
    return str(row["case_uid"])


def a_step_that_waits(monkeypatch: Any) -> str:
    """Install a playbook whose last step must wait for a human, and return its id.

    The shipped playbooks keep their human steps optional, so a page never waits
    behind one; the runner's waiting is exercised on this one instead.
    """
    from shoc.cases import playbooks

    book = playbooks.Playbook.from_dict(
        {
            "id": "revoke_page_then_suspend",
            "title": "Revoke, page, then suspend",
            "rules": ["okta_mfa_push_fatigue"],
            "steps": [
                {
                    "name": "revoke the user's sessions",
                    "action": "okta.revoke_sessions",
                    "params": {"user": "{{ entity.user }}"},
                },
                {
                    "name": "page the on-call engineer",
                    "action": "notify.page",
                    "params": {"summary": "{{ case.title }}", "severity": "critical"},
                },
                {
                    "name": "suspend the account",
                    "action": "okta.suspend_user",
                    "params": {"user": "{{ entity.user }}"},
                },
            ],
        }
    )
    real = playbooks.get
    monkeypatch.setattr(
        playbooks, "get", lambda pid, *rest: book if pid == book.id else real(pid, *rest)
    )
    return book.id


def load_fixture(rule_id: str, kind: str) -> list[dict[str, Any]]:
    path = FIXTURES / "rules" / rule_id / f"{kind}.json"
    return json.loads(path.read_text())


def fixture_source(rule: Any) -> str:
    """Rules declare a product; fixtures are raw records for its mapping (ING-4)."""
    from shoc.ingest import ocsf

    return (
        ocsf.source_for(rule.logsource.get("product", "aws"), rule.logsource.get("service", ""))
        or "aws_cloudtrail"
    )


def fixture_rows(
    records: list[dict[str, Any]], source: str, tenant_id: str, now: Any
) -> list[dict[str, Any]]:
    """Expand and map fixture records, each through its own `_source` when it names one."""
    from shoc.ingest import ocsf

    rows: list[dict[str, Any]] = []
    for name in dict.fromkeys(r.get(SOURCE_KEY, source) for r in records):
        group = [
            {k: v for k, v in r.items() if k != SOURCE_KEY}
            for r in records
            if r.get(SOURCE_KEY, source) == name
        ]
        mapping = ocsf.load_mapping(name)
        rows += [mapping.map_record(r, tenant_id) for r in expand(group, name, now)]
    return rows


def dsn() -> str:
    return os.environ.get("SHOC_DSN", "")


def audit_seq(conn: Any, tenant_id: str) -> int:
    """The last audit row's seq for a tenant, to read what a test adds after it."""
    from shoc.db.pool import fetch_one

    row = fetch_one(
        conn,
        "SELECT coalesce(max(seq), 0) AS seq FROM shoc.audit_log WHERE tenant_id = %s",
        (tenant_id,),
    )
    return int(row["seq"]) if row else 0


def audit_trail(conn: Any, tenant_id: str, after: int) -> list[tuple[str, str]]:
    """(capability, principal) of every action row in the audit chain after `after`."""
    from shoc.db.pool import fetch_all

    rows = fetch_all(
        conn,
        """SELECT capability, principal_kind || ':' || principal_id AS who
           FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s AND capability LIKE 'action.%%'
           ORDER BY seq""",
        (tenant_id, after),
    )
    return [(r["capability"], r["who"]) for r in rows]
