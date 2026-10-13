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
    "live_tenants",
    "load_fixture",
    "malicious_case",
]


def malicious_case(conn: Any, tenant_id: str, scenario: str, store: Any) -> str:
    """Replay an eval scenario into the store under test and rule its first case
    malicious, with citations. Without the store, replay would open the backend
    SHOC_BACKEND names, not the one the test is parametrised over."""
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
    behind one; the runner's waiting is exercised on this one instead. Its steps
    read the push-fatigue finding's user: `entity.user` is every account the
    spray tried, and names the first of them (RFC 0026).
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
                    "params": {"user": "{{ rule.okta_mfa_push_fatigue.user }}"},
                },
                {
                    "name": "page the on-call engineer",
                    "action": "notify.page",
                    "params": {"summary": "{{ case.title }}", "severity": "critical"},
                },
                {
                    "name": "suspend the account",
                    "action": "okta.suspend_user",
                    "params": {"user": "{{ rule.okta_mfa_push_fatigue.user }}"},
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
    """Expand and map fixture records, each through its own `_source` when it names one.

    A record maps to every row it holds, as ingest stores it: each event of a
    Workspace activity is a row of its own (ING-3).
    """
    from shoc.ingest import ocsf

    rows: list[dict[str, Any]] = []
    for name in dict.fromkeys(r.get(SOURCE_KEY, source) for r in records):
        group = [
            {k: v for k, v in r.items() if k != SOURCE_KEY}
            for r in records
            if r.get(SOURCE_KEY, source) == name
        ]
        mapping = ocsf.load_mapping(name)
        rows += [row for r in expand(group, name, now) for row in mapping.map_records(r, tenant_id)]
    return rows


def dsn() -> str:
    return os.environ.get("SHOC_DSN", "")


# A test session's tenant and an eval run's; SHOC_TEST_TENANT names a fixed one.
TEST_TENANTS = ("test", "eval")


def live_tenants(conn: Any) -> list[str]:
    """Tenants a deployment uses: not a test or eval run's, and holding a
    configured source or a finding. `shoc migrate` alone registers an empty one.
    The worker tests empty the shared queue, so a database with one is no
    place for the suite."""
    from shoc.db.pool import fetch_all, fetch_one

    migrated = fetch_one(conn, "SELECT to_regclass('shoc.tenants') IS NOT NULL AS ok")
    if not (migrated and migrated["ok"]):
        return []
    used = fetch_all(
        conn,
        """SELECT tenant_id FROM shoc.tenants t
           WHERE EXISTS (SELECT 1 FROM shoc.connector_config c WHERE c.tenant_id = t.tenant_id)
              OR EXISTS (SELECT 1 FROM shoc.findings f WHERE f.tenant_id = t.tenant_id)""",
    )
    fixed = os.environ.get("SHOC_TEST_TENANT")
    ours = (*TEST_TENANTS, fixed) if fixed else TEST_TENANTS
    return sorted(r["tenant_id"] for r in used if not r["tenant_id"].startswith(ours))


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


class Counting:
    """A store that keeps the canonical SQL of every statement it is sent."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.sent: list[str] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)

    def query(self, canonical_sql: str, params: Any = None, limit: int = 1000) -> Any:
        self.sent.append(canonical_sql)
        return self.store.query(canonical_sql, params, limit)
