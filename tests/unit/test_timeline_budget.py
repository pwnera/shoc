"""timeline.build binds no more values than the store accepts (STO-3, D250)."""

from __future__ import annotations

from shoc.capabilities.timeline import PIVOTS, _match
from shoc.store import sql


def test_the_pivots_stay_within_the_budget_however_many_entities_a_case_has():
    entities = [f"{kind}:v{i}" for kind in PIVOTS for i in range(60)]
    params: dict = {}
    budget = sql.max_params("databricks") - 40 - 40 - 3  # products, cited, tenant and window
    terms = _match(entities, params, budget)
    assert len(params) == budget, "every value the budget allows is still a pivot"
    assert sum(sql.placeholders(t) for t in terms) == len(params)


def test_each_kind_still_takes_at_most_fifty_values():
    params: dict = {}
    _match([f"user:u{i}" for i in range(60)], params, 10_000)
    assert len(params) == 50


def test_a_sign_in_session_is_a_pivot():
    """Okta's and Entra's session ids are typed `session:`, not `key:` (hunt-23)."""
    params: dict = {}
    assert _match(["session:102abcSESSION"], params, 100) == ["actor_session_uid IN (:p0)"]
    assert params == {"p0": "102abcSESSION"}


def test_a_spent_budget_binds_no_pivot():
    params: dict = {}
    assert _match(["user:alice", "ip:203.0.113.7"], params, -5) == []
    assert params == {}


def test_the_statement_build_sends_stays_within_the_databricks_budget(monkeypatch):
    """The arithmetic in build and the values _read adds must agree."""
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace
    from typing import Any

    from shoc.capabilities import timeline
    from shoc.store.base import QueryResult

    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    events = [
        {
            "event_uid": f"e{i}",
            "time": t0 + timedelta(minutes=i),
            "metadata_product": f"product-{i % 3}",
        }
        for i in range(40)
    ]
    entities = [f"{kind}:v{i}" for kind in PIVOTS for i in range(60)]
    monkeypatch.setattr(timeline, "_cited", lambda ctx, case_uid: (events, entities))
    sent: list = []

    class Store:
        dialect = "databricks"

        def query(self, statement, params, limit):
            sent.append((statement, params))
            return QueryResult(rows=[], sql=statement)

    ctx: Any = SimpleNamespace(tenant_id="t1", store=Store())
    timeline.build.fn(ctx, timeline.BuildInput(case_uid="c1"))
    [(statement, params)] = sent
    assert sql.placeholders(statement) <= sql.max_params("databricks")
    assert sql.placeholders(statement) == len(params), "every bound value is used once"
