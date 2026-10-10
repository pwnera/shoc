"""A query's row limit reaches the store as SQL (STO-1, D162)."""

from __future__ import annotations

import pytest

from shoc.store.sql import PARAM_STYLE, prepare, translate

DIALECTS = sorted(PARAM_STYLE)


@pytest.mark.parametrize("dialect", DIALECTS)
def test_a_select_without_a_limit_gets_one(dialect):
    sql = "SELECT event_uid FROM ocsf_events WHERE tenant_id = :t ORDER BY time DESC"
    assert translate(sql, dialect, 101).endswith("LIMIT 101")


@pytest.mark.parametrize("dialect", DIALECTS)
def test_a_lower_limit_the_caller_wrote_stays(dialect):
    out = translate("SELECT event_uid FROM ocsf_events LIMIT 5", dialect, 101)
    assert "LIMIT 5" in out and "101" not in out


def test_a_higher_limit_is_lowered_and_a_bound_one_stays():
    assert translate("SELECT a FROM ocsf_events LIMIT 5000", "postgres", 101).endswith("LIMIT 101")
    sql, args = prepare("SELECT a FROM ocsf_events LIMIT :n", {"n": 7}, "postgres", 101)
    assert sql.count("LIMIT") == 1 and args == {"n": 7}


def test_an_aggregate_is_capped_and_a_union_is_left_alone():
    grouped = "SELECT metadata_product, COUNT(*) AS n FROM ocsf_events GROUP BY metadata_product"
    assert translate(grouped, "databricks", 201).endswith("LIMIT 201")
    union = "SELECT a FROM ocsf_events UNION ALL SELECT b FROM ocsf_events"
    assert "LIMIT" not in translate(union, "databricks", 10)


def test_without_a_limit_nothing_is_added():
    assert "LIMIT" not in translate("SELECT a FROM ocsf_events", "snowflake")
