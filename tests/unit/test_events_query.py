"""The explorer's query builder: what a one-box search compiles to (STO-2)."""

from __future__ import annotations

import pytest

from shoc.capabilities.events import (
    EventQuery,
    SummarizeInput,
    build_query,
    build_summary,
    parse_terms,
)
from shoc.errors import ValidationError
from shoc.store import sql as dialect


def terms(text: str) -> tuple[list[str], dict]:
    params: dict = {}
    return parse_terms(text, params), params


def test_a_bare_word_searches_the_fields_that_identify_something():
    where, params = terms("getsecretvalue")
    assert where == [
        "(LOWER(message) LIKE :q0 OR LOWER(api_operation) LIKE :q0 "
        "OR LOWER(actor_user_name) LIKE :q0 OR LOWER(src_endpoint_ip) LIKE :q0 "
        "OR LOWER(resource_uid) LIKE :q0)"
    ]
    assert params == {"q0": "%getsecretvalue%"}


def test_an_ocsf_path_becomes_its_column():
    where, params = terms("actor.user.name=Alice")
    assert where == ["LOWER(actor_user_name) = :q0"]
    assert params == {"q0": "alice"}


def test_a_source_path_reaches_into_the_raw_record():
    where, _ = terms("raw.debugContext.debugData.dtHash~ab12")
    assert where == ["LOWER(JSON_EXTRACT_SCALAR(raw, '$.debugContext.debugData.dtHash')) LIKE :q0"]


def test_an_integer_column_is_compared_as_a_number():
    where, params = terms("api.response.code>=400")
    assert where == ["api_response_code >= :q0"]
    assert params == {"q0": 400}


def test_negation_and_quoting():
    where, params = terms("status!=Success message~'access denied'")
    assert where == ["LOWER(status) <> :q0", "LOWER(message) LIKE :q1"]
    assert params == {"q0": "success", "q1": "%access denied%"}


def test_an_unknown_field_is_rejected_rather_than_ignored():
    with pytest.raises(ValidationError, match=r"unknown field 'actor\.nam'"):
        terms("actor.nam=alice")


@pytest.mark.parametrize(
    "text",
    [
        "actor.user.name='; DROP TABLE ocsf_events --'",
        "raw.a');DELETE FROM ocsf_events WHERE 1=1--=x",
        "message~%' OR '1'='1",
    ],
)
def test_no_term_can_close_the_statement(text):
    try:
        where, params = terms(text)
    except ValidationError:
        return
    clauses = " AND ".join(where)
    for danger in (";", "--", "DROP", "DELETE", "OR '1'"):
        assert danger not in clauses, clauses
    assert all(isinstance(value, (str, int)) for value in params.values())


def test_the_row_query_can_return_the_whole_event():
    sql, params, limit = build_query(EventQuery(q="okta", include_raw=True, limit=50), "t1")
    assert "unmapped, raw, ingested_at FROM ocsf_events" in sql
    assert sql.endswith("ORDER BY time DESC LIMIT 50")
    assert params["q0"] == "%okta%"
    assert limit == 50


def test_the_default_row_stays_the_narrow_column_set():
    sql, _, _ = build_query(EventQuery(), "t1")
    assert " raw," not in sql


def test_citations_still_bypass_the_window():
    sql, params, _ = build_query(EventQuery(event_uids=["e1", "e2"]), "t1")
    assert "event_uid IN (:u0, :u1)" in sql
    assert "window_start" not in params


@pytest.mark.parametrize(
    ("since", "bucket"),
    [("-30m", "minute"), ("-24h", "hour"), ("-30d", "day")],
)
def test_the_histogram_bucket_fits_the_window(since, bucket):
    sql, _, _, used = build_summary(SummarizeInput(since=since), "t1")
    assert used == bucket
    assert f"DATE_TRUNC('{bucket}', time) AS group_key" in sql
    assert sql.endswith("ORDER BY group_key LIMIT 50")


def test_grouping_by_a_field_ranks_the_top_values():
    sql, _, _, used = build_summary(SummarizeInput(by="metadata.product.name", limit=5), "t1")
    assert used == ""
    assert "metadata_product AS group_key" in sql
    assert sql.endswith("GROUP BY metadata_product ORDER BY n DESC LIMIT 5")


@pytest.mark.parametrize("dialect_name", ["postgres", "databricks", "snowflake"])
def test_both_queries_translate_to_every_backend(dialect_name):
    row_sql, _, _ = build_query(
        EventQuery(q="actor.user.name=alice denied", include_raw=True), "t1"
    )
    hist_sql, _, _, _ = build_summary(SummarizeInput(since="-7d", q="status=Failure"), "t1")
    for canonical in (row_sql, hist_sql):
        assert dialect.translate(canonical, dialect_name)
