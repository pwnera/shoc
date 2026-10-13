"""shoc's own footprint (RFC 0021): the parts that need no database."""

from __future__ import annotations

from shoc.cases import own
from shoc.detect.osint import is_public_address


def test_a_tailnet_address_is_not_the_internet():
    assert not is_public_address("100.64.0.1")
    assert not is_public_address("10.0.0.1")
    assert is_public_address("198.51.100.7"), "documentation ranges stand for the internet here"
    # Log-derived values arrive with whitespace; every caller gets the same answer.
    assert is_public_address(" 198.51.100.7\n")
    assert not is_public_address(" 100.64.0.1 ")


def test_an_entity_key_and_the_account_are_the_same_value():
    assert own.bare("user:alice@example.com") == "alice@example.com"
    assert own.bare("ip:203.0.113.5") == "203.0.113.5"
    assert own.bare("session:102abcSESSION") == "102abcSESSION"
    assert own.bare("https://example.com") == "https://example.com"


def test_scopes_are_read_from_named_parameters_and_keys():
    raw = {
        "events": [
            {
                "parameters": [
                    {"name": "client_id", "value": "1"},
                    {"name": "scope", "multiValue": ["https://mail.google.com/", "openid"]},
                ]
            }
        ],
        "token": {"scopes": "read write"},
    }
    assert own.scopes_of(raw) == {"https://mail.google.com/", "openid", "read", "write"}


def test_the_intake_read_runs_on_bigquery_where_raw_is_json():
    """BigQuery refuses DISTINCT over a JSON column, so no finding would become a case."""
    from shoc.store import sql
    from shoc.store.base import QueryResult

    class Store:
        dialect = "bigquery"

        def __init__(self):
            self.sql = ""

        def query(self, canonical, params, limit):
            self.sql = canonical
            # Newest first, as the read orders them: e1 was updated in place.
            rows = [
                {"event_uid": "e1", "n": 2, "time": "2026-10-01T10:00:00Z"},
                {"event_uid": "e2", "n": 3, "time": "2026-10-01T09:30:00Z"},
                {"event_uid": "e1", "n": 1, "time": "2026-10-01T09:00:00Z"},
            ]
            return QueryResult(rows=rows)

    store = Store()
    events = own._events(store, "t1", ["e1", "e2", "e1"])
    assert [(e["event_uid"], e["n"]) for e in events] == [("e1", 2), ("e2", 3)]
    assert "ORDER BY TIME DESC" in store.sql.upper()
    assert "DISTINCT" not in sql.translate(store.sql, "bigquery").upper()
