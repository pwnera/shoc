"""memory.add_fact reads expires_at as every other capability reads a time (AGT-4)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shoc.capabilities import cases
from shoc.capabilities.registry import Caller, Context
from shoc.errors import ValidationError


@pytest.fixture
def stored(monkeypatch) -> list:
    kept: list = []

    def add(conn, tenant_id, body, subject, kind, source, expires):
        kept.append(expires)
        return "M-1"

    monkeypatch.setattr(cases.memory_store, "add", add)
    return kept


def _add(expires_at: str):
    ctx = Context(tenant_id="t1", caller=Caller())
    ctx._db = object()
    return cases.add_fact.fn(ctx, cases.MemoryFact(body="A fact", expires_at=expires_at))


def test_a_time_without_an_offset_is_utc(stored):
    _add("2026-10-01T00:00")
    assert stored == [datetime(2026, 10, 1, tzinfo=UTC)]


def test_a_time_that_does_not_parse_is_the_callers_mistake(stored):
    with pytest.raises(ValidationError):
        _add("tomorrow")
    assert not stored


def test_no_expiry_stays_none(stored):
    _add("")
    assert stored == [None]
