from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import pytest

from shoc.errors import ValidationError
from shoc.jsonschema import coerce_dataclass, dataclass_schema


@dataclass
class Inner:
    x: int = 1


@dataclass
class Sample:
    """A sample input."""

    name: str
    mode: Literal["a", "b"] = "a"
    count: int = 3
    tags: list[str] = field(default_factory=list)
    inner: Inner | None = None


def test_schema_marks_only_defaultless_fields_required():
    schema = dataclass_schema(Sample)
    assert schema["required"] == ["name"]
    assert schema["properties"]["mode"]["enum"] == ["a", "b"]
    assert schema["properties"]["tags"] == {"type": "array", "items": {"type": "string"}}
    assert schema["additionalProperties"] is False


def test_coerce_fills_defaults_and_nested_dataclasses():
    out = coerce_dataclass(Sample, {"name": "n", "inner": {"x": 7}})
    assert out.count == 3 and out.inner.x == 7


@pytest.mark.parametrize(
    "payload, message",
    [
        ({}, "missing required field"),
        ({"name": 1}, "expected a string"),
        ({"name": "n", "mode": "c"}, "expected one of"),
        ({"name": "n", "nope": 1}, "unknown field"),
        ({"name": "n", "count": True}, "expected an integer"),
    ],
)
def test_coerce_rejects_bad_input(payload, message):
    with pytest.raises(ValidationError) as exc:
        coerce_dataclass(Sample, payload)
    assert message in str(exc.value)


def test_database_types_survive_the_envelope():
    """Postgres hands back Decimal, date and UUID; json.dumps does not take them."""
    import json
    from datetime import UTC, date, datetime, timedelta
    from decimal import Decimal
    from uuid import UUID

    from shoc.jsonschema import to_json

    payload = {
        "cost": Decimal("1.2345"),
        "fires": Decimal("42"),  # sum() over bigint comes back as numeric
        "day": date(2026, 9, 24),
        "at": datetime(2026, 9, 24, 12, tzinfo=UTC),
        "age": timedelta(minutes=90),
        "id": UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
        "blob": b"\x00\xff",
        "nested": [{"also": Decimal("0.5")}],
    }
    out = to_json(payload)
    json.dumps(out)  # the point of the test: this must not raise
    assert out["cost"] == 1.2345
    assert out["fires"] == 42 and isinstance(out["fires"], int)
    assert out["day"] == "2026-09-24"
    assert out["age"] == 5400.0
    assert out["blob"] == "00ff"
    assert out["nested"][0]["also"] == 0.5
