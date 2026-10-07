"""The public contract is snapshotted now and freezes at v0.4 (D14, D24, docs/contract.md)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.snapshot_contract import snapshot
from shoc.capabilities.registry import all_capabilities

SNAPSHOT = Path("contract/v1.json")


@pytest.fixture(scope="module")
def frozen():
    assert SNAPSHOT.exists(), "run python scripts/snapshot_contract.py"
    return json.loads(SNAPSHOT.read_text())


def test_the_snapshot_matches_the_registry(frozen):
    current = snapshot()
    missing = sorted(set(frozen["capabilities"]) - set(current["capabilities"]))
    assert not missing, (
        f"capabilities removed from the contract: {missing}. "
        "That is a major release; if it is intended, re-run scripts/snapshot_contract.py."
    )


def test_no_capability_loses_a_field_or_gains_a_required_one(frozen):
    current = snapshot()["capabilities"]
    for name, was in frozen["capabilities"].items():
        now = current.get(name)
        if now is None:
            continue
        old_fields = set(was["input_schema"].get("properties", {}))
        new_fields = set(now["input_schema"].get("properties", {}))
        assert old_fields <= new_fields, f"{name} lost input field(s): {old_fields - new_fields}"
        old_required = set(was["input_schema"].get("required", []))
        new_required = set(now["input_schema"].get("required", []))
        assert new_required <= old_required, (
            f"{name} made field(s) required that were optional: {new_required - old_required}"
        )


def _fields(schema: dict, prefix: str = "") -> set[str]:
    """Every field path in a JSON Schema, nested objects and list items included."""
    out: set[str] = set()
    for key, sub in schema.get("properties", {}).items():
        out |= {prefix + key} | _fields(sub, f"{prefix}{key}.")
    for sub in [schema.get("items"), schema.get("additionalProperties"), *schema.get("anyOf", [])]:
        if isinstance(sub, dict):
            out |= _fields(sub, prefix)
    return out


def test_no_capability_loses_an_output_field(frozen):
    current = snapshot()["capabilities"]
    assert all("output_schema" in c for c in current.values()), "responses are in the contract"
    for name, was in frozen["capabilities"].items():
        now = current.get(name)
        if now is None:
            continue
        lost = _fields(was.get("output_schema", {})) - _fields(now["output_schema"])
        assert not lost, f"{name} lost output field(s): {sorted(lost)}"


def test_event_types_are_read_from_the_code_and_only_grow(frozen):
    current = set(snapshot()["event_types"])
    published_elsewhere = {
        "health.source.quality",  # an OpsAlert kind
        "health.action.stuck",
        "health.audit.broken",  # a literal alert in the worker
        "source.needs_credentials",  # the Integrator
    }
    assert published_elsewhere <= current
    removed = set(frozen["event_types"]) - current
    assert not removed, f"event types no longer published: {sorted(removed)}"


def test_surfaces_keep_their_names(frozen):
    current = snapshot()["capabilities"]
    for name, was in frozen["capabilities"].items():
        now = current.get(name)
        if now is None:
            continue
        assert now["rest"] == was["rest"], f"{name}: REST path changed"
        assert now["mcp_tool"] == was["mcp_tool"], f"{name}: MCP tool name changed"


def test_autonomy_never_loosens(frozen):
    order = {"L0": 0, "L1": 1, "L2": 2}
    current = snapshot()["capabilities"]
    for name, was in frozen["capabilities"].items():
        now = current.get(name)
        if now is None:
            continue
        assert order[now["autonomy"]] >= order[was["autonomy"]], (
            f"{name}: autonomy dropped from {was['autonomy']} to {now['autonomy']}"
        )
        if was["principals"] == ["human"]:
            assert now["principals"] == ["human"], f"{name}: was human-only and no longer is"


def test_the_ocsf_layout_only_grows(frozen):
    current = {c["name"]: c["type"] for c in snapshot()["ocsf_columns"]}
    for column in frozen["ocsf_columns"]:
        assert column["name"] in current, f"OCSF column removed: {column['name']}"
        assert current[column["name"]] == column["type"], (
            f"OCSF column {column['name']} changed type"
        )


def test_the_event_store_interface_is_stable(frozen):
    current = set(snapshot()["event_store_interface"])
    assert set(frozen["event_store_interface"]) <= current


def test_every_capability_is_in_the_snapshot(frozen):
    names = {c.name for c in all_capabilities()}
    unlisted = names - set(frozen["capabilities"])
    assert not unlisted, (
        f"new capability(ies) not in the contract snapshot: {sorted(unlisted)}. "
        "Run python scripts/snapshot_contract.py."
    )


def test_the_response_envelope_is_three_keys():
    from shoc.capabilities.registry import Result

    assert set(Result(data={}).to_json()) == {"data", "summary", "citations"}
