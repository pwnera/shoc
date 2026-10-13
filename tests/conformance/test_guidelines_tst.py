"""Checks for the tests-and-simplicity guidelines (TST-G4, TST-G6) that need Postgres."""

from __future__ import annotations

import ast
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from shoc.cases import playbooks
from shoc.db.pool import execute, fetch_all
from shoc.detect import hunts
from shoc.detect import rules as ruleset
from tests.support import ROOT

pytestmark = pytest.mark.postgres


# -- TST-G4: clean and conn's teardown clear every tenant table ---------------
TENANT_TABLES = """
    SELECT c.relname AS name FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid
    WHERE n.nspname = 'shoc' AND a.attname = 'tenant_id' AND NOT a.attisdropped
      AND c.relkind IN ('r', 'p') AND NOT c.relispartition"""
CASCADES = """
    SELECT child.relname AS child, parent.relname AS parent FROM pg_constraint k
    JOIN pg_class child ON child.oid = k.conrelid
    JOIN pg_class parent ON parent.oid = k.confrelid
    JOIN pg_namespace n ON n.oid = child.relnamespace
    WHERE n.nspname = 'shoc' AND k.contype = 'f' AND k.confdeltype = 'c'"""

# Left behind by both on purpose: the session's tenant id is unique, so they harm nothing.
KEPT = {
    "audit_log": "append-only on purpose (SEC-1)",
    "audit_checkpoints": "the audit chain's checkpoint, kept with the chain (SEC-1)",
}
# Left by `clean` alone: conn's teardown removes them at the end of the session.
KEPT_BY_CLEAN = {"tenants": "the session's tenant row, which every test needs"}
KNOWN_UNCLEANED = {
    "api_tokens": "a token one test creates is still there for the next (TST-G4)",
}


def _cleared_by(fixture: str) -> set[str]:
    """The tables a fixture in tests/conftest.py deletes the test tenant's rows from."""
    tree = ast.parse((ROOT / "tests" / "conftest.py").read_text())
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fixture)
    return {
        str(e.value)
        for loop in ast.walk(func)
        if isinstance(loop, ast.For) and isinstance(loop.iter, ast.Tuple | ast.List)
        for e in loop.iter.elts
        if isinstance(e, ast.Constant)
    }


def _with_cascades(conn, cleared: set[str]) -> set[str]:
    """`cleared` and every table an ON DELETE CASCADE empties along with it."""
    edges = [(r["child"], r["parent"]) for r in fetch_all(conn, CASCADES)]
    gone = set(cleared)
    while more := {child for child, parent in edges if parent in gone} - gone:
        gone |= more
    return gone


@pytest.mark.parametrize("fixture", ["clean", "conn"])
def test_clean_empties_every_tenant_table(conn, fixture):
    """TST-G4: clean and conn's teardown clear every shoc table with a tenant_id.

    `push_deliveries` outlived `clean`, so a shared delivery id made a load
    count depend on which test ran first (qa-16).
    """
    tables = {str(r["name"]) for r in fetch_all(conn, TENANT_TABLES)}
    cleared = _cleared_by(fixture)
    assert not cleared - tables, f"{fixture} names tables with no tenant_id: {cleared - tables}"
    kept = {**KEPT, **(KEPT_BY_CLEAN if fixture == "clean" else {})}
    missed = tables - _with_cascades(conn, cleared) - set(kept)
    known = set(KNOWN_UNCLEANED) if fixture == "clean" else set()
    assert not missed - known, (
        f"tests/conftest.py: {fixture} leaves the test tenant's rows in {sorted(missed - known)}"
    )
    assert known <= missed, f"{fixture} clears {sorted(known - missed)} now; take it out of KNOWN"


# -- TST-G6: the merged-content loaders treat a bad row alike ----------------
# Each kind's loader, its merged table and that table's id column; the shipped
# items are content/<kind>/*.yaml.
LOADERS: dict[str, tuple[Callable[..., list[Any]], str, str]] = {
    "rules": (ruleset.load, "merged_rules", "rule_id"),
    "hunts": (hunts.load, "merged_hunts", "pack_id"),
    "playbooks": (playbooks.load, "merged_playbooks", "playbook_id"),
}
KNOWN_UNEVEN = {
    "hunts": "a merged pack with a shipped id is dropped without a reason in `skipped`",
    "playbooks": "load takes no `skipped`; a row it leaves out is only logged",
}


def _merge(conn, table: str, column: str, tenant: str, item_id: str, body: dict) -> None:
    row = {
        "tenant_id": tenant,
        column: item_id,
        "body": json.dumps(body, default=str),
        "merged_by": "agent:test",
        **({"playbook_id": ""} if table == "merged_rules" else {}),
    }
    execute(
        conn,
        f"INSERT INTO shoc.{table} ({', '.join(row)}) VALUES ({', '.join(['%s'] * len(row))})",
        tuple(row.values()),
    )


@pytest.mark.parametrize("kind", sorted(LOADERS))
def test_a_broken_merged_row_leaves_the_shipped_set(kind, conn, config, clean):
    """TST-G6: each merged loader leaves out a broken row and a shipped id, and says why.

    `rules.merged` lacked the skip-a-broken-row guard the hunt and playbook
    loaders had; a fix to one sibling lands on all three.
    """
    load, table, column = LOADERS[kind]
    tenant = config.tenant_id
    shipped = {item.id: item for item in load(config)}
    path = sorted((Path(config.content_dir) / kind).glob("*.yaml"))[0]
    copy = {**yaml.safe_load(path.read_text()), "title": "A merged copy"}
    _merge(conn, table, column, tenant, "test_broken", {"id": "test_broken", "title": "Broken"})
    _merge(conn, table, column, tenant, copy["id"], copy)

    skipped: dict[str, str] = {}
    takes_skipped = "skipped" in inspect.signature(load).parameters
    loaded = load(config, conn, tenant, skipped) if takes_skipped else load(config, conn, tenant)
    by_id = {item.id: item for item in loaded}

    problems = []
    if set(by_id) != set(shipped):
        problems.append(f"loaded {sorted(set(by_id) ^ set(shipped))} beside the shipped set")
    if copy["id"] in by_id and by_id[copy["id"]].title != shipped[copy["id"]].title:
        problems.append(f"the merged copy of {copy['id']} replaced the shipped one")
    if len(loaded) != len(by_id):
        problems.append("an id loaded twice")
    for item_id in ("test_broken", copy["id"]):
        if item_id not in skipped:
            problems.append(f"no reason in `skipped` for {item_id}")
    if kind in KNOWN_UNEVEN:
        assert problems, f"{kind} treats bad rows like its siblings now; take it out of KNOWN"
    else:
        assert not problems, f"{kind}: " + "; ".join(problems)
