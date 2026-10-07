"""The dependency budget and licence checks fail where they should (Phase 0 CI)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from scripts import check_dependency_budget as budget
from scripts.check_licenses import permitted

DEPS = tomllib.loads(Path("pyproject.toml").read_text())["project"]["dependencies"]
CORE = [budget.name_of(d) for d in DEPS]


def test_permissive_licences_pass():
    assert permitted("x", "MIT")
    assert permitted("x", "Apache-2.0 OR BSD-3-Clause")
    assert permitted("x", "MIT AND (Apache-2.0 OR BSD-2-Clause)")


def test_copyleft_and_unrecognised_licences_fail():
    for licence in (
        "GPL-2.0-only",
        "GPL-2.0",
        "AGPL-3.0-only",
        "LGPL-3.0-only",
        "",
        "MIT License",
        "LicenseRef-Proprietary",
        "GPL-2.0-only AND (MIT OR BSD-3-Clause)",
    ):
        assert not permitted("x", licence), licence
    assert permitted("x", "GPL-2.0-only OR MIT")  # the recipient may choose MIT


def test_a_reviewed_exception_holds_only_for_the_licence_reviewed():
    assert permitted("psycopg", "LGPL-3.0-only")
    assert not permitted("psycopg", "GPL-3.0-only")


def test_the_installed_runtime_passes_both_checks():
    pulled = budget.closure(DEPS)
    assert "pydantic" in pulled  # through mcp
    assert budget.transitive_problems(CORE, DEPS, pulled) == []
    assert budget.denied_imports() == []


def test_a_new_transitive_package_fails_until_reviewed():
    pulled = budget.closure(DEPS) | {"left-pad": {"httpx"}}
    [problem] = budget.transitive_problems(CORE, DEPS, pulled)
    assert "new transitive dependency 'left-pad' (via httpx)" in problem


def test_pydantic_through_anything_but_mcp_fails(monkeypatch):
    real = budget.closure

    def httpx_needs_pydantic(reqs):
        found = real(reqs)
        if any(budget.name_of(r) == "httpx" for r in reqs):
            found.setdefault("pydantic", set()).add("httpx")
        return found

    monkeypatch.setattr(budget, "closure", httpx_needs_pydantic)
    problems = budget.transitive_problems(CORE, DEPS, budget.closure(DEPS))
    assert any("denied package 'pydantic'" in p for p in problems)


def test_shoc_importing_a_denied_package_fails(tmp_path):
    (tmp_path / "m.py").write_text("import os\nfrom pydantic import BaseModel\n")
    [hit] = budget.denied_imports(tmp_path)
    assert hit.endswith("m.py:2 imports pydantic")
