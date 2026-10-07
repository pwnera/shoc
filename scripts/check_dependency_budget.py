#!/usr/bin/env python3
"""Fail the build if the core dependency budget is exceeded (principle 3).

Core stays at 8 packages or fewer; starlette and uvicorn share the "web" slot.
Anything on the deny list needs an RFC, not a pull request. The budget covers
what the core pulls in too: every transitive runtime package must be on the
reviewed TRANSITIVE list, a denied package may arrive only through the one
direct dependency named in TOLERATED, and no shoc module may import a denied
package itself. Run from the repo root: python -m scripts.check_dependency_budget
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from packaging.requirements import Requirement  # installed with pytest ([dev])

LIMIT = 8
SHARED_SLOTS = {"starlette": "web", "uvicorn": "web"}
DENIED = {
    "temporal",
    "temporalio",
    "celery",
    "redis",
    "kafka",
    "confluent-kafka",
    "boto3",
    "botocore",
    "neo4j",
    "zep-python",
    "pgvector",
    "langchain",
    "langgraph",
    "crewai",
    "camel-ai",
    "litellm",
    "opa",
    "pysigma",
    "pydantic",
    "sqlalchemy",
    "prometheus-client",
    "minio",
}
# A denied package the core may carry only because the named direct dependency
# needs it. mcp is in the budget on purpose and its SDK is built on pydantic.
TOLERATED = {"pydantic": "mcp"}
# Every package the core pulls in on Linux, reviewed. A new one fails the build
# until someone reads what it is and adds it here.
TRANSITIVE = {
    "annotated-types",
    "anyio",
    "attrs",
    "certifi",
    "cffi",
    "click",
    "h11",
    "httpcore",
    "httpx-sse",
    "idna",
    "jsonschema",
    "jsonschema-specifications",
    "psycopg-binary",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "pydantic-settings",
    "python-dotenv",
    "python-multipart",
    "referencing",
    "rpds-py",
    "sse-starlette",
    "typing-extensions",
    "typing-inspection",
}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def name_of(requirement: str) -> str:
    return norm(re.split(r"[<>=!\[;\s]", requirement.strip(), maxsplit=1)[0])


def closure(requirements: list[str]) -> dict[str, set[str]]:
    """Installed packages these requirements pull in, each with who pulls it in."""
    found: dict[str, set[str]] = {}
    todo = [("shoc", Requirement(r)) for r in requirements]
    while todo:
        parent, req = todo.pop()
        name = norm(req.name)
        if req.marker and not req.marker.evaluate({"extra": ""}):
            continue
        if name in found:  # ponytail: extras asked for on a second path are not followed
            found[name].add(parent)
            continue
        found[name] = {parent}
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            sys.exit(f"FAIL '{name}' is not installed; run pip install -e . first")
        for r in dist.requires or []:
            sub = Requirement(r)
            if sub.marker and not any(
                sub.marker.evaluate({"extra": e}) for e in req.extras or {""}
            ):
                continue
            sub.marker = None
            todo.append((name, sub))
    return found


def denied_imports(root: Path = Path("shoc")) -> list[str]:
    hits = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            else:
                continue
            hits += [
                f"{path}:{node.lineno} imports {m}" for m in mods if norm(m.split(".")[0]) in DENIED
            ]
    return hits


def transitive_problems(
    direct: list[str], deps: list[str], pulled: dict[str, set[str]]
) -> list[str]:
    problems = []
    for name, parents in sorted(pulled.items()):
        if name in direct:
            continue
        if name not in TRANSITIVE:
            problems.append(
                f"new transitive dependency '{name}' (via {', '.join(sorted(parents))}); "
                "review it and add it to TRANSITIVE"
            )
        if name in DENIED:
            carrier = TOLERATED.get(name)
            others = [d for d in deps if name_of(d) != carrier]
            if carrier is None or name in closure(others):
                problems.append(
                    f"denied package '{name}' arrives through {', '.join(sorted(parents))}; "
                    f"only {carrier or 'an RFC'} may bring it in"
                )
    return problems


def main() -> int:
    data = tomllib.loads(Path("pyproject.toml").read_text())
    deps = data["project"]["dependencies"]
    core = [name_of(d) for d in deps]
    slots = {SHARED_SLOTS.get(n, n) for n in core}
    problems: list[str] = []
    if len(slots) > LIMIT:
        problems.append(
            f"core uses {len(slots)} dependency slots, the budget is {LIMIT}: {sorted(slots)}"
        )
    for n in core:
        if n in DENIED:
            problems.append(f"'{n}' is on the deny list; write an RFC before adding it")
    extras = data["project"].get("optional-dependencies", {})
    for extra, deps_ in extras.items():
        if extra == "dev":
            continue
        for d in deps_:
            if name_of(d) in DENIED:
                problems.append(f"extra '{extra}' pulls denied dependency '{name_of(d)}'")
    pulled = closure(deps)
    problems += transitive_problems(core, deps, pulled)
    problems += [f"{h}, a denied package; shoc must not use it directly" for h in denied_imports()]
    for p in problems:
        print(f"FAIL {p}")
    for n in sorted(TRANSITIVE - pulled.keys()):
        print(f"WARN '{n}' is on TRANSITIVE but no longer pulled in; remove it")
    if not problems:
        print(
            f"OK core uses {len(slots)}/{LIMIT} dependency slots: {sorted(slots)}; "
            f"{len(pulled) - len(core)} reviewed transitive packages"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
