"""Operability and deployment guidelines checked on the files (OPS-G5, OPS-G6, OPS-G7).

Each KNOWN holds what breaks its rule today, and why. A new violation fails,
and so does an entry that no longer breaks the rule, so a list only shrinks.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator

import yaml

from tests.support import ROOT

SHOC = ROOT / "shoc"


def _ratchet(found: dict[str, str], known: dict[str, str], rule: str) -> None:
    new = sorted(set(found) - set(known))
    assert not new, f"{rule}:\n" + "\n".join(f"  {found[key]}" for key in new)
    gone = sorted(set(known) - set(found))
    assert not gone, f"no longer breaks '{rule}'; take out of KNOWN: {', '.join(gone)}"


def _modules() -> Iterator[tuple[str, ast.Module]]:
    for path in sorted(SHOC.rglob("*.py")):
        yield path.relative_to(ROOT).as_posix(), ast.parse(path.read_text(), str(path))


def _is_environ(node: ast.AST) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "environ") or (
        isinstance(node, ast.Name) and node.id == "environ"
    )


def _env_reads(tree: ast.Module) -> list[tuple[str, int]]:
    """Each `SHOC_*` name read from the environment, with its line: os.environ.get,
    os.environ[...], os.getenv and `in os.environ`."""
    out = []
    for node in ast.walk(tree):
        key: ast.AST | None = None
        if isinstance(node, ast.Call) and node.args:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and (
                    (func.attr in ("get", "pop", "setdefault") and _is_environ(func.value))
                    or func.attr == "getenv"
                )
            ) or (isinstance(func, ast.Name) and func.id == "getenv"):
                key = node.args[0]
        elif isinstance(node, ast.Subscript) and _is_environ(node.value):
            key = node.slice
        elif isinstance(node, ast.Compare) and any(_is_environ(c) for c in node.comparators):
            key = node.left
        if (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.startswith("SHOC_")
        ):
            out.append((key.value, getattr(node, "lineno", 0)))
    return out


# -- OPS-G5: one function per operator switch ---------------------------------
SETTINGS = "shoc/config.py"

# Read where they are used instead of through Config. Each is a second place a
# deployer's setting can be read differently (live-3).
KNOWN_ENV_READS = {
    "shoc/cli.py:SHOC_CLI_USER": "OPS-G5 known gap: the audit name of one CLI command",
    "shoc/cli.py:SHOC_NEW_MASTER_KEY": "OPS-G5 known gap: rotate-key's target key",
    "shoc/capabilities/llm.py:SHOC_LLM_BASE_URL_ALLOWLIST": "OPS-G5 known gap",
    "shoc/capabilities/llm.py:SHOC_LLM_BASE_URL": "OPS-G5 known gap: Config.llm_base_url too",
    "shoc/agents/ops.py:SHOC_LLM_PRICE_IN": "OPS-G5 known gap: the price override",
    "shoc/agents/ops.py:SHOC_LLM_PRICE_OUT": "OPS-G5 known gap: the price override",
    "shoc/api/auth.py:SHOC_TOKENS": "OPS-G5 known gap: re-read on each token check",
    "shoc/api/auth.py:SHOC_BIND": "OPS-G5 known gap: serve's published address",
    "shoc/db/secrets.py:SHOC_ALLOW_WEAK_KEY": "OPS-G5 known gap: the test-only key escape",
    "shoc/api/mcp.py:SHOC_MCP_ROLE": "OPS-G5 known gap: the stdio client's role",
    "shoc/api/mcp.py:SHOC_MCP_USER": "OPS-G5 known gap: the stdio client's audit id",
}


def test_settings_are_read_in_one_place():
    """OPS-G5: a SHOC_* variable is read in shoc/config.py and nowhere else."""
    found = {}
    for rel, tree in _modules():
        if rel == SETTINGS:
            continue
        for name, line in _env_reads(tree):
            found[f"{rel}:{name}"] = f"{rel}:{line} reads {name}; read it through Config"
    _ratchet(found, KNOWN_ENV_READS, "SHOC_* is read only in shoc/config.py")


# Where SHOC_DRY_RUN meets the policy: `Policy.dry_run_for` and `actions.decide`.
DRY_RUN_RESOLVERS = {"shoc/config.py", "shoc/cases/policy.py", "shoc/cases/actions.py"}

KNOWN_DRY_RUN_READS = {
    "shoc/cases/playbooks.py:start": "OPS-G5 known gap: a run is recorded dry only while "
    "SHOC_DRY_RUN=1, whatever the policy's dry_run says",
    "shoc/cases/playbooks.py:job_key": "OPS-G5 known gap: the start key follows SHOC_DRY_RUN "
    "alone, as `start` does",
}


def _is_config(node: ast.AST) -> bool:
    return (isinstance(node, ast.Name) and node.id in ("cfg", "config")) or (
        isinstance(node, ast.Attribute) and node.attr == "config"
    )


def _reads_dry_run(node: ast.AST) -> bool:
    """`cfg.dry_run`, `ctx.config.dry_run` or `getattr(config, "dry_run", …)`."""
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        return node.attr == "dry_run" and _is_config(node.value)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and _is_config(node.args[0])
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "dry_run"
    )


def _own_nodes(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """A function's nodes, without those of the functions defined inside it."""
    todo: list[ast.AST] = list(fn.body)
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            todo.extend(ast.iter_child_nodes(node))


def test_dry_run_is_resolved_by_the_policy():
    """OPS-G5: Config.dry_run is read only where Policy.dry_run_for resolves it."""
    found = {}
    for rel, tree in _modules():
        if rel in DRY_RUN_RESOLVERS:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            nodes = list(_own_nodes(fn))
            if any(isinstance(n, ast.Attribute) and n.attr == "dry_run_for" for n in nodes):
                continue
            for node in nodes:
                if _reads_dry_run(node):
                    found[f"{rel}:{fn.name}"] = (
                        f"{rel}:{getattr(node, 'lineno', fn.lineno)} {fn.name} reads "
                        "Config.dry_run without Policy.dry_run_for"
                    )
    _ratchet(found, KNOWN_DRY_RUN_READS, "dry run is resolved by Policy.dry_run_for")


# -- OPS-G6: a migration keeps the previous release's queries working ---------
MIGRATIONS = SHOC / "db" / "migrations"
BREAKS_OLD_CODE = {
    "renames a table, column or index": re.compile(r"\brename\b"),
    "sets a column NOT NULL": re.compile(r"\bset not null\b"),
    "changes a column's type": re.compile(
        r"\balter column (?:if exists )?\w+ (?:set data )?type\b"
    ),
    "drops a column default": re.compile(r"\bdrop default\b"),
}
ADD_COLUMN = re.compile(r"\badd column (?:if not exists )?(\w+)([^,;]*)")

# Each ran before any release existed (0.0.1 is unreleased), so no old pods ran beside it.
KNOWN_MIGRATIONS = {
    "014_openspace.sql": "renames room_messages to openspace_messages; before any release",
    "020_playbook_steps_tenant.sql": "sets playbook_steps.tenant_id NOT NULL; before any release",
    "025_audit_keyed.sql": "drops audit_log.ts's default; before any release",
}


def test_no_new_migration_breaks_the_previous_release():
    """OPS-G6: a migration never renames, narrows or retypes what old code still queries."""
    found = {}
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = re.sub(r"/\*.*?\*/", " ", path.read_text(), flags=re.DOTALL)
        text = " ".join(re.sub(r"--[^\n]*", " ", text).lower().split())
        why = [what for what, pattern in BREAKS_OLD_CODE.items() if pattern.search(text)]
        why += [
            f"adds NOT NULL column {m.group(1)} without a default"
            for m in ADD_COLUMN.finditer(text)
            if "not null" in m.group(2)
            and "default" not in m.group(2)
            and "generated" not in m.group(2)
        ]
        if why:
            found[path.name] = f"{path.relative_to(ROOT)} {'; '.join(why)}"
    _ratchet(found, KNOWN_MIGRATIONS, "a migration keeps the previous release working")


# -- OPS-G7: deploy files follow the code -----------------------------------
COMPOSE = ROOT / "deploy" / "docker-compose.yml"

# Settings of one command or of a developer, which docs/deploy.md tells a
# Compose user to pass another way.
HOST_ONLY = {
    "SHOC_NEW_MASTER_KEY": "rotate-key's own, with docker compose run -e",
    "SHOC_ALLOW_WEAK_KEY": "tests and local trials only",
    "SHOC_CLI_USER": "one CLI command's, with docker compose run -e",
    "SHOC_MCP_ROLE": "the stdio MCP client's",
    "SHOC_MCP_USER": "the stdio MCP client's",
    "SHOC_CONTENT_DIR": "needs its directory mounted too, in docker-compose.override.yml",
}


def test_every_setting_reaches_the_containers():
    """OPS-G7: every SHOC_* variable the code reads passes through x-shoc-env and is documented."""
    passed = set(yaml.safe_load(COMPOSE.read_text())["x-shoc-env"])
    read: dict[str, str] = {}
    for rel, tree in _modules():
        for name, line in _env_reads(tree):
            read.setdefault(name, f"{rel}:{line}")
    missing = sorted(set(read) - passed - set(HOST_ONLY))
    assert not missing, "read but never passed to a container by x-shoc-env: " + ", ".join(
        f"{name} ({read[name]})" for name in missing
    )
    assert not set(HOST_ONLY) - set(read), "HOST_ONLY names a variable nothing reads"
    table = (ROOT / "docs" / "deploy.md").read_text()
    undocumented = sorted(name for name in read if f"`{name}`" not in table)
    assert not undocumented, "missing from docs/deploy.md: " + ", ".join(undocumented)


IMAGE = re.compile(r"image:\s*ghcr\.io/\S+?:\$\{(\w+):-([^}]*)\}")

KNOWN_IMAGE_DEFAULTS = {
    "deploy/docker-compose.yml:SHOC_VERSION": "no release is published yet (0.0.1); "
    "docs/deploy.md documents edge as the default",
    "console/deploy/docker-compose.yml:CONSOLE_VERSION": "release.yml publishes no console "
    "image; edge.yml is the only one that does",
    "deploy/helm/shoc/Chart.yaml:appVersion": "release-please's extra-files bump only "
    "shoc/__init__.py",
}


def test_released_images_are_the_default():
    """OPS-G7: a shipped image default is the release release-please bumps, never edge."""
    from shoc import __version__

    settings = json.loads((ROOT / ".release-please-config.json").read_text())
    bumped = {
        entry if isinstance(entry, str) else entry.get("path")
        for package in settings["packages"].values()
        for entry in package.get("extra-files", [])
    }
    found = {}
    for rel in ("deploy/docker-compose.yml", "console/deploy/docker-compose.yml"):
        for number, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
            if not (m := IMAGE.search(line)):
                continue
            var, default = m.groups()
            if (
                default in ("", "edge", "latest")
                or "x-release-please-version" not in line
                or rel not in bumped
            ):
                found[f"{rel}:{var}"] = (
                    f"{rel}:{number} defaults {var} to '{default}', not a version "
                    "release-please writes"
                )
    chart = "deploy/helm/shoc/Chart.yaml"
    app_version = yaml.safe_load((ROOT / chart).read_text())["appVersion"]
    assert app_version == __version__, f"{chart} appVersion {app_version} is not {__version__}"
    if chart not in bumped:
        found[f"{chart}:appVersion"] = f"{chart} appVersion is not in release-please's extra-files"
    _ratchet(found, KNOWN_IMAGE_DEFAULTS, "the default image is the signed release")
