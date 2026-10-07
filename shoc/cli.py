"""`shoc` — the CLI, generated from the capability registry (API-1).

`shoc serve`, `shoc worker`, `shoc migrate` and `shoc mcp` are the process
commands; every capability also appears automatically, so `shoc events query
--since -1h` and `shoc ask "what happened with AKIA…"` exist without anyone
writing a command for them.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
import typing
from typing import Any, get_args, get_origin

import yaml

from shoc import __version__
from shoc.capabilities.registry import Caller, Capability, Context, all_capabilities
from shoc.config import Config
from shoc.errors import ConfigError, ShocError

CLI_CALLER = Caller(kind="human", id="cli", scopes=("*",))


# -- flags from schemas -----------------------------------------------------
def _add_flags(parser: argparse.ArgumentParser, cap: Capability) -> list[str]:
    """One flag per input field. Returns the names of required fields."""
    hints = typing.get_type_hints(cap.input)
    required: list[str] = []
    for f in dataclasses.fields(cap.input):
        tp = hints.get(f.name, str)
        doc = (f.metadata or {}).get("doc", "")
        flag = "--" + f.name.replace("_", "-")
        is_required = (
            f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING  # type: ignore[misc]
        )
        if is_required:
            required.append(f.name)
        origin = get_origin(tp)
        if tp is bool or tp == (bool | None):  # --flag / --no-flag; unset leaves it out
            parser.add_argument(
                flag, dest=f.name, action=argparse.BooleanOptionalAction, default=None, help=doc
            )
        elif origin is list:
            parser.add_argument(flag, dest=f.name, nargs="*", help=doc)
        elif origin is dict:
            parser.add_argument(flag, dest=f.name, help=f"{doc} (JSON object)")
            # Credentials on a command line end up in shell history and in the
            # process list. Every dict field gets a file form, `-` for stdin.
            parser.add_argument(
                flag + "-file",
                dest=f.name + "_file",
                help=f"Read {f.name} as JSON or YAML from a file, or from stdin with '-'",
            )
        elif tp is int or tp == (int | None):
            parser.add_argument(flag, dest=f.name, type=int, help=doc)
        elif tp is float:
            parser.add_argument(flag, dest=f.name, type=float, help=doc)
        elif get_origin(tp) is typing.Literal:
            parser.add_argument(flag, dest=f.name, choices=list(get_args(tp)), help=doc)
        else:
            parser.add_argument(flag, dest=f.name, help=doc)
    if len(required) == 1:
        # A convenience positional for the one required field (`shoc ask "…"`).
        # It gets its own dest so it cannot overwrite the flag of the same name.
        parser.add_argument(
            "positional_value",
            nargs="?",
            default=None,
            metavar=required[0],
            help=f"(positional form of --{required[0].replace('_', '-')})",
        )
    return required


def _payload(cap: Capability, args: argparse.Namespace, required: list[str]) -> dict[str, Any]:
    hints = typing.get_type_hints(cap.input)
    out: dict[str, Any] = {}
    raw = getattr(args, "json_input", None)
    if raw:
        out.update(json.loads(raw))
    names = {f.name for f in dataclasses.fields(cap.input)}
    for name in sorted(names):
        value = getattr(args, name, None)
        from_file = getattr(args, name + "_file", None)
        if from_file:
            if value is not None:
                raise ConfigError(f"give --{name} or --{name}-file, not both")
            if from_file == "-":
                value = sys.stdin.read()
            else:
                from pathlib import Path

                value = Path(from_file).read_text()
        if value is None:
            continue
        if get_origin(hints.get(name)) is dict and isinstance(value, str):
            # A file may be YAML, so a content/ playbook or rule is sent as it is.
            value = yaml.safe_load(value) if from_file else json.loads(value)
        out[name] = value
    if len(required) == 1:
        positional = getattr(args, "positional_value", None)
        if isinstance(positional, str):
            out[required[0]] = positional
    return out


# Columns nobody reads in a terminal: the same for every row, or an id the
# summary already gave. `--json` still carries everything.
_DULL_COLUMNS = frozenset({"tenant_id", "raw", "evidence", "cursor"})
_MAX_COLUMNS = 6


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) if len(value) <= 3 else f"{len(value)} items"
    if isinstance(value, dict):
        return f"{len(value)} field(s)"
    return str(value)


def _table(rows: list[dict[str, Any]]) -> None:
    """Print rows as a table, in the order the output dataclass declares them.

    Declared order is authored order, so the identifying and human-facing
    fields come first without a second list here to keep in step.
    """
    import shutil

    keys = [k for k in rows[0] if k not in _DULL_COLUMNS]
    shown, hidden = keys[:_MAX_COLUMNS], keys[_MAX_COLUMNS:]
    width = max(shutil.get_terminal_size((100, 24)).columns, 60)
    cells = [[_cell(r.get(k)) for k in shown] for r in rows]
    widths = [min(max(len(k), *(len(c[i]) for c in cells)), 44) for i, k in enumerate(shown)]
    # Give back whatever the terminal cannot hold, from the widest column in.
    while sum(widths) + 2 * (len(widths) - 1) > width and max(widths) > 8:
        widths[widths.index(max(widths))] -= 1

    def line(values: list[str]) -> str:
        out = []
        for value, w in zip(values, widths, strict=True):
            out.append((value if len(value) <= w else value[: w - 1] + "…").ljust(w))
        return "  ".join(out).rstrip()

    print(line([k.replace("_", " ") for k in shown]))
    print(line(["-" * w for w in widths]))
    for row in cells:
        print(line(row))
    if hidden:
        print(f"({len(hidden)} more column(s): {', '.join(hidden)} — use --json)")


def _fields(data: dict[str, Any], indent: str = "") -> None:
    """Key and value per line, expanding one level: nested detail is the answer.

    `health status` is mostly nested dicts; collapsing them to "6 field(s)"
    would hide the thing the command was asked for.
    """
    width = max((len(k) for k in data), default=0)
    for key, value in data.items():
        # A key with a dot or a colon is an identifier — an action name, a
        # scope — not a field label, so it is printed as it is written.
        label = key if ("." in key or ":" in key) else key.replace("_", " ")
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            print(f"{indent}{label}:")
            _table(value)
        elif isinstance(value, dict) and value and not indent:
            print(f"{indent}{label}:")
            _fields(value, indent="  ")
        elif isinstance(value, list) and not value:
            print(f"{indent}{label.ljust(width)}  none")
        else:
            print(f"{indent}{label.ljust(width)}  {_cell(value)}")


def _print(result: Any, as_json: bool) -> None:
    payload = result.to_json()
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
        return
    print(payload["summary"])
    data = payload["data"]
    if isinstance(data, dict) and data:
        _fields(data)
    elif data not in ({}, None):
        print(json.dumps(data, indent=2, default=str))
    if payload["citations"]:
        shown = payload["citations"][:10]
        more = len(payload["citations"]) - len(shown)
        print("citations: " + ", ".join(shown) + (f" (+{more} more)" if more > 0 else ""))


# -- process commands -------------------------------------------------------
def _grant_configured_readonly(conn: Any, cfg: Config) -> str:
    """Grant the role in SHOC_READONLY_DSN read access to the tenant schema.

    The role is created by the deployment (the compose file's init script), but
    until it is granted, every agent read fails with "relation ocsf_events does
    not exist" once a cycle, forever. Migrating is the moment the schema exists,
    so it is the moment to grant. Never creates a role and never rotates a
    password: `shoc grant-readonly` stays the command for that.
    """
    from urllib.parse import urlsplit

    if not cfg.readonly_dsn:
        return ""
    role = urlsplit(cfg.readonly_dsn).username or ""
    if not role:
        return ""
    from shoc.db.migrate import RoleNotCreated, grant_readonly

    database = (urlsplit(cfg.dsn).path or "/shoc").lstrip("/")
    try:
        schemas = grant_readonly(conn, role, "", database, cfg.tenant_schema())
    except RoleNotCreated:
        return (
            f"note: SHOC_READONLY_DSN names role '{role}', which does not exist. "
            f"Run `shoc grant-readonly --role {role}` for the SQL to create it."
        )
    except Exception as exc:  # a grant we could not make is not a failed migration
        return f"note: could not grant '{role}' read access ({exc}); run `shoc grant-readonly`."
    return f"read-only role '{role}' granted SELECT in: {', '.join(schemas)}."


OWNER_WARNING = (
    "warning: serve and worker connect as the role that owns shoc's schema, so they "
    "could disable the audit log's triggers and delete its rows. Set SHOC_MIGRATE_DSN "
    "to that role and SHOC_DSN to one that does not own the schema (RFC 0024)."
)


def _warn_if_owner(cfg: Config) -> None:
    """Say so when the runtime role could rewrite the audit log (SEC-1, RFC 0024)."""
    from shoc.db.pool import connect, owns_audit_log

    try:
        owner = owns_audit_log(connect(cfg))
    except Exception:  # no database yet: `serve` and `worker` say so themselves
        return
    if owner:
        logging.getLogger("shoc").warning(OWNER_WARNING)


def cmd_migrate(args: argparse.Namespace, cfg: Config) -> int:
    from urllib.parse import urlsplit

    from shoc.db.migrate import grant_runtime, migrate
    from shoc.db.pool import ALL_TENANTS, connect_owner, fetch_one, set_tenant
    from shoc.store import open_store

    # As the owner: the schema, then the grants that let SHOC_DSN run shoc
    # without owning it (RFC 0024). Tenant event schemas are created below as
    # SHOC_DSN, which loads and prunes them.
    conn = connect_owner(cfg)
    set_tenant(conn, ALL_TENANTS)
    applied = migrate(conn)
    runtime = urlsplit(cfg.dsn).username or ""
    me = (fetch_one(conn, "SELECT current_user AS me") or {}).get("me")
    if cfg.migrate_dsn and runtime and runtime != me:
        grant_runtime(conn, runtime, (urlsplit(cfg.dsn).path or "/shoc").lstrip("/"))
        print(
            f"runtime role '{runtime}' granted; it can append to the audit log and not change it."
        )
    else:
        print(OWNER_WARNING, file=sys.stderr)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.tenants (tenant_id, name, backend, schema_name)
               VALUES (%s,%s,%s,%s) ON CONFLICT (tenant_id) DO NOTHING""",
            (cfg.tenant_id, cfg.tenant_id, cfg.backend, cfg.tenant_schema()),
        )
    store = open_store(cfg)
    store.migrate()
    print(
        f"migrations applied: {', '.join(applied) if applied else 'none (already current)'}; "
        f"tenant '{cfg.tenant_id}' ready on {cfg.backend}"
    )
    granted = _grant_configured_readonly(conn, cfg)
    if granted:
        print(granted)
    from shoc.db.pool import connect, is_superuser

    if is_superuser(connect(cfg)):
        print(
            "warning: shoc is connected as a Postgres superuser, which bypasses row-level "
            "security. Create an ordinary role for it before production.",
            file=sys.stderr,
        )
    return 0


def cmd_serve(args: argparse.Namespace, cfg: Config) -> int:
    import uvicorn

    from shoc.api.auth import check_bind
    from shoc.api.rest import build_app

    check_bind(args.host, cfg)
    _warn_if_owner(cfg)
    uvicorn.run(build_app(cfg), host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_worker(args: argparse.Namespace, cfg: Config) -> int:
    from shoc.worker import run

    logging.basicConfig(
        level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(message)s"
    )
    _warn_if_owner(cfg)
    run(cfg, once=args.once)
    return 0


def cmd_mcp(args: argparse.Namespace, cfg: Config) -> int:
    import asyncio

    from shoc.api.mcp import serve_stdio

    asyncio.run(serve_stdio(cfg))
    return 0


def cmd_grant_readonly(args: argparse.Namespace, cfg: Config) -> int:
    """Create the read-only Postgres role agents query through (SEC-1)."""
    import secrets as pysecrets
    from urllib.parse import urlsplit

    from shoc.db.migrate import RoleNotCreated, grant_readonly
    from shoc.db.pool import ALL_TENANTS, connect_owner, set_tenant

    conn = connect_owner(cfg)
    set_tenant(conn, ALL_TENANTS)
    from shoc.db.pool import fetch_one

    parts = urlsplit(cfg.dsn)
    database = (parts.path or "/shoc").lstrip("/")
    existed = bool(
        fetch_one(conn, "SELECT 1 AS yes FROM pg_roles WHERE rolname = %s", (args.role,))
    )
    # Do not rotate an existing role's password unless asked: that needs
    # privileges shoc deliberately does not have.
    password = args.password or ("" if existed else pysecrets.token_urlsafe(24))
    try:
        schemas = grant_readonly(conn, args.role, password, database, cfg.tenant_schema())
    except RoleNotCreated as exc:
        print(exc, file=sys.stderr)
        return 1
    host = parts.hostname or "localhost"
    port = parts.port or 5432
    print(f"role '{args.role}' can now read, and only read, in: {', '.join(schemas)}.")
    if password:
        print(
            "Set this on serve and worker so agents use it:\n"
            f"  SHOC_READONLY_DSN=postgresql://{args.role}:{password}@{host}:{port}/{database}"
        )
    else:
        print(
            f"'{args.role}' already existed, so its password was left alone; keep the "
            "SHOC_READONLY_DSN you already have."
        )
    print("Run this again after adding a tenant, so the new schema is covered too.")
    return 0


def cmd_keygen(args: argparse.Namespace, cfg: Config) -> int:
    from shoc.db.secrets import generate_key

    print(generate_key())
    return 0


def cmd_rotate_key(args: argparse.Namespace, cfg: Config) -> int:
    """Re-seal every secret and move the audit chain to a new master key (SEC-1, RFC 0024).

    One transaction, as the schema owner. Stop `serve` and `worker` first: they
    hold the old key, and once this commits they can neither open a secret nor
    append to the audit log until they restart with the new one.
    """
    import os

    from shoc.db import audit, secrets
    from shoc.db.pool import ALL_TENANTS, connect_owner

    new = os.environ.get("SHOC_NEW_MASTER_KEY", "").strip()
    made = not new
    new = new or secrets.generate_key()
    if not cfg.master_key:
        raise ConfigError("SHOC_MASTER_KEY must hold the current key to rotate from")
    if new == cfg.master_key:
        raise ConfigError("SHOC_NEW_MASTER_KEY is the key already in use")
    conn = connect_owner(cfg)
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("SELECT set_config('shoc.tenant_id', %s, true)", (ALL_TENANTS,))
        resealed, unreadable = secrets.reseal(conn, cfg.master_key, new)
        chains = audit.rotate(conn, cfg.master_key, new)
    print(
        f"{resealed} secret(s) sealed with the new key, {chains} audit chain(s) moved to it."
        + (
            f" {unreadable} secret(s) the old key could not open were left as they were."
            if unreadable
            else ""
        )
    )
    if made:
        print(f"The new key, shown once:\n  SHOC_MASTER_KEY={new}")
    print("Set SHOC_MASTER_KEY to the new key on every shoc process, then start serve and worker.")
    return 0


def _bundled_scenario(name: str) -> tuple[str, Any]:
    """Resolve a scenario that ships with shoc to its source and its records.

    The quick start's demo used to be a relative path into the checkout, which
    does not exist in the container the same quick start tells you to run.
    """
    from shoc.config import scenarios_dir
    from shoc.ingest.connectors.file import read_records

    root = scenarios_dir()
    available = sorted(d.name for d in root.iterdir() if (d / "events.json").is_file())
    if name not in available:
        raise ConfigError(f"no scenario called '{name}'. shoc ships: {', '.join(available)}")
    expected = yaml.safe_load((root / name / "expected.yaml").read_text())
    source = str(expected["source"])
    records = json.loads((root / name / "events.json").read_text())
    if isinstance(records, dict):  # a scenario across sources replays its main one here
        return source, list(records.get(source) or [])
    return source, read_records(root / name / "events.json")


def cmd_replay(args: argparse.Namespace, cfg: Config) -> int:
    """Load a recorded file through a mapping — the quick start and the evals use this."""
    from pathlib import Path

    from shoc.capabilities.registry import call
    from shoc.ingest.connectors.file import read_records
    from shoc.ingest.replay import expand

    ctx = Context(tenant_id=cfg.tenant_id, caller=CLI_CALLER, config=cfg)
    if args.scenario:
        args.source, records = _bundled_scenario(args.scenario)
    elif args.source and args.path:
        records = read_records(Path(args.path))
    else:
        raise ConfigError(
            "give a source and a file, or --scenario <name> for one that ships with shoc"
        )
    if not args.as_recorded:
        # A recorded scenario describes shapes (`_repeat`) and leaves timestamps
        # to the replay, so a relative detection window still sees the events.
        records = expand(records, args.source, spread_seconds=300)
    result = call("events.ingest", ctx, {"source": args.source, "records": records})
    _print(result, args.json)
    return 0


def cmd_plan(args: argparse.Namespace, cfg: Config) -> int:
    """Show what `shoc apply` would change (API-4)."""
    from pathlib import Path

    from shoc.capabilities.registry import call
    from shoc.configcode import read_file

    ctx = Context(tenant_id=cfg.tenant_id, caller=CLI_CALLER, config=cfg)
    result = call("config.plan", ctx, {"config": read_file(Path(args.file))})
    print(result.data.rendered)
    return 1 if result.data.invalid else 0


def cmd_apply(args: argparse.Namespace, cfg: Config) -> int:
    """Make the deployment match the config file (API-4)."""
    from pathlib import Path

    from shoc.capabilities.registry import call
    from shoc.configcode import read_file

    ctx = Context(tenant_id=cfg.tenant_id, caller=CLI_CALLER, config=cfg)
    config = {"config": read_file(Path(args.file))}
    preview = call("config.plan", ctx, config)
    print(preview.data.rendered)
    if preview.data.invalid:
        return 1
    if not preview.data.to_change:
        print("\nnothing to do")
        return 0
    if not args.yes:
        answer = input("\napply these changes? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("cancelled")
            return 1
    result = call("config.apply", ctx, config)
    print(result.summary)
    return 0


def cmd_init_config(args: argparse.Namespace, cfg: Config) -> int:
    from pathlib import Path

    from shoc.configcode import write_example

    path = write_example(Path(args.file))
    print(f"wrote {path}. Edit it, then run: shoc plan -f {path}")
    return 0


def cmd_rules_check(args: argparse.Namespace, cfg: Config) -> int:
    """Compile every rule without touching a database (runs in CI)."""
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import compile_rule

    failures = 0
    rules = ruleset.load(cfg)
    for rule in rules:
        try:
            compile_rule(rule)
        except ShocError as exc:
            failures += 1
            print(f"FAIL {rule.id}: {exc}")
    print(f"{len(rules) - failures}/{len(rules)} rule(s) compile")
    return 1 if failures else 0


def cmd_new(args: argparse.Namespace, cfg: Config) -> int:
    """Scaffold a connector, mapping or rule with its tests (ING-4)."""
    from pathlib import Path

    from shoc import scaffold

    root = Path(args.root)
    if args.what == "connector":
        written = scaffold.new_connector(args.name, root, args.force)
        nxt = "Fill in fetch(), then run: pytest tests/unit/test_mappings_all.py"
    elif args.what == "mapping":
        written = scaffold.new_mapping(args.name, root, args.force)
        nxt = "Edit the mapping and its fixture, then run: pytest tests/unit/test_mappings_all.py"
    else:
        written = scaffold.new_rule(args.name, args.product, args.service, root, args.force)
        nxt = (
            "Write the detection and both fixtures, then run: "
            f"pytest tests/conformance/test_rules.py -k {args.name}"
        )
    print(f"created:\n{written.describe()}\n\nnext: {nxt}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shoc", description=(__doc__ or "shoc").splitlines()[0])
    parser.add_argument("--version", action="version", version=f"shoc {__version__}")
    parser.add_argument("--tenant", help="Tenant id (default: SHOC_TENANT or 'default')")
    parser.add_argument(
        "--json", action="store_true", help="Print the full result envelope as JSON"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("migrate", help="Apply database migrations and prepare the tenant")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("serve", help="Run the REST + ingest server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("worker", help="Run connectors, detections and housekeeping")
    p.add_argument("--once", action="store_true", help="Drain the queue once and exit")
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("mcp", help="Run the MCP server over stdio")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser(
        "grant-readonly", help="Create the read-only Postgres role agents query through"
    )
    p.add_argument("--role", default="shoc_agent")
    p.add_argument("--password", default="", help="Leave empty to generate one")
    p.set_defaults(func=cmd_grant_readonly)

    p = sub.add_parser("keygen", help="Print a new master key for connector secrets")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser(
        "rotate-key",
        help="Re-seal secrets and move the audit chain to SHOC_NEW_MASTER_KEY (or a new key)",
    )
    p.set_defaults(func=cmd_rotate_key)

    p = sub.add_parser("replay", help="Load a recorded attack, or any fixture file, into shoc")
    p.add_argument("source", nargs="?", help="Mapping name, e.g. aws_cloudtrail")
    p.add_argument("path", nargs="?", help="NDJSON or JSON file of raw source records")
    p.add_argument(
        "--scenario",
        help="A recorded attack that ships with shoc, e.g. leaked_aws_key. Names its own source.",
    )
    p.add_argument(
        "--as-recorded",
        action="store_true",
        help="Keep the file's own timestamps and ids instead of replaying it as if it were happening now",
    )
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("plan", help="Show what applying the config file would change")
    p.add_argument("-f", "--file", default="shoc.yaml")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="Make the deployment match the config file")
    p.add_argument("-f", "--file", default="shoc.yaml")
    p.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("init-config", help="Write a starter shoc.yaml")
    p.add_argument("-f", "--file", default="shoc.yaml")
    p.set_defaults(func=cmd_init_config)

    p = sub.add_parser("new", help="Scaffold a connector, mapping or rule")
    p.add_argument("what", choices=["connector", "mapping", "rule"])
    p.add_argument("name", help="Lower-case name, e.g. cloudflare or okta_admin_role_granted")
    p.add_argument("--product", default="aws", help="Rule logsource product")
    p.add_argument("--service", default="cloudtrail", help="Rule logsource service")
    p.add_argument("--root", default=".", help="Repository root to write into")
    p.add_argument("--force", action="store_true", help="Overwrite existing files")
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("rules", help="Rule tooling")
    rules_sub = p.add_subparsers(dest="rules_command", required=True)
    pc = rules_sub.add_parser("check", help="Compile every rule and report failures")
    pc.set_defaults(func=cmd_rules_check)

    # Generated capability commands: `shoc events query`, `shoc ask "…"`, …
    groups: dict[str, Any] = {}
    for cap in all_capabilities():
        words = cap.cli_words
        if len(words) == 1:
            cp = sub.add_parser(words[0], help=cap.summary)
        else:
            if words[0] not in groups:
                parent = sub.add_parser(words[0], help=f"{words[0]} capabilities")
                groups[words[0]] = parent.add_subparsers(dest=f"{words[0]}_command", required=True)
            cp = groups[words[0]].add_parser(words[1], help=cap.summary)
        cp.add_argument("--json-input", help="Raw JSON payload, merged under the flags")
        required = _add_flags(cp, cap)
        cp.set_defaults(func=_capability_runner(cap, required))
    return parser


def _capability_runner(cap: Capability, required: list[str]):
    def run(args: argparse.Namespace, cfg: Config) -> int:
        ctx = Context(tenant_id=cfg.tenant_id, caller=CLI_CALLER, config=cfg)
        result = cap.invoke(ctx, _payload(cap, args, required))
        _print(result, args.json)
        return 0

    return run


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.load()
    if getattr(args, "tenant", None):
        cfg.tenant_id = args.tenant
    try:
        return int(args.func(args, cfg) or 0)
    except ShocError as exc:
        print(f"error ({exc.code}): {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
