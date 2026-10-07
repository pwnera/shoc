#!/usr/bin/env python3
"""Write `contract/v1.json`: the public contract, frozen at v0.4.

From v1.0 these only change in a major release: capability names and schemas,
REST paths, MCP tool names, event types, the `EventStore` interface and the OCSF
table layout. CI regenerates this file and fails when it differs, so a contract
change is always a deliberate, reviewed commit.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

OUT = Path("contract/v1.json")


def event_types() -> list[str]:
    """Every event type SSE and webhook subscribers can receive, read from the code.

    `publish(conn, tenant, "<type>", ...)` names most of them. Health events are
    `health.<kind>` for each `OpsAlert("<kind>", ...)` and each alert handed to
    `_publish_alert` as a literal. A type built any other way stops the snapshot,
    so a new event cannot reach subscribers without reaching the contract.
    """
    import shoc

    found: set[str] = set()
    for path in sorted(Path(shoc.__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            args = node.args
            if name == "publish":
                kind = args[2] if len(args) >= 3 else None
                # A literal, a choice of two literals, or f"health.{kind}" (below).
                choices = [kind.body, kind.orelse] if isinstance(kind, ast.IfExp) else [kind]
                if all(isinstance(c, ast.Constant) for c in choices):
                    found.update(str(c.value) for c in choices if isinstance(c, ast.Constant))
                elif not (
                    isinstance(kind, ast.JoinedStr)
                    and ast.literal_eval(kind.values[0]) == "health."
                ):
                    raise ValueError(f"{path}:{node.lineno}: publish an event type as a literal")
            elif name == "OpsAlert":
                if not (args and isinstance(args[0], ast.Constant)):
                    raise ValueError(f"{path}:{node.lineno}: name the alert kind as a literal")
                found.add(f"health.{args[0].value}")
            elif name == "_publish_alert" and len(args) == 2 and isinstance(args[1], ast.Dict):
                found.update(
                    f"health.{value.value}"
                    for key, value in zip(args[1].keys, args[1].values, strict=True)
                    if isinstance(key, ast.Constant)
                    and key.value == "kind"
                    and isinstance(value, ast.Constant)
                )
    return sorted(found)


def snapshot() -> dict:
    from shoc.actions import available as actions_available
    from shoc.capabilities.registry import all_capabilities
    from shoc.store import ocsf
    from shoc.store.base import EventStore

    caps = all_capabilities()
    return {
        "contract_version": 1,
        "capabilities": {
            cap.name: {
                "scope": cap.scope,
                "autonomy": cap.autonomy,
                "principals": list(cap.principals),
                "audit": cap.audit,
                "rest": cap.rest_path,
                "mcp_tool": cap.mcp_name,
                "cli": "shoc " + " ".join(cap.cli_words),
                "input_schema": cap.input_schema(),
                "output_schema": cap.output_schema(),
            }
            for cap in caps
        },
        "event_types": event_types(),
        "ocsf_columns": [{"name": n, "type": t} for n, t in ocsf.COLUMNS],
        "ocsf_fields": dict(sorted(ocsf.FIELD_MAP.items())),
        "event_store_interface": sorted(
            name for name in dir(EventStore) if not name.startswith("_")
        ),
        "actions": sorted(actions_available()),
    }


def main() -> int:
    import sys

    data = snapshot()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print(
                "FAIL the public contract changed. Run `python scripts/snapshot_contract.py` "
                "and review the diff: from v1.0 these changes need a major release."
            )
            return 1
        print(f"OK contract unchanged ({len(data['capabilities'])} capabilities)")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(data['capabilities'])} capabilities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
