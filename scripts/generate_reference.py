#!/usr/bin/env python3
"""Generate `docs/reference.md` from the registry, so the docs cannot drift."""

from __future__ import annotations

import json
from pathlib import Path

from shoc import __version__
from shoc.capabilities.registry import all_capabilities

OUT = Path("docs/reference.md")


def main() -> int:
    caps = all_capabilities()
    lines = [
        "# Capability reference",
        "",
        f"Generated from the registry in shoc {__version__} by "
        "`python scripts/generate_reference.py`. Do not edit by hand.",
        "",
        "Every capability below exists on REST, MCP and the CLI. The response envelope is",
        "always `{data, summary, citations}`.",
        "",
        "| Capability | Scope | Autonomy | Principals | REST | MCP tool | CLI |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in caps:
        lines.append(
            f"| `{c.name}` | `{c.scope}` | {c.autonomy} | {', '.join(c.principals)} | "
            f"`POST {c.rest_path}` | `{c.mcp_name}` | `{'shoc ' + ' '.join(c.cli_words)}` |"
        )
    for c in caps:
        lines += [
            "",
            f"## `{c.name}`",
            "",
            c.summary + ".",
            "",
            f"- **Scope:** `{c.scope}` · **Autonomy:** {c.autonomy} · "
            f"**Audited:** {'yes' if c.audit else 'no'}",
            f"- **Principals:** {', '.join(c.principals)}",
            "",
            "Input schema:",
            "",
            "```json",
            json.dumps(c.input_schema(), indent=2),
            "```",
        ]
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(caps)} capabilities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
