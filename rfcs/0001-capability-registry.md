---
rfc: 0001
title: The capability registry as the single product surface
status: accepted
authors: ["@Rettila"]
created: 2026-09-24
requirements: ["API-1"]
---

# RFC 0001: The capability registry as the single product surface

## Summary

Every operation shoc can perform is declared once, in `shoc/capabilities/`, with
a typed input, a typed output, a scope, the principals allowed to call it and an
autonomy level. REST + OpenAPI, MCP tools, CLI commands, Slack callbacks and the
tools handed to our own agents are generated from those declarations. No surface
may reach the kernel any other way.

## Motivation

The product has five front ends and no required UI. Written by hand, each front
end drifts: a REST route gains a parameter the MCP tool lacks, an agent gets a
tool that skips the autonomy check, a CLI flag silently bypasses the audit log.
For a product whose value rests on "every action is typed, policy-checked and
audited", drift is the failure mode rather than a papercut.

## Guide-level explanation

A capability is a decorated function:

```python
@capability(
    name="finding.set_status",
    summary="Change a finding's status",
    input=StatusUpdate, output=StatusResult,
    scope="findings:write",
    principals=("human", "agent"),
    autonomy="L0",
    audit=True,
)
def set_status(ctx: Context, inp: StatusUpdate) -> Result: ...
```

That one declaration produces `POST /v1/finding/set_status` with a JSON Schema
body, the MCP tool `finding_set_status`, the command
`shoc finding set-status --finding-uid … --status triage`, an entry in
`docs/reference.md`, and an audit row on every call.

Answers always come back in one envelope:

```json
{ "data": {...}, "summary": "F-1a2b… is now triage.", "citations": ["ct-9f…"] }
```

## Reference-level explanation

- **Input and output types are dataclasses.** JSON Schema is derived from them
  (`shoc/jsonschema.py`), and untrusted JSON is coerced back into them with
  field-level errors. We do not take a runtime-validation dependency for this
  (principle 3).
- **`Capability.invoke` is the only call path.** It checks the principal kind,
  then the scope, then autonomy (an `L2` capability refuses any non-human
  principal), then validates the input, then runs the body, then writes the
  audit row. A surface that wants to skip a check has to stop being a surface.
- **Names are hierarchical** (`area.verb`). The area maps to the REST path
  segment, the MCP tool name (`area_verb`) and the CLI command group.
- **The registry describes itself.** `capability.list` and
  `capability.describe` return the same schemas the surfaces publish, so an
  agent can discover what it may call without reading our docs.

## Drawbacks

Generated surfaces are less idiomatic than hand-written ones: REST is
`POST`-only and RPC-shaped rather than resource-shaped, and CLI flags follow
field names rather than what a shell user might expect.

## Alternatives

- **Hand-written surfaces with a shared service layer.** Rejected: the checks
  live in the service layer by convention, and conventions rot.
- **FastAPI plus pydantic.** Rejected on principle 3 (dependency budget) and
  because it still leaves MCP, CLI and Slack to hand-write.
- **OpenAPI-first with generated servers.** Rejected: it makes the HTTP surface
  the source of truth, and our primary clients are agents, not browsers.

## Dependency and scope impact

No new dependencies. Public contract: the capability name, its schemas, the
REST path and the MCP tool name are all part of the frozen contract from v0.4.

## Security considerations

The registry is the enforcement point for the security model: principals,
scopes, bounded autonomy and audit. It follows that two reviewers are required
for changes to `shoc/capabilities/registry.py` (see `CODEOWNERS`), and that a
capability with `audit=True` must never be made to skip the audit row on an
error path, because errors are audited too.

## Unresolved questions

Per-capability rate limits and token budgets for external agents; whether Slack
callbacks need their own principal kind rather than reusing `human`.

## Adoption and migration

Shipped in v0.1 with the kernel. There is nothing to migrate from.
