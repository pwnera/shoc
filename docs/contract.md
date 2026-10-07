# The public contract

From v1.0 these break only in a major release. Until then they are
snapshotted in [`contract/v1.json`](https://github.com/pwnera/shoc/blob/main/contract/v1.json); CI regenerates that
file and fails if it differs, so a change is always a deliberate commit somebody
reviewed.

## What is in the contract

| Part | Where it lives | What "breaking" means |
| --- | --- | --- |
| Capability names and input schemas | `shoc/capabilities/` | Renaming one, removing a field, making an optional field required, narrowing a type |
| Output schemas | each capability's output dataclass | Removing or renaming a field of `data`, at any depth |
| REST paths | generated: `POST /v1/<area>/<name>` | Changing a path or the response envelope |
| MCP tool names | generated: `area_name` | Renaming a tool, or changing its input schema |
| Response envelope | `{data, summary, citations}` | Anything other than these three keys at the top level |
| Event types | read from the code that publishes them | Renaming or removing a type |
| `EventStore` interface | `shoc/store/base.py` | Adding a required method, changing a signature |
| OCSF table layout | `shoc/store/ocsf.py` | Removing a column, changing its type or meaning |
| Content formats | rules, playbooks, policy YAML | Removing a key, changing what one means |
| Autonomy semantics | L0/L1/L2, "L2 needs a human" | Any loosening at all |

"L2 needs a human" is about the principal, and over MCP it also means the person
confirms each L2 call in their client (RFC 0018). Which role a client carries is
set by `SHOC_MCP_ROLE` over stdio, and over HTTP by the bearer token or the account a session belongs to. That is a choice about a deployment rather than a property of the
contract, and it is documented in [`security-model.md`](security-model.md). What
the contract holds is that nothing else loosens it, and that the default, an
external agent, is unchanged.

## What is *not* in the contract

- Adding a capability, a column, an event type or a rule. Those are minor
  releases.
- Internal module layout, database table shapes other than the OCSF tables, job
  kinds, prompt text, model choice.
- The CLI's exact output text. Use `--json` for anything a script depends on.
- The `/auth/*` routes a browser signs in through (RFC 0028). They are
  documented in [`security-model.md`](security-model.md#people-sign-in), and the
  capabilities that manage people are in the contract like any other.
- Detection content: rules are expected to change with the threat, and each one
  is versioned with the release.

## Deprecation

A field, capability or config key that is going away warns for at least two
minor releases before it is removed, and the release notes list it. Nothing is
removed in a patch.

## Checking it yourself

```bash
python scripts/snapshot_contract.py --check
```

If that fails on your branch, you changed the contract. That may well be
correct, but say so in the pull request, and the `contract/v1.json` diff shows
exactly what a client would notice.
