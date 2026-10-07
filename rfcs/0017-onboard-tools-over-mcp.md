---
rfc: 0017
title: Let the operator's assistant onboard tools over MCP
status: superseded   # by RFC 0018: the operator mode here is the deployer role there
authors: ["@Rettila"]
created: 2026-09-28
requirements: ["API-1", "ING-1", "RSP-4", "SEC-1", "SEC-2"]
supersedes: null
---

# RFC 0017: Let the operator's assistant onboard tools over MCP

## Summary

`SHOC_MCP_PRINCIPAL=operator` makes an MCP client a human principal that can
connect a log source and give the playbook runner the credentials it acts with,
and cannot approve, run or undo an action. Before this, connecting Okta from
Claude meant setting `SHOC_MCP_PRINCIPAL=human`, which also hands the model
every L2 approval.

## Motivation

The operator is the company's only technical person. The assistant they already
use is the client they are most likely to set shoc up from, and the MCP surface
already lists every onboarding capability. None of them reached a client:

| Capability | Scope | Principals |
| --- | --- | --- |
| `source.configure` | `sources:write` | human |
| `source.push_key` | `sources:write` | human |
| `source.sync` | `sources:sync` | human, agent, service |
| `source.onboard` | `sources:onboard` | human, agent, service |
| `action.configure` | `actions:configure` (L2) | human |
| `intel.configure` | `intel:configure` | human |

The default MCP principal is `external_agent`, which holds none of these
scopes. The one override, `human`, holds `*`. Onboarding a source was
all-or-nothing: no assistant, or an assistant that can approve isolating a host.

## Guide-level explanation

In the MCP client's configuration:

```
SHOC_MCP_PRINCIPAL=operator
SHOC_MCP_USER=rettila@example.com     # recorded in the audit log
```

The client then sees `source_configure`, `source_push_key`, `source_sync`,
`source_onboard`, `action_configure` and `intel_configure` next to the read
tools. "Connect Okta, here is the token" becomes one `source_configure` call; the
Integrator takes the source from there as it does for any other client (D50).
`action_approve`, `action_reject`, `action_run`, `action_undo` and `config_apply`
are not listed.

## Reference-level explanation

`shoc/api/mcp.py` gains `OPERATOR_SCOPES`: the external agent's scopes plus
`sources:write`, `sources:sync`, `sources:onboard`, `actions:configure` and
`intel:configure`. `caller_from_env` returns
`Caller(kind="human", scopes=OPERATOR_SCOPES)` for the exact string `operator`.
Nothing in the registry changes: `Capability.check` already decides by principal,
then scope, then autonomy, and the missing `actions:approve`, `actions:run` and
`config:write` scopes are what keep the operator out of approvals.

Capabilities that no external agent may call sit under scopes the MCP caller
does not hold (`cases:transition`, `platforms:lookup`, `sources:sample`,
`hunts:work`), so being a human principal does not bring the operator
`case.set_state`, `platform.lookup`, `source.sample`, `hunt.daily` or
`hunt.pack`.

`tests/unit/test_security_invariants.py` pins both halves: the onboarding
capabilities are reachable in operator mode, the approval and run capabilities
are not, and any string other than `human` or `operator` leaves the client an
external agent.

## Drawbacks

Credentials pass through the assistant's context and its provider's logs. That
is true of `human` mode today and of pasting a token into any chat; the operator
chooses it.

## Alternatives

- **Do nothing.** Onboarding over MCP keeps requiring `human` mode and its
  approvals.
- **Give `external_agent` the onboarding scopes.** A model reading
  attacker-written log content could repoint an existing source's `org_url`:
  `source.configure` keeps the stored secret when none is sent, so the next poll
  would carry the token to that host. It could also point `notify` credentials at
  a webhook it controls. Rejected.
- **Let external agents add sources but never edit one.** Closes the first case,
  still leaves action credentials, and costs a second code path in
  `source.configure`. Rejected.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: a new accepted value for `SHOC_MCP_PRINCIPAL`. No
  capability, tool name or schema changes.

## Security considerations

The operator can store credentials, which is L2 by design (`action.configure`).
A prompt injection that reaches an operator-mode client can therefore repoint a
source or an action credential, but cannot approve or run the action that would
use it. Set `operator` only on a stdio server whose client the operator drives,
as with `human`. Every call is audited under `SHOC_MCP_USER`.

## Unresolved questions

- Whether `slack.configure` belongs in operator mode. It is left out until
  someone needs to set up Slack from an assistant.
- The streamable-HTTP `/mcp` mount reads the same variable. Binding the MCP
  principal to the bearer token instead is a separate change.

## Adoption and migration

Off unless set. Existing `human` and default deployments behave as before.
