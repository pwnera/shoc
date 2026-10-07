---
rfc: 0007
title: Configure the crew's model without a restart
status: accepted
authors: ["@Rettila"]
created: 2026-09-25
requirements: ["AGT-5", "API-1", "SEC-1"]
supersedes: null
---

# RFC 0007: Configure the crew's model without a restart

## Summary

The provider, model, base URL and API key the crew uses move out of the process
environment and into stored per-tenant configuration, changed with
`shoc llm configure` and picked up by the next case with nothing restarted.
`SHOC_LLM_*` keeps working as the bootstrap default for a fresh install; once a
stored setting exists, it wins.

## Motivation

Every other configurable thing in shoc is already changeable at runtime.
`source.configure`, `intel.configure` and `slack.configure` write to
`shoc.connector_config` and are read back on the next call: `load_app` in
`shoc/api/slack.py` reads the row on every callback. The crew's model is the
exception: `Config` reads `os.environ` in its field defaults, each process
builds one `Config` at startup, and a process cannot have its environment
changed from outside.

The cost of that showed up the first time a gateway misbehaved. A deployment
pointed at a third-party gateway got `{"code":500,"msg":"The server is
currently being maintained"}` on every completion. Moving to another model
meant editing `deploy/.env` and recreating two containers. `docker compose
restart` is not enough (environment is fixed when a container is created), so
the obvious remedy silently changes nothing, which is a bad failure to hand
someone at 3am.

For a product that claims to run 24/7 for companies with no security team, "the
crew is down until someone with SSH access redeploys" is the wrong blast radius
for a provider outage. Two smaller motivations follow from the same change: a
`tenant_id` already keys `connector_config`, so per-tenant models come for free
(principle 7), and the API key stops living in the environment of every
container and every `docker inspect`.

## Guide-level explanation

```
$ shoc llm show
provider=openai model=gemini-2.5-pro base_url=https://api.kie.ai/v1 key=set (from environment)

$ shoc llm configure --provider anthropic --model claude-sonnet-5 --api-key sk-ant-…
the crew now uses anthropic/claude-sonnet-5; the next case picks it up

$ shoc llm show
provider=anthropic model=claude-sonnet-5 base_url=(default) key=set (stored)
```

No restart, no deploy, and `shoc health status` reports which model answered the
last case. Clearing the stored row falls back to the environment:

```
$ shoc llm configure --clear
stored configuration removed; the crew falls back to SHOC_LLM_* (openai/gemini-2.5-pro)
```

An install that never runs `llm configure` behaves exactly as it does today.

## Reference-level explanation

**Storage.** Reuse `shoc.connector_config` with `source='llm'`, the way Slack
reuses it with `source='slack'`. No migration: the table already has
`settings jsonb` for `{provider, model, base_url}`, `secret bytea` for the
sealed key, and `(tenant_id, source)` as its primary key. Row-level security
already covers `connector_config` (migration `007`), so a tenant cannot read
another tenant's model configuration.

**Reading.** `from_config(config, conn=None)` gains an optional connection. With
one, it reads the row, unseals the key with `seal`/`open_secret` from
`shoc/db/secrets.py`, and overlays the stored values on the `Config` ones field
by field: a stored `model` with no stored `base_url` keeps the environment's
base URL. Without a connection, or with no row, behaviour is unchanged. The five
call sites (`shoc/capabilities/intel.py`, `shoc/capabilities/ops.py`,
`shoc/cases/review.py`, `shoc/agents/loop.py`, `shoc/agents/hunter.py`) already
run inside a `Context` holding a connection, so each passes `ctx.db`.

The read is one primary-key lookup on a connection that is already open, once
per capability call, not once per model turn. No cache, no invalidation, no TTL
to reason about. If that lookup ever shows up in a profile, a version column is
the cheap fix; measuring first is cheaper still.

**Precedence.** Stored wins over environment. The alternative makes
`llm.configure` a no-op on any deployment that also sets `SHOC_LLM_*`, which is
every deployment using the compose file, and a control that silently does
nothing is worse than no control.

**Capabilities.** Two, both in the registry, both generating their own REST,
MCP and CLI surfaces:

- `llm.configure`: scope `llm:write`, autonomy **L2**, principals `("human",)`,
  audited. Same shape as `slack.configure`.
- `llm.show`: scope `llm:read`, autonomy L0, key never returned, only
  `set`/`unset` and where the value came from.

**Failure modes.** A stored configuration naming an unreachable provider breaks
the crew until someone fixes it, exactly as a bad environment variable does
today, except the repair no longer needs host access. If the master key has been
rotated since the row was written, `open_secret` fails; `llm.show` reports the
row as unreadable rather than pretending the key is unset. If a provider answers
without a completion, the client raises a `ConfigError` quoting the provider's
own message. That is the change that turned the gateway outage above from "the
model did not return JSON" into something diagnosable.

**Cost accounting.** `price_for` in `shoc/agents/ops.py` matches a model name
against a hardcoded table and returns `(0.0, 0.0)` for anything it does not
recognise, so spend on an unlisted model records as $0. That is already wrong
today (the gateway deployment is recording zero for every call), and runtime
model switching makes it wronger, because the model can now change without
anyone touching the deployment that would prompt them to set
`SHOC_LLM_PRICE_IN`/`_OUT`. Prices belong in the stored settings alongside the
model. This RFC proposes storing them there and leaving the environment
overrides as a fallback.

**Principles touched.** Principle 1 (headless first): the operation starts as a
capability and the CLI is generated, not hand-written. Principle 5 (bounded
autonomy): L2, human-only, audited. Principle 3 is untouched: no new
dependency, no new service.

## Drawbacks

Configuration now lives in two places, and "why is it using that model?" becomes
a question with two answers. `llm.show` naming the source of each value is the
mitigation, and it is the same trade already made for connectors.

The API key moves from process environment to Postgres. Both are recoverable by
anyone who owns the host; the database at least keeps it out of `docker inspect`
and out of the environment of every child process.

A runtime-settable `base_url` is a real new risk, discussed below.

## Alternatives

**Do nothing.** Every model change stays a deploy. Acceptable if the crew is
optional and outages are rare; neither holds for a 24/7 product whose provider
is a third-party gateway.

**Re-read a file on each call.** `SHOC_LLM_CONFIG=/etc/shoc/llm.yaml`, stat and
reload when the mtime changes. No migration, no capability, and it works, but
it is not reachable over the API or MCP, it is not per-tenant, it has no audit
trail, and it needs the file mounted into both containers. It solves the restart
and nothing else, and it invents a second configuration mechanism that the rest
of the system does not use.

**SIGHUP to reload the environment.** A process cannot see a changed
environment; this would mean re-reading a file anyway, with signals added.

**A generic `shoc.settings` table.** Cleaner in the abstract. It is also a new
table, a new access pattern and a new thing to secure, to hold one row. If a
third non-connector consumer appears, that is the moment to extract it.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: two new capability names (`llm.configure`,
  `llm.show`) with their generated REST paths and MCP tools, and two new scopes
  (`llm:write`, `llm:read`). No change to `EventStore`, OCSF layout or any YAML
  format. Additive: nothing existing changes shape.

## Security considerations

`llm.configure` is L2 and `principals=("human",)`, so the registry refuses it
for `agent` and `external_agent` before the body runs. A prompt-injected agent
cannot reconfigure the model it runs on, which matters more than usual here: the
capability that chooses where evidence is sent must not be reachable from the
evidence.

**The base URL is the sharp edge.** Today, redirecting the crew's traffic
requires host access to change an environment variable. After this change, an
attacker holding a human token, or a Slack approver's account, can point
`base_url` at a server they control and receive every case's prompt (real log
lines, account identifiers, internal hostnames) with no deploy and no file
touched. The audit row records it, which helps afterwards and not during.

Two mitigations, and I would like a decision on the first before this is
accepted:

1. `SHOC_LLM_BASE_URL_ALLOWLIST`, a comma-separated list of hosts a stored
   `base_url` may name. Unset means "the current environment value and the two
   provider defaults". This keeps the dangerous field pinned to the deployment
   while the model, provider and key stay runtime-settable.
2. `llm.show` reports the base URL in full to any reader with `llm:read`, and
   `health.status` names the host the last completion went to, so a redirect is
   visible without reading the audit log.

The key is sealed with the master key, as connector secrets are. `llm.show`
never returns it. It is decrypted in the worker's memory and sent only to the
configured provider.

## Unresolved questions

- The base URL allowlist: ship it with this RFC, or accept the risk and record
  it as a decision? My reading is that runtime model switching is worth having
  and runtime *endpoint* switching mostly is not, so the allowlist should be in
  the first version.
- Do stored prices belong here or in a separate change to `health.cost`? They
  are a correctness bug today, independent of this RFC.
- Should `llm.configure` validate by making one cheap completion before storing?
  It turns a typo into an immediate error instead of a broken next case, at the
  cost of a call and a slower, sometimes-failing write.

## Adoption and migration

No migration and no feature flag. Existing installs keep reading `SHOC_LLM_*`
and behave identically until someone runs `llm configure`. `--clear` returns a
deployment to environment-only. The compose file and Helm chart keep their
`SHOC_LLM_*` variables as the bootstrap path, and the quick start keeps showing
environment variables, with `llm configure` documented as how to change a model
on a running deployment.

## Resolution

Accepted on 2026-09-30 and recorded as D72. The allowlist ships in the first
version. Stored prices and a test completion before storing are left out:
prices are a separate fix to `health.cost`, and a bad model shows up on the
next case as a provider error the case records. `model_cheap` is stored
alongside `model` so the narrow roles move with it. `slack` and `llm` rows are
excluded from `source.list`, the Integrator and config-as-code pruning, since
neither is a source.
