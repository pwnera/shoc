---
rfc: 0019
title: Issue and revoke bearer tokens through the registry
status: accepted
authors: ["@Rettila"]
created: 2026-09-29
requirements: ["API-1", "SEC-1"]
supersedes: null
---

# RFC 0019: Issue and revoke bearer tokens through the registry

## Summary

`token.create`, `token.list` and `token.revoke` issue, list and revoke bearer
tokens for the four roles of RFC 0018 and for machines. The token is shown once
and shoc keeps its SHA-256 in `shoc.api_tokens`. Revoking or expiring a token
takes effect on the next request, with no restart. `SHOC_TOKENS` keeps working
and becomes the way the first admin gets in.

## Motivation

Before this RFC every token lived in `SHOC_TOKENS`, a JSON map in the process
environment:

- A token was stored in plain text in `.env` or a Kubernetes secret.
- Giving someone access, changing their role or taking it away meant editing
  JSON by hand and restarting `serve` and `worker`.
- Nothing said who held a token, since when, or who issued it, and a token
  could not expire.
- The operator is usually absent. A token that leaks while nobody is watching
  has to be revocable from wherever the operator is, including their assistant,
  without a shell on the host.

## Guide-level explanation

On a fresh install, from the host:

```bash
shoc token create --who rettila@example.com --role admin
```

The answer carries the token once. From then on everything goes through the
registry, from the CLI, REST, MCP or the console's API screen:

```bash
shoc token create --who alice@example.com --role operator --expires-days 90
shoc token create --who wazuh --kind service --scopes events:write
shoc token list
shoc token revoke --token-id tok_3f2a9c01b7d4
```

Over MCP, `token.create` and `token.revoke` are L2, so the person confirms each
one in their client's prompt before it runs.

## Reference-level explanation

- **Table.** `shoc.api_tokens` (migration 027): `tenant_id`, `token_id`, the
  token's SHA-256, `who`, `role` or `kind` and `scopes`, `created_by`,
  `expires_at`, `revoked_at`, `revoked_by`. Row-level security like every other
  table. Rows are never deleted.
- **Token.** `shoc_` followed by 32 random bytes, URL-safe. The prefix lets
  secret scanners recognise it. 32 random bytes cannot be recovered from their
  hash, so no salt or slow hash is needed, and the lookup is an index hit on the
  hash.
- **Lookup.** `authenticate` checks `SHOC_TOKENS` first, then the table, across
  tenants: the token names its tenant. The lookup pins the connection to
  `shoc:all` and unpins it before returning.
- **Single-user mode.** It ends with the first token ever issued, revoked or
  not. Revoking every token locks the API; `shoc token create` on the host
  issues a new one. A process remembers that a token exists, so single-user
  checks stop querying once one does. `shoc serve` binds off loopback once a
  token exists.
- **Capabilities.** `token.create` and `token.revoke` need `tokens:write`, are
  L2, human-only and audited. Only `admin` holds `tokens:write`, so no other
  role can issue itself a wider one. `token.list` needs `tokens:read` and never
  returns a hash. A token acts on the tenant it was issued in.
- **Expiry.** `expires_days` is 0 (never) by default. A machine token that
  expires stops ingestion with nobody watching, so expiry is chosen, not
  imposed.

## Drawbacks

- Every request with a stored token costs one indexed query.
- Two sources of tokens until `SHOC_TOKENS` is retired, if it ever is.

## Alternatives

- **A `shoc token new` helper that prints a line to paste into `SHOC_TOKENS`.**
  Removes the hand-made random string and nothing else: tokens stay in plain
  text, revoking still needs a restart.
- **Hashing inside `SHOC_TOKENS`.** Keeps restarts and hand-edited JSON.
- **OIDC.** A second service to run, against principle 3.

## Dependency and scope impact

- New dependencies: none (`hashlib`, `secrets`).
- New required services: none.
- Public contract: three capabilities, the `tokens` scope area, migration 027.
  `authenticate` and `check_bind` take an optional config.

## Security considerations

- `token.create` returns a secret once; it is in the security invariants' list
  of secret-returning capabilities, human-only and audited. The audit row keeps
  a hash of the output, never the token.
- An assistant cannot mint or revoke a token on its own: both are L2 and wait
  for the person's confirmation over MCP.
- Someone who can read `shoc.api_tokens` learns who holds tokens and their
  hashes, which cannot be used to authenticate.
- Someone who can write it can add a token. That is the same trust already
  placed in whoever can write `shoc.connector_config` or the audit log.

## Unresolved questions

- Whether the weekly report should list tokens that expire in the next two
  weeks.
- Whether `SHOC_TOKENS` should be retired once installs have moved over.

## Adoption and migration

Migration 027 creates the table. Existing `SHOC_TOKENS` entries keep working
unchanged. An install that runs in single-user mode stays there until its first
`token.create`.
