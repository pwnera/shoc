# Security model

shoc reads a company's most sensitive logs and, later, acts on their systems.
This page states what it assumes, what it enforces and what it leaves to you.

## Principals

| Principal | Arrives through | Rights |
| --- | --- | --- |
| Human | CLI, the console with a session, Slack, an assistant over MCP | Those of the person's role (below). The CLI and single-user mode are `admin` |
| Crew agent | Internal tool calls | Per crew role; L1 actions only where policy allows |
| External agent | MCP with no role (a teammate's assistant, a partner bot) | Read, ask, post to a case, add facts and indicators, run hunts. Never propose or approve an action |
| Service | REST, ingest, webhooks | The scopes its token lists |

Every capability declares which principal kinds may call it and which scope they
need. `Capability.invoke` checks the principal, then the scope, then autonomy,
before any code runs. An `L2` capability refuses every non-human principal, and
that check is in the registry, not in a policy file someone can edit.

### Roles

A person's account or token, and the `shoc mcp` stdio client, name one of four
roles (RFC 0018). All four are human principals.

| Role | Can |
| --- | --- |
| `admin` | Everything |
| `operator` | Read everything; propose, approve, reject, run and undo actions; work cases, findings, rules, detections, hunts and intel; merge and run playbooks; refresh the graph and posture; record shoc's own assets |
| `deployer` | Read everything; connect sources, store action credentials, configure intel feeds, Slack, the LLM and webhooks, record shoc's own assets, apply config as code |
| `reader` | Read everything |

A listed Slack approver is an `operator`.

### Tokens and single-user mode

`token.create` issues a bearer token for a person, with a role, or for a
machine, with a kind and scopes (RFC 0019). The answer carries the token once;
`shoc.api_tokens` keeps its SHA-256. `token.revoke` ends it on the next
request, and `expires_days` makes it end on its own. Issuing and revoking are L2
and need `tokens:write`, which only `admin` holds.

```bash
shoc token create --who rettila@example.com --role admin
shoc token create --who alice@example.com --role operator --expires-days 90
shoc token create --who loader --kind service --scopes events:write
shoc token list
shoc token revoke --token-id tok_3f2a9c01b7d4
```

`SHOC_TOKENS` is the other way in, and the one that needs no database write:
it maps each bearer token to a caller and a tenant. A person's entry names a
role, `{"role": "operator", "id": "alice"}`; a machine's names a kind and its
scopes, `{"kind": "service", "id": "ci", "scopes": ["events:write"]}`. An entry
with no scopes holds none. Changing it needs a restart.

REST, `/ingest`, `/v1/stream`, `/metrics` and `/mcp` check both the same way,
and a token acts on its own tenant only: a request whose `x-shoc-tenant` header
names another is refused. A request with no credential, or with a token that is
unknown, expired or revoked, is 401 `unauthenticated`. A token short of the
scope, principal or autonomy a call needs, or naming another tenant, is 403
`denied`.

With no token in `SHOC_TOKENS`, none ever issued and no account, shoc is in
single-user mode and every caller is a human with every scope, which includes
approving an L2 action. The first token or the first account ends it for good:
revoking every token and disabling every account locks the API, and
`shoc token create` or `shoc user invite` on the host lets a person in again.
Single-user mode is meant for the person at this machine (D63), so while it
lasts:

- `shoc serve` refuses to start unless the published address is loopback:
  `SHOC_BIND` when it is set (Compose sets it), `--host` otherwise. The Helm
  chart requires `SHOC_TOKENS` when it creates the secret.
- A request carrying `Forwarded`, `X-Forwarded-For` or `X-Real-IP` is refused,
  because a proxy in front makes the port reachable from wherever the proxy is.
- A request whose `Host` or `Origin` is not localhost is refused. A web page the
  operator opens can reach loopback, by a cross-site POST or by DNS rebinding,
  and both give themselves away there. `/mcp` checks the same.

A proxy that adds no forwarding header and rewrites `Host` to loopback is not
detected; a token is the fix for any proxy. An HTTP client of `/mcp` with
no token is an external agent even in single-user mode.

### People sign in

A person signs in to the console starting from their email (RFC 0028). An
email in a domain of the company's identity provider sends the browser there
over OpenID Connect, and it comes back signed in. Any other email asks for a
password, then a six-digit code from an authenticator app, and the console
sends all three in one request, so a right password answers the same as a
wrong one. Accounts come from an admin's invitation, or from a first sign-in
through the provider with an address in one of its domains, which joins as
`reader`.

```bash
shoc user invite you@example.com --role admin
shoc user update --email bob@example.com --role operator
shoc user update --email bob@example.com --disabled
shoc user update --email bob@example.com --no-disabled
shoc user reset --email bob@example.com
shoc user list
```

`user.invite`, `user.reset`, `user.update` and `sso.configure` are L2 and need
`users:write` or `sso:write`, which only `admin` holds, as with `tokens:write`.
`user.list` and `sso.show` need `users:read` and `sso:read`, which every role
holds through `*:read`; neither returns a hash or a secret. Disabling a person
ends their sessions, their links and the role tokens issued to their email, and
`--no-disabled` lets them sign in again. `user.update` refuses to leave no
active admin.

`SHOC_PUBLIC_URL`, the console's origin as people reach it, is required for any
sign-in. Emailed links and the SSO redirect URI are built from it and never
from the request, it is the only `Origin` a sign-in is accepted from, and an
`https` scheme makes the cookie `Secure`. Without it the routes below answer
503 `sign_in_not_configured`.

Signing in sets cookies and follows redirects before there is a caller, so it
cannot be a capability. These routes do that and nothing else, and managing
people is left to the capabilities above. They answer JSON with
`Cache-Control: no-store`, errors as `{"error": {code, message}}`, and they are
not part of the frozen contract.

| Route | Does |
| --- | --- |
| `POST /auth/start {email, return_to}` | Answers `{"method": "password"}`, or for an SSO domain `{"method": "sso", "url": …}`, the provider's authorize URL with `state`, `nonce`, PKCE (S256) and `login_hint`, plus a sealed state cookie: `__Host-shoc_sso` with path `/` when `SHOC_PUBLIC_URL` is `https`, else `shoc_sso` with path `/auth/sso`; HttpOnly, `SameSite=Lax`, 10 minutes. `return_to` must be a path on this origin. The answer never says whether an account exists |
| `GET /auth/sso/callback` | Opens the state cookie, checks `state`, which works once, and RFC 9207 `iss` when sent, exchanges the code with the verifier and the client secret, checks the ID token, sets the session cookie and redirects to `return_to`. A failure redirects to `/?signin=<code>` |
| `POST /auth/login {email, password, code}` | Checks all three and sets the session cookie. A throttled attempt is 429 `slow_down`; every other failure is 401 `bad_credentials`, the same for an unknown email, a wrong password, a wrong code, a locked or disabled account and a password account in an SSO domain |
| `POST /auth/token {token}` | Makes a person's token (one with a role) the session cookie, for up to 12 hours, or until the token ends if sooner. A machine token is 401 `bad_credentials` |
| `POST /auth/link {link}` | Answers the link's email and, for an enrolling link, the new authenticator's `otpauth://` URI. An unknown, used or expired link is 410 `link_expired` |
| `POST /auth/link/accept {link, password, code}` | Sets the password, and for an enrolling link the authenticator, once the code checks. Ends the link and the person's other links and sessions, and signs this browser in. A wrong code is 401 `bad_code`, and the fifth ends the link |
| `POST /auth/forgot {email}` | Emails an active password account a link that keeps its authenticator, at most one per 5 minutes, from a background thread so the answer takes as long either way. Always `{"sent": true}`, or `{"sent": false}` when mail is not configured |
| `POST /auth/logout` | Revokes the session and clears the cookie. A token used through `/auth/token` stays live; `token.revoke` ends it |

Every `POST` to these routes, and every `POST` that relies on the session
cookie, must carry `Content-Type: application/json` and an `Origin` equal to
`SHOC_PUBLIC_URL`'s, or it is refused with 403 `cross_site`. That stops a
cross-site form, a `text/plain` post and a page on another port of the same
host, which `SameSite` does not cover.

The session cookie is `__Host-shoc_session` when `SHOC_PUBLIC_URL` is `https`,
and `shoc_session` otherwise. It is HttpOnly, `SameSite=Strict`, path `/`, and
lasts 12 hours. A request with more than one is refused. The cookie holds a
session token, kept like any other as a SHA-256 row in `shoc.api_tokens`, with
the account's `user_id` and no role of its own. `authenticate` reads a bearer
token first, then the cookie. A session takes its role from the account on
every request, so a role change applies on the next one and a disabled account
is signed out. The caller is a human whose id is the email, so the audit log
names the person. A cookie that names no live session is 401 `signed_out`, and
the event stream checks its caller again every 30 seconds and ends with the
session. No script on the page can read the cookie, the console keeps no
credential in storage, and "Log out" clears the tab's session storage.

Passwords, codes and links:

- A password is 12 to 256 characters and not the email. It is hashed with
  `hashlib.scrypt` (n=2^15, r=8, p=1, a 16-byte salt) on two threads of its
  own, so a burst of sign-ins cannot starve the API. An unknown email is hashed
  too, so it takes as long as a known one.
- The authenticator follows RFC 6238: SHA-1, six digits, 30-second steps, one
  step either side. A step is accepted only above the last one used, in the same
  `UPDATE`, so a code works once even under concurrent requests. Every account
  with a password has one, and nobody signs in with a password alone.
- Sessions and links are 32 random bytes kept as SHA-256. The authenticator's
  seed is sealed in the account's row. The seed an enrolling link offers is
  derived from the master key and the link each time, and never stored.
- `user.invite` creates the account and a link valid 7 days, and `user.reset` a
  link valid 1 day. Both enrol, so accepting sets a new password and a new
  authenticator, and both are refused until `SHOC_PUBLIC_URL` is set. In an SSO
  domain an invitation creates the account with no link, and a reset is
  refused.
- "Forgot password" emails a link that sets a new password and keeps the
  authenticator, so a stolen mailbox alone does not open the account. A lost
  phone needs an admin's reset.
- A link is built from `SHOC_PUBLIC_URL`, emailed only to the stored address,
  and carried in the URL fragment (`/welcome#…`), which reaches no server and no
  `Referer`. A new link ends the person's earlier ones. Without mail, or when
  the mail cannot be sent, `user.invite` and `user.reset` return the link once,
  like a token, and over MCP that puts it in the assistant's context.

Wrong passwords and codes:

- A wrong password is throttled per account and client address, 10 in 15
  minutes, and answers 429 `slow_down` past that. It never locks the account,
  so knowing the admin's email is not enough to lock them out.
- Every `POST` to `/auth/*` and every SSO callback counts against a cap of 100
  per client address in 15 minutes, also answered with 429 `slow_down`. Both
  send `Retry-After: 900`; a sign-in turned away because 16 already wait for
  the hashing threads gets `Retry-After: 5`.
- The client address is the socket's, unless the socket is in
  `SHOC_TRUSTED_PROXIES` (loopback and `172.16.0.0/12` by default). Then it is
  the first `X-Forwarded-For` entry, read from the right, outside those
  networks. A TLS terminator in front of the console must append
  `X-Forwarded-For`, or everyone behind it shares one address.
- A wrong code needs the right password first, so it counts against the
  account. Five lock it for 15 minutes, then 30, 60 and so on up to a day, and
  email the person when mail is configured. Only a completed sign-in resets the
  count. Wrong codes on a link that keeps the authenticator count too.
- A lock writes one `auth.locked` row to the audit log. Other failures are not
  audited, so a guesser cannot fill the chain. Sign-ins (`auth.signin`) and
  accepted links (`auth.link_accepted`) are audited under the person.

For single sign-on, an admin registers `<SHOC_PUBLIC_URL>/auth/sso/callback` as
the redirect URI at the provider, then runs `sso.configure` with the issuer, the
client id and secret, and the company's domains.

- `sso.configure` reads the issuer's discovery document and stores its
  endpoints. The issuer and every endpoint must be `https` on a public address,
  the document must name the issuer exactly, and Microsoft's shared `common`,
  `organizations` and `consumers` issuers are refused. It refuses while no admin
  exists, since the first person through SSO joins as `reader`.
- The ID token must be signed with RS256, PS256 or ES256 by a key from the
  provider's JWKS, cached an hour. It must name the issuer exactly, hold the
  client id in `aud` (and in `azp` when present), be current within 60 seconds
  and carry the nonce.
- Its `email` must be in a configured domain and vouched for by the provider:
  `email_verified` true, plus `hd` in the domains for Google. For Microsoft, the
  token's `tid` must be the issuer's tenant, and a guest (`idp` present) is
  refused, since a member's address is set by the company's administrators. A
  token without an `email` claim signs nobody in.
- A person is found by issuer and subject. On a first sign-in they are found by
  email and linked, or join as `reader`. After that only the subject is matched.
- When `sso.configure` moves to another issuer, a person linked to the old one
  is found by email on their next sign-in and linked to the new one. The same
  issuer with a new subject for a linked email is refused.
- The round trip's state, nonce, PKCE verifier, tenant and return page travel in
  the state cookie, sealed with the master key, so it can be neither read nor
  forged. Each `shoc serve` process accepts a state once.
- A password account in an SSO domain cannot use its password, because the
  provider is how the company takes access away. When the provider is down, the
  way in is a token.

### An assistant asks, the person confirms

Most of the time the person works through an assistant, and the assistant is a
model that reads log content an attacker can write. So a role says what the
person may do, and an L2 call that arrives over MCP (`action.approve`,
`action.undo`, `case.close`, `credential.configure`, `config.apply`,
`llm.configure`, `slack.configure`, and every other L2 capability) does not run
until the person confirms it:

1. The assistant calls the tool.
2. shoc sends the client an elicitation: a yes-or-no prompt that shoc writes,
   naming the action, its target and its rationale. The client shows it to the
   person; the model does not answer it.
3. On yes, the call runs and is audited under the person's id. On anything
   else, nothing changes and the tool answers `declined`.

A client that does not support elicitation gets `confirmation_required`, and
the person approves in Slack or runs the `shoc` command in a terminal. A
person who confirms without reading the prompt approves what the model asked
for; the prompt names the target so that reading it takes seconds.

For the stdio client:

```
SHOC_MCP_ROLE=operator
SHOC_MCP_USER=<who this is>        # recorded in the audit log
```

Any value but the exact name of a role leaves the client an external agent. An
HTTP client of `/mcp` is whatever its bearer token names, and its sessions are
stateful so that the prompt and the answer travel on the same session.

## Bounded autonomy

- **L0**: notify only.
- **L1**: act automatically, but only on pre-approved, reversible actions.
- **L2**: a human approves, in Slack or any client, within four hours. Past that
  a `high` or `critical` case pages once, and anything lower is rejected with the
  reason written into the case (D37).

New installs default to dry run (`SHOC_DRY_RUN=1`): actions are proposed and
recorded, never executed.

## Evidence or nothing

A verdict without cited event IDs is downgraded to "needs human". A citation
counts when the event exists and belongs to the work: one of the case's own
events, one the crew cited there before, or one a lookup returned during the
run. A Hunter's `explained` cites the tuple's events too. A revised verdict
stands on its own citations, never on the first round's. The eval harness fails
a scenario that produces an uncited finding, and the conformance suite works
every prompt-injection scenario with a scripted model that obeys the injected
text: CI fails if log content reaches a prompt outside a data block or the
attacker's verdict is recorded.

## Untrusted content

Log content is attacker-controlled. It is quoted into prompts as data and never
followed as instructions, and so is everything written after reading it: a
role's reasoning handed to the next, a question to a peer, earlier openspace
messages and a tool's error. Agent outputs are schema-checked before they become
messages; agents hold a read-only database role and no action credentials.
On a warehouse it is a principal, role, user or service account that `shoc
migrate` grants `SELECT` on each tenant's catalog, database, schema or dataset,
and on every backend the
store's read path runs nothing but a single `SELECT`.

## Audit

Every audited capability call, and every change of an action's state, appends a
row to `shoc.audit_log` under the principal that made it. A worker records
`action.started` before it calls the provider, so a crash mid-call still leaves
a row, and `ops.alerts` raises `action.stuck` for an action left running over an
hour. Each row carries an HMAC of the previous row's hash and its own fields,
keyed from `SHOC_MASTER_KEY`, and triggers refuse UPDATE, DELETE and TRUNCATE.

`shoc migrate` records a fingerprint of the key in `shoc.audit_key`. A process
whose key is empty or different refuses to write or verify the log, so a shell
or an MCP client started with the wrong environment fails instead of adding a
row that would never verify.

`shoc health audit` walks the whole chain and counts every row that does not
match. The worker runs it every hour from `ops.check`; a break it has not seen
before pages the operator through the Manager (`audit_broken`) and publishes
`health.audit.broken` once. The same break does not page again, and a later one
does, because rows after a break are still checked.

Without the master key, nobody can edit, insert or re-chain rows and have the
chain verify, including the database role shoc runs as. That role does not own
the schema (RFC 0024): `shoc migrate` connects as the owner (`SHOC_MIGRATE_DSN`)
and grants the runtime role (`SHOC_DSN`) SELECT and INSERT on the audit log and
SELECT on its key tables, so `serve` and `worker` cannot disable the triggers,
delete or truncate. Compose and the Helm chart run that way. With one DSN for
both, `migrate`, `serve` and `worker` warn that the runtime role owns the log.

The owner, or a superuser, can still delete the newest rows and leave a chain
that verifies. Every webhook delivery carries the tenant's chain head
(`audit_head`, `seq:hash`) in its signed body, so a subscriber holds a copy
outside Postgres; `shoc health audit --head <seq:hash>` fails when the chain no
longer holds that row as it was.

`shoc rotate-key` moves the chain to a new master key. The old chain key is
kept in `shoc.audit_epochs`, sealed with the new master key, and each chain gets
an `audit.rekey` row keyed with the new key and chained onto the old head, so
every older row still verifies.

## Secrets

Connector, action, feed, webhook, Slack, LLM and SSO credentials, and each
account's authenticator seed, are encrypted with AES-256-GCM under a key
derived from `SHOC_MASTER_KEY` before they reach the database. The row a value
is stored in (tenant, table and source, provider, feed or account) is its
associated data, so a value copied into another row or another tenant does not
open. Values sealed before that, with Fernet and bound to
nothing, are sealed again by `shoc migrate`, and one that is left is refused.
Lose the key and the secrets are unrecoverable by design. Rotate a credential by
re-running `source configure`, and the key itself with `shoc rotate-key`, which
seals every value again under the new key in the same transaction that moves
the audit chain.

Passwords are kept as scrypt hashes, and sessions, links and tokens as SHA-256.
The read-only role agents query through cannot read accounts, links, SSO
settings or tokens; `shoc grant-readonly` revokes them.

## Tenancy

`tenant_id` is in every table and every call, and each tenant's events live in
their own Postgres schema (catalog on Databricks, database on Snowflake, schema
on Redshift, dataset on BigQuery).
Isolation is enforced in the adapter and the database, never in a prompt.

A request names its tenant in `X-Shoc-Tenant`. `shoc:all`, the database's
setting for every tenant, is refused there with a 403. A token or a session acts
on its own tenant, and a header that names another is refused the same way
(D63). A browser that is not signed in yet signs in to the tenant its header
names, else `SHOC_TENANT`; emails are unique within a tenant, and an SSO domain
belongs to one provider within it.

## What is yours to do

- Terminate TLS in front of `shoc serve`, and issue a token or invite an account
  before exposing it beyond loopback, a reverse proxy on the same host included.
- Set `SHOC_PUBLIC_URL` to the address people open the console at, and serve
  the console over `https` (`tailscale serve` will do). On plain `http` the
  session cookie is sent to every port of the host, so another service on the
  same address could read it.
- Have the TLS terminator in front of the console append `X-Forwarded-For`,
  and add its address to `SHOC_TRUSTED_PROXIES` when it runs on another host,
  so sign-in limits count each person's address rather than the proxy's.
- Configure mail (`SHOC_SMTP_URL`) wherever an assistant manages people.
  Without it, invitation and reset links come back in the answer, which over
  MCP is the assistant's context. Confirm a reset request with the person
  another way before you issue one, since its link replaces the password and
  the authenticator.
- Keep SSO domains to the company's own. Anyone the provider vouches for at
  one of them joins as `reader`, which reads every event and finding.
- Give each connector a read-only credential with the narrowest scope.
- Back up Postgres: it holds the audit log, the findings and your configuration.
- Keep `SHOC_MASTER_KEY` outside the database and outside the image.
- Outside Compose and the chart, give `serve` and `worker` a database role that
  does not own the schema, and keep the owner's DSN for `shoc migrate`.
- Give each person the narrowest role that fits, and each machine token only
  the scopes it uses. Keep `admin` to the one or two people who need it.
- `SHOC_INTEL_FEEDS=off` if shoc should open no outbound connection you did not
  configure. By default it pulls two public abuse.ch feeds every six hours and
  the lists lookups answer from once a day (the quick start names the hosts).

Report vulnerabilities as described in [`SECURITY.md`](https://github.com/pwnera/shoc/blob/main/SECURITY.md).
