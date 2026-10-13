# Security model

shoc reads a company's most sensitive logs and, later, acts on their systems.
This page states what it assumes, what it enforces and what it leaves to you.

## Principals

| Principal | Arrives through | Rights |
| --- | --- | --- |
| Human | CLI, the console with a session, Slack, an assistant over MCP | Those of the person's role (below). The CLI and single-user mode are `admin`. The CLI is trusted host access: whoever can run it also holds the DSN and the master key. Its caller is recorded as `cli:<SHOC_CLI_USER>`, or `cli` when the variable is unset, a name the person running it declares and nothing authenticates; it attributes an honest operator and stops no one |
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

A listed Slack approver is an `operator`. A listed Slack reader is an external
agent with the `events`, `findings`, `cases`, `ask` and `health` read scopes,
and a Slack user on neither list gets `/shoc help` and a refusal
([`slack.md`](slack.md)).

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
clears their password and authenticator. `--no-disabled` re-enables the
account; a password account then needs `user.reset` to set a new password and
authenticator before it can sign in, and an SSO account signs in as before.
Changing a person's role also revokes any role token issued to their email
under a different role, since a role token keeps the role it was issued with,
and the summary names those tokens. `user.update` refuses to leave no active
admin.

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
| `POST /auth/forgot {email}` | Emails an active password account a link that keeps its authenticator, at most one per 5 minutes. The work runs on two threads of its own, so the answer takes as long either way and a burst of requests waits in a queue instead of each opening a database connection. Always `{"sent": true}`, or `{"sent": false}` when mail is not configured |
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
every request, so a role change applies on the next one (role tokens issued to
the email under another role are revoked by the same `user.update`) and a
disabled account is signed out. The caller is a human whose id is the email, so the audit log
names the person. A cookie that names no live session is 401 `signed_out`, and
the event stream checks its caller again every 30 seconds and ends with the
session. No script on the page can read the cookie and the console keeps no
credential in storage. The console keeps the signed-in `user.me` id under
`shoc.owner`, beside the crew thread in the tab's session storage (`shoc.chat`)
and beside the recent records and queries in local storage (`shoc.recent`,
`shoc.explore.recent`). Those belong to that person: "Log out" removes them, and
so does a sign-in by someone else on the same browser (SEC-3). A link the
console builds from kernel data (a rule or hunt reference, an intel report URL)
is clickable only when it is `http` or `https`; any other scheme shows as plain
text, and the console's lint rules stop any screen from rendering HTML.

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

- `/auth/*` refuses `X-Shoc-Tenant: shoc:all`, as the API does.
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
  provider's JWKS, which is fetched like discovery and the token exchange
  (`https` to a public host, no redirects) and kept an hour. It must name the
  issuer exactly, hold the client id in `aud` (and in `azp` when present), be
  current within 60 seconds and carry the nonce.
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

The prompt is never cut. One that would run past 600 characters refuses the
call with `confirmation_required` and points to the `shoc <area> <verb>`
command, since whatever lay past the cut would be confirmed unseen.
`config.apply` is shown as its plan's change list, unchanged lines left out.
Other L2 arguments are shown with the fields that say who or what changes first
(email, who, role, type, target, kind, provider, issuer, domains, base URL and
the like), then the rest by name, secrets as `(hidden)`. An action's rationale
comes last, labelled `Crew rationale (unverified)`, and is left out whole when
it does not fit. A tool is reached only by its underscored name
(`action_approve`); a dotted name such as `action.approve` is refused with
`unknown_tool`, so no second spelling of an L2 tool skips the confirmation.

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

New installs default to dry run: actions are proposed and recorded, never
executed. `SHOC_DRY_RUN` set to `1` or `0` wins over the policy's `dry_run` in
both directions; unset, the policy decides. A page is sent for real either way
([`response.md`](response.md#autonomy-in-three-levels)).

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

## Outbound fetches

A URL a caller hands in or a person configures (an `intel.add` or
`intel.digest` URL, a list or RSS source, an item on the report queue) is
fetched by one function (`shoc/detect/report.py`, `get`). Each hop must resolve
only to public addresses, and the connection goes to the address that was
checked, with the name kept for `Host` and TLS, so neither a redirect nor a
second DNS answer reaches an internal address. A fetch follows at most 3
redirects, each checked, reads at most 8 MiB and gives up after 60 seconds in
all, connect and headers included. That pinned path ignores the environment, so
`SSL_CERT_FILE` and `SSL_CERT_DIR` do not apply to it.

Behind `HTTPS_PROXY` or `ALL_PROXY`, each hop is still checked with local DNS
but sent by name, because an HTTPS tunnel checks the certificate against the
host it is given. The proxy resolves the name again, so DNS rebinding between
the two lookups is not caught there, and a network with a proxy and no local DNS
cannot fetch reports.

A keyless research source may follow a redirect only to a public address, and
connects to the address it vetted on every hop, redirects included, with the
name kept for `Host` and TLS, as report fetches do. Through `HTTPS_PROXY` or
`ALL_PROXY` it goes by name, as above. `.localhost` and `.svc` names count as
internal for research and report fetches. A source that carries a key follows
no redirect, so the key never reaches another host; OTX and MISP feeds report a
redirect as a feed error. The OpenID Connect issuer, token endpoint and JWKS
URI must resolve to public addresses, a name that resolves to a private one is
refused, and each call connects to the address it checked.

## Audit

Every audited capability call, and every change of an action's state, appends a
row to `shoc.audit_log` under the principal that made it. A worker records
`action.started` before it calls the provider, so a crash mid-call still leaves
a row, and `ops.alerts` raises `action.stuck` for an action left running over an
hour. Each row carries an HMAC of the previous row's hash and its own fields,
keyed from `SHOC_MASTER_KEY`, and triggers refuse UPDATE, DELETE and TRUNCATE.

`shoc migrate` records a fingerprint of the key in `shoc.audit_key`. `serve`
and the worker refuse to start when their key does not match it, and any other
process whose key is empty or different refuses to write or verify the log, so
a shell or an MCP client started with the wrong environment fails instead of
adding a row that would never verify.

What is audited:

- Every call to an audited capability, the ones that fail included. A failed
  call's row keeps a shoc error's message, or only the class name of any other
  exception, whose message may hold data. An L2 or security-tagged capability
  commits its change and its audit row in one transaction or not at all, except
  `action.undo` and anything scoped `actions:run` or `playbooks:run`, because
  what a vendor did cannot be rolled back.
- A refused call by a caller that authenticated, once a minute per principal and
  capability; later refusals within that minute leave no row. Failed sign-ins
  other than a lock are the one refusal not audited (above).
- Reads of `events.query`, `search`, `timeline.build`, `case.get`, `finding.get`
  and `memory.search` by an external agent or a service token. A person's
  `events.query` is audited only with `include_raw` or a limit over 100. The
  crew's reads and a person's console views are not audited per call: the
  crew's are in the case's openspace, and a row per click would bury the rest.

Each row carries `subject` (migration 058): a masked summary of the
identifiers in the input (an email, a role, a case id, an endpoint's host), up
to 10 citations, and for a sign-in its method and client address. Secrets show
as `(hidden)` and free text is never stored, since a row is never deleted.
`subject` joins the HMAC only when present, so older rows still verify.

`shoc health audit` walks the chain and counts every row that does not
match. A walk that finds it whole keeps its last row in
`shoc.audit_checkpoints` (migration 063), and the next one starts there; the
worker walks the whole chain once a day, so a rewrite of rows an earlier walk
passed is still found. The worker runs the check every hour from `ops.check`;
a break it has not seen before pages the operator through the Manager (`audit_broken`) and publishes
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
re-running `source configure`, or by changing its `SHOC_SECRET_*` variable and
running `shoc apply` (a new credential keeps the source's push key), and the
key itself with `shoc rotate-key`, which
seals every value again under the new key in the same transaction that moves
the audit chain.

A blank secret field on reconfiguration keeps the stored secret only while
every URL setting (`org_url`, `base_url`, `indexer_url`, `console_url`, `url`
and the rest) keeps its scheme, host and port, and `cloud` and
`storage_account` keep their value (`credentials.same_host`). A new host needs
the credential again. This holds for sources, action credentials, intel feeds
and lookup sources, as `sso.configure` already does for SSO.

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

## Data and privacy

The company that runs shoc is the controller of everything shoc collects. The
shoc project receives nothing from a deployment, so it has no sub-processors of
its own. Every third party in this section is one the deployer turns on, and the
contract with it is the deployer's.

### What shoc holds

Security logs name people. Depending on the sources connected, events carry
email addresses, user names, account and device ids, group and role names,
source and destination addresses, user agents and host names, and what the
product logged about the act itself: mail subjects and recipients, file names
and paths, URLs, command lines, API calls and their parameters. Each event keeps
its original record in `raw` beside its OCSF columns.

Postgres also holds the people who use shoc (email, role, a scrypt password
hash, a sealed authenticator seed), the audit log with each sign-in's client
address, cases, findings, the crew's messages, and the memory facts people and
the crew wrote about the company.

| Data | Where | Kept |
| --- | --- | --- |
| Events | Postgres, or the warehouse `SHOC_BACKEND` names | `SHOC_RETENTION_DAYS` (90 by default). Postgres drops whole monthly partitions, so it keeps an event at least that long and up to about 31 days more. A warehouse deletes by exact time; its own history (Delta time travel, Snowflake Fail-safe) follows the warehouse's settings |
| Stream events | Postgres | The same window, and until every enabled webhook has sent them |
| Hunt observations, the entity graph, indicator lookups | Postgres | The same window |
| Pushed records waiting to load | Postgres | Until they load, or the same window |
| Memory facts | Postgres | Each until its expiry; a fact with none stays |
| Exposures (each account, key, address and resource the Surveyor saw act) | Postgres | Until a survey no longer sees it; an account or user stays, marked stale after 60 days |
| The queue of threat reports to read | Postgres | 30 days from when each was queued; one still unread after 7 is dropped |
| Jobs | Postgres | 7 days once done, 30 once failed. A job that guards a one-time effect stays |
| Cases, findings, openspace messages, notices, the audit log | Postgres | Never expired. They are the incident record, and the audit log refuses deletes |
| Threat reports read, with the crew's reading; posture snapshots | Postgres | Never expired |
| Accounts | Postgres | Never deleted. Disabling one erases its password hash and authenticator seed |

No capability finds, exports or erases one person's data. Events leave with the
retention window; cases, findings and the audit log stay. `events.retain`
refuses fewer days than the configured retention (the value `config.apply` set,
else `SHOC_RETENTION_DAYS`), so lowering retention is a `config.apply` change a
person confirms, never one call an assistant can be steered into.

### What reaches the model

With `SHOC_LLM_PROVIDER=none`, the default, no model is called and none of this
leaves. Once a provider is set, each crew turn on a case sends it:

- the case: its id, entity, severity, ATT&CK techniques, and the rule, title,
  severity, event count and times of its 25 worst findings;
- the events those findings cite, up to 40, each with its OCSF columns and up
  to 60 fields of its original record, 200 characters each;
- the memory facts about the entity, the entities one hop away in the graph,
  and the Surveyor's posture for up to five of the case's entities;
- the indicators the evidence contains, what the feeds and earlier lookups say
  about them, and threat reports already read that describe the same technique
  or malware;
- the earlier discussion on the case (its last 25 messages, 500 characters
  each) and what brought the crew back to it;
- what people wrote into the case: its last 10 messages from a person, 1,000
  characters each, with who wrote each one;
- CTI's answer, when the evidence holds something worth researching;
- the answer to every lookup the role makes during the turn, up to 8,000
  characters each. An `events.query` with `include_raw` returns whole records.

Outside a case, the model also gets a person's question to `ask` with what the
Manager looks up to answer it; a threat report's title and summary, then its
text, with the company's profile (the products it connects, how many identities
its logs name, its clouds) when CTI reads one; up to five recent records of a
source whose format changed, when the Integrator repairs its mapping; and a
report's body, when the Manager writes its reading of one. It also gets:

- every day, with no case open, the rows each hunt pack returned, which are
  log records, with the pack's prose, for the Hunter to settle;
- what the Hunter and the Detection Engineer read in their backlog turns,
  whose tools include `events.query`;
- new findings with the open cases, when the Sentinel places them in a case;
- a proposed action with the case's cited events, the memory facts, the
  entities around it in the graph and the lookups made on it, when the IR
  Commander reviews the action;
- the day's posture survey and the one before it, when the Surveyor reads it;
- the sources that are down, their errors and the open alerts, when the
  Manager judges a source outage.

Log content goes into a prompt quoted as data (see [Untrusted
content](#untrusted-content)). No field is redacted, masked or pseudonymised:
the crew matches an account across sources, looks it up and cites the values it
read, and a token in place of an email would break each of those.

To keep all of it inside the deployment, set `SHOC_LLM_PROVIDER=openai` and
point `SHOC_LLM_BASE_URL` at a model you host, such as vLLM or Ollama (see
[Models](agents.md#models)). `llm.configure` can move the endpoint only to a host
in `SHOC_LLM_BASE_URL_ALLOWLIST`.

The provider's region, its retention of prompts and its data processing terms
are set on your account with it, not in shoc. With
`SHOC_LLM_PROVIDER=openai-responses` pointed at `api.openai.com`, shoc sends
`store: false`, so OpenAI keeps no response for later retrieval; its
abuse-monitoring retention still applies. A gateway gets no such field, and what
it keeps follows its own terms.

### Who else receives what

| Destination | Receives | Turned on by |
| --- | --- | --- |
| The model provider | What the section above lists | `SHOC_LLM_PROVIDER`, or `llm.configure` |
| Lookups without an account: RDAP (the registry IANA names, else rdap.org), FIRST EPSS, NVD | The host of a domain, URL or email, a public address, a CVE id | Always on. `SHOC_INTEL_FEEDS=off` does not stop them |
| Your DNS resolver | A domain a lookup resolves, a public address it reverse-resolves | Always on, like the row above |
| Lookups with an account: abuse.ch, ipapi.is, AbuseIPDB, GreyNoise, Shodan, Netlas, VirusTotal, urlscan.io | The indicator: a public address, a domain, a hash, or a URL cut to scheme, host and path | A key set with `shoc intel configure --lookup` |
| Slack | Case cards (title, severity, verdict, entity, summary, five finding titles, actions waiting with their rationale, three event ids), the Manager's messages and reports, answers to `/shoc` | `slack.configure` |
| PagerDuty, in the US or EU region the credential names | A page's text (severity, the conditions behind it, case ids), its severity and the notice ids | A `notify` credential |
| Your mail server | Sign-in links and lock notices to the person concerned; a page the pager did not take, to every enabled admin and operator who has signed in | `SHOC_SMTP_URL` |
| Webhook subscribers | The stream events of the types subscribed to (case, finding, action and health changes), and the audit chain head, signed | `stream.subscribe` |
| Your identity provider | The person's email as a sign-in hint, and the code exchange | `sso.configure` |
| A warehouse | Every event, whole | `SHOC_BACKEND` |
| An outside monitor | A bare GET after each hourly check | `SHOC_HEARTBEAT_URL` |
| The products you connect | Connectors only read from them. An action sends the target of its step (an account, a key, a host) | `source.configure`, `credential.configure` |

A lookup never sends a private, loopback or internal value, a value the company
owns, or one a source shared under a restricted TLP marking; those are answered
from local lists and the company's own data. The indicator feeds and the lists
lookups read from are downloads: they receive a request and no company data.

A webhook URL must be `https`, except for an address that is not on the
internet (loopback, private, link-local, or carrier-grade NAT such as a
tailnet), a name with no dot, or a name under `.local`, `.internal`, `.lan`,
`.corp`, `.home.arpa`, `.intranet`, `.localhost` or `.svc`.

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
- By default shoc pulls two public abuse.ch feeds every six hours and the
  lists lookups answer from once a day (the quick start names the hosts).
  `SHOC_INTEL_FEEDS=off` stops the two feeds and the startup list download. It
  does not make shoc silent: lookups still reach RDAP, FIRST EPSS, NVD and your
  DNS resolver, and load the lists on first use (see [Who else receives
  what](#who-else-receives-what)). A feed you configure yourself (OTX, MISP, a
  list) also loads the MISP warninglists from their source, which is one more
  host.
- Choose the model provider as you would any processor that reads your logs,
  and add it and every destination you turn on to your record of processing
  ([Data and privacy](#data-and-privacy)).

Report vulnerabilities as described in [`SECURITY.md`](https://github.com/pwnera/shoc/blob/main/SECURITY.md).
