---
rfc: 0028
title: People sign in with their email, a password and an authenticator, or their company's SSO
status: accepted
authors: ["@Rettila"]
created: 2026-10-05
requirements: ["SEC-3", "API-1", "SEC-1"]
supersedes: null
---

# RFC 0028: People sign in with their email, a password and an authenticator, or their company's SSO

## Summary

A person opens the console, types their email and continues. If the email's
domain belongs to the company's identity provider, the browser goes there
(OpenID Connect) and comes back signed in. Otherwise the person types a password
and a six-digit code from an authenticator app. Accounts come from an admin's
invitation, or, for SSO, from signing in with an allowed domain, which joins as
`reader`. A signed-in browser holds an HttpOnly cookie carrying a short-lived
token of the kind `token.create` issues, kept as a hash in `shoc.api_tokens`.
Bearer tokens stay for machines, MCP clients, the CLI and break-glass, and a
person's token can still open the console.

This amends RFC 0019, which rejected OIDC as "a second service to run": shoc is
a client of the provider the company already runs, so nothing new is deployed.
It amends D16 (the console gains a sign-in, which the kernel serves to any
browser client), D63 and D66 (the first account also ends single-user mode),
and moves SSO from the SaaS column of the open-core table to the open-source
one.

## Motivation

The console asked for a bearer token and kept it in `localStorage`:

- Nothing tied a token to the company's directory. When someone leaves, their
  Google or Microsoft account is disabled and their shoc token keeps working
  until someone remembers it. The operator is usually absent (RFC 0015), so
  that someone rarely comes.
- A token is one factor. A security product reached with a pasted string fails
  the first customer security review.
- `localStorage` is readable by any script on the page, and the console renders
  log content an attacker wrote.
- Teams share tokens, so the audit log names a token rather than a person.
- A hosted shoc reached from Claude.ai or ChatGPT needs per-person sign-in.
  Their remote MCP connectors expect OAuth, and this RFC builds the half of it
  that knows who the person is.

## Guide-level explanation

Set `SHOC_PUBLIC_URL` to the console's address, then invite the first admin
from the host:

```bash
shoc user invite you@example.com --role admin
```

The answer carries a link, once, or says it was emailed when `SHOC_SMTP_URL` is
set and the mail went out. The link opens `/welcome#…` in the console, which
shows a QR code for an authenticator app and asks for a password and the first
code. The account is then live and the browser signed in.

Everyone else is invited from the console's API screen, or from an assistant
(`user.invite` is L2, so the person confirms it). To let the whole company in
through its provider, register `<SHOC_PUBLIC_URL>/auth/sso/callback` as the
redirect URI there, then:

```bash
shoc sso configure --issuer https://accounts.google.com \
  --client-id 123.apps.googleusercontent.com --client-secret … --domains example.com
```

Anyone at `example.com` who signs in there joins as `reader`, and an admin
raises their role with `shoc user update --email bob@example.com --role operator`.
People invited in an SSO domain sign in through the provider, with the role they
were invited with.

Signing in:

1. The person types their email and continues.
2. An SSO domain sends the browser to the provider and back to the page it
   started on.
3. Any other email asks for a password, then a six-digit code, and sends both
   together.

A forgotten password: "Forgot password" emails a link when mail is configured.
That link sets a new password and asks for a code from the authenticator the
person already has, so a stolen mailbox alone does not open the account. A lost
phone: an admin runs `user.reset`, whose link replaces both the password and
the authenticator.

## Reference-level explanation

### Settings

| Variable | Meaning |
| --- | --- |
| `SHOC_PUBLIC_URL` | The console's origin as people reach it, e.g. `https://shoc.example.com`. Required for any sign-in: it builds emailed links and the SSO redirect URI, it is the only `Origin` a sign-in or cookie request is accepted from, and its scheme decides whether cookies are `Secure`. |
| `SHOC_SMTP_URL` | `smtps://user:pass@host:465` (TLS) or `smtp://user:pass@host:587` (STARTTLS, required). Optional. Certificates are verified. |
| `SHOC_MAIL_FROM` | The `From` address. Defaults to the SMTP user when that is an address. |
| `SHOC_TRUSTED_PROXIES` | Comma-separated networks whose `X-Forwarded-For` is believed when sign-in attempts are counted per client address. Defaults to loopback and `172.16.0.0/12`, where Docker puts its networks. |

### Tenant

A request that is not signed in yet acts on the tenant its `X-Shoc-Tenant`
header names, else `SHOC_TENANT`, as Slack's callbacks do. Emails are unique
within a tenant and an SSO domain belongs to one provider within it. Once a
browser is signed in, its cookie names the tenant, and a different
`X-Shoc-Tenant` is refused (D63).

### Tables (migration 039)

- `shoc.users`: `tenant_id`, `user_id` (`usr_…`), `email` (lower case, unique
  per tenant), `role` (one of the four), `password_hash`, `secret` (the
  authenticator's seed, sealed with the row as associated data), `totp_step`
  (the last step accepted), `sso_issuer` and `sso_subject` (unique per tenant
  together), `code_failures`, `locked_until`, `created_by`, `created_at`,
  `last_login_at`, `disabled_at`, `disabled_by`. Added to the tables
  `shoc rotate-key` re-seals.
- `shoc.user_links`: invitation and reset links. `link_id`, the link's SHA-256,
  `user_id`, `enrol` (whether accepting it replaces the authenticator),
  `wrong_codes`, `created_by`, `created_at`, `expires_at`, `used_at`.
- `shoc.sso_providers`: `tenant_id`, `provider` (`oidc`), `issuer`,
  `client_id`, `domains`, the endpoints read from discovery, `secret` (the
  client secret, sealed). Re-sealed by `shoc rotate-key`.
- `shoc.api_tokens` gains `user_id`. A signed-in browser is a row with that
  `user_id`, no role of its own, `who` set to the email and a 12-hour expiry.

Accounts, links and sessions are not deleted: links end by `used_at` or expiry,
sessions by `revoked_at` or expiry, people by `disabled_at`. `sso.configure`
with `clear` deletes the provider's row. `shoc grant-readonly` revokes the
read-only agent role's access to these four tables.

### Secrets and hashes

- Passwords: `hashlib.scrypt` (n=2^15, r=8, p=1, 16-byte salt, `maxmem` 64 MiB),
  stored as `scrypt$32768$8$1$<salt>$<hash>`, on two worker threads of their own
  so a burst of sign-ins cannot starve the API. At least 12 characters, at most
  256, and not the email. An unknown email is hashed against a fixed salt, so it
  takes as long as a known one.
- Authenticator: 20 random bytes, RFC 6238 with SHA-1, six digits, 30-second
  steps, one step either side. A step is accepted only if it is above
  `totp_step`, set in the same `UPDATE … WHERE totp_step < step`, so a code works
  once even under concurrent requests.
- The seed offered by an enrolling link is not stored: it is
  `HMAC-SHA256(sha256("shoc authenticator\0" + master key), link)[:20]`,
  recomputed when the link is opened and when it is accepted.
- Sessions and links are 32 random bytes, kept as SHA-256, like tokens.
- The SSO round trip's state (state, nonce, PKCE verifier, tenant, issuer,
  client id, page to return to, expiry) travels in a cookie sealed with
  `shoc.db.secrets.seal`, so it can be neither read nor forged. Each
  `shoc serve` process accepts a state once.

### Routes

Signing in cannot be a capability: it sets cookies, follows redirects and runs
before there is a caller. These routes do that and nothing else; managing people
is done by the capabilities below. They are not part of the frozen contract
(`contract/v1.json`); the console and other browser clients use them. Answers
are JSON with `Cache-Control: no-store`; errors use `{"error": {code, message}}`.

Every `POST` here must carry `Content-Type: application/json` and an `Origin`
equal to `SHOC_PUBLIC_URL`'s, or it is refused with 403 `cross_site`. Without
`SHOC_PUBLIC_URL` they answer 503 `sign_in_not_configured`.

| Route | Does |
| --- | --- |
| `POST /auth/start {email, return_to}` | `{"method": "password"}`, or for an SSO domain `{"method": "sso", "url": <provider's authorize URL>}` and the sealed state cookie: `__Host-shoc_sso` with path `/` when `SHOC_PUBLIC_URL` is `https`, else `shoc_sso` with path `/auth/sso`; HttpOnly, `SameSite=Lax`, 10 minutes. The URL carries `state`, `nonce`, PKCE (S256) and `login_hint`. `return_to` is a path on this origin (`/…`, never `//`). Never says whether an account exists. |
| `GET /auth/sso/callback` | Opens the state cookie, checks `state`, which works once, and RFC 9207 `iss` when sent, exchanges the code with the verifier and the client secret, checks the ID token (below), finds the person, sets the session cookie and redirects to `return_to`. A failure redirects to `/?signin=<code>`. |
| `POST /auth/login {email, password, code}` | Checks all three and sets the session cookie. A throttled attempt is 429 `slow_down`; any other failure is 401 `bad_credentials`, the same for an unknown email, a wrong password, a wrong code, a locked or disabled account, and a password account in an SSO domain. |
| `POST /auth/token {token}` | A person's token (one with a role) becomes the session cookie itself, for up to 12 hours, or until the token ends if sooner. Machine tokens get 401 `bad_credentials`. |
| `POST /auth/link {link}` | `{email, enrol, otpauth}`: the email, and for an enrolling link the new authenticator's `otpauth://` URI. 410 `link_expired` for an unknown, used or expired link. |
| `POST /auth/link/accept {link, password, code}` | Sets the password, and for an enrolling link the authenticator, after checking the code. Ends the link, the person's other links and sessions, and signs this browser in. A wrong code is 401 `bad_code`; five end the link. |
| `POST /auth/forgot {email}` | With mail configured, emails a link that keeps the authenticator to an active password account, at most one per 5 minutes, sent from a background thread so the answer takes the same time either way. Always `{"sent": true}`; `{"sent": false}` when mail is not configured. |
| `POST /auth/logout` | Revokes the session and clears the cookie. A token used through `/auth/token` stays live; `token.revoke` ends it. |

`/auth/` joins `/v1/` in the console's proxy.

### The session cookie

`__Host-shoc_session` when `SHOC_PUBLIC_URL` is `https` (`Secure`), else
`shoc_session`; HttpOnly, `SameSite=Strict`, path `/`, 12 hours. A request with
more than one session cookie is refused.

`authenticate` reads a bearer token first, as today, then the cookie. Either is
looked up in `api_tokens`; a session row takes its role from its account, so a
role change applies on the next request, and a disabled account signs out. The
caller is a human with the account's role and the email as its id, so the audit
log names the person. A cookie request that is a `POST` passes the same
content-type and `Origin` check as the sign-in routes. A cookie that names no
live session is 401 `signed_out`. The event stream re-checks its caller every 30
seconds and ends when the session does.

### Wrong passwords and codes

- A wrong password is throttled per account and client address (10 in 15
  minutes) and never locks the account, so nobody can lock out the admin by
  knowing their email. Past that, attempts answer 429 `slow_down`.
- Every `POST` to `/auth/*` and every SSO callback counts against a cap of 100
  per client address in 15 minutes, also answered with 429 `slow_down`.
- The client address is the socket's, unless the socket is in
  `SHOC_TRUSTED_PROXIES`. Then it is the first `X-Forwarded-For` entry, read
  from the right, outside those networks. A TLS terminator in front of the
  console must append `X-Forwarded-For`, or everyone behind it shares one
  address.
- A wrong code, which needs the right password first, counts against the
  account. Five lock it for 15 minutes, then 30, 60 and so on up to a day, and
  email the person when mail is configured. Only a completed sign-in resets the
  count. Wrong codes on a link that keeps the authenticator count too.
- A lock writes one `auth.locked` row to the audit log. Other failures are not
  audited, so a guesser cannot fill the chain. Sign-ins (`auth.signin`) and
  accepted links (`auth.link_accepted`) are audited under the person.
- A password account in an SSO domain cannot sign in with its password: the
  provider is how the company takes access away.
- Every account with a password has an authenticator; there is no sign-in with
  a password alone.

### SSO

- `sso.configure` fetches the issuer's discovery document and stores its
  endpoints. The issuer and every endpoint must be `https` on a public address,
  the document must name the issuer exactly, and Microsoft's shared `common`,
  `organizations` and `consumers` issuers are refused. It also refuses while no
  admin exists, since the first person through SSO joins as `reader`.
- The ID token must be signed with RS256, PS256 or ES256 by a key from the
  provider's JWKS (`jwt.PyJWKClient`, cached an hour), name the issuer exactly,
  hold the client id in `aud` (and in `azp` when present), be current within 60
  seconds, and carry the nonce.
- Its `email` must be in a configured domain and vouched for by the provider:
  `email_verified` true, plus `hd` in the domains for Google; for Microsoft, the
  token's `tid` must be the issuer's tenant and a guest (`idp` present) is
  refused, since a member's address is set by the company's administrators. No
  `email` claim, no sign-in.
- The person is found by issuer and subject. On a first sign-in they are found
  by email and linked; otherwise they join as `reader`. After that the subject
  decides, not the email.
- When `sso.configure` moves to another issuer, a person linked to the old one
  is found by email on their next sign-in and linked to the new one, which has
  vouched for the email as on a first sign-in. The same issuer with a new
  subject for a linked email is refused.
- Sessions from SSO last 12 hours, like the others; signing in again is one
  redirect.

### Capabilities

| Capability | Scope | Autonomy |
| --- | --- | --- |
| `user.invite {email, role}` | `users:write` | L2, human-only, audited. `role` defaults to `reader`. In an SSO domain it creates the account with no link. Otherwise it needs `SHOC_PUBLIC_URL`, and creates the account and an enrolling link valid 7 days, emailed when mail is configured and returned once when it is not or the mail cannot be sent. |
| `user.reset {email}` | `users:write` | L2. An enrolling link valid 1 day, delivered like an invitation, that replaces the password and the authenticator. Needs `SHOC_PUBLIC_URL`. Refused in an SSO domain. |
| `user.update {email, role, disabled}` | `users:write` | L2. Empty fields are left as they are. Disabling ends the person's sessions, links and the role tokens issued to their email. Refuses to leave no active admin. |
| `user.list {disabled}` | `users:read` | L0, human-only. |
| `user.me` | `meta:read` | L0. The caller's id, kind, role, tenant and, for an account, its email. |
| `sso.show` | `sso:read` | L0, human-only. |
| `sso.configure {issuer, client_id, client_secret, domains, clear}` | `sso:write` | L2, human-only, audited. |

A new link ends the person's earlier ones. Only `admin` holds `users:write` and
`sso:write`, as with `tokens:write`, so no other role can give itself a wider
one. Every role reads `users:read` and `sso:read` through `*:read`; neither
returns a hash or a secret. `user.invite` and `user.reset` join the capabilities
that return a secret once.

### Single-user mode

It ends with the first token or the first account, invited or not, and stays
ended. `shoc serve` binds off loopback once either exists.

### Console

The console keeps no credential in storage, and "Log out" clears the tab's
session storage, so the next person on the tab does not inherit the crew chat.
It asks `user.me` whether the browser is signed in. When it is not, `/` shows
the front page and any other address the login page, which signing in replaces
with the console at that address (`/login` with `/`). The login page asks for
the email, then the password, then the code, or goes to the provider; "Use a
token" is the last way in. Calls and the event stream rely on the cookie, which
the browser sends to its own origin. A 401 `signed_out` raises a "Signed out"
banner whose "Log in" opens the login page at the same address. The API screen gains a People tab: invite, change role,
reset, disable, and the SSO settings. `/welcome` takes invitation and reset
links before anything else loads, and clears the link from the address bar.

## Drawbacks

- shoc now owns password storage, throttling and a second factor, code that must
  be right and that a token never needed.
- Two optional outbound connections: the mail server and the identity provider.
- `SHOC_PUBLIC_URL` becomes required for anyone who signs in through a browser.
- On plain `http`, a cookie is sent to every port of the host, so another
  service on the same address could read it. The console should be served over
  `https` (`tailscale serve` will do), which also gives the cookie its
  `__Host-` prefix.
- A team that turns on SSO for a domain moves password accounts in that domain
  to the provider, admins included. The way back when the provider is down is a
  token.

## Alternatives

- **Keep tokens for people.** The motivation above.
- **A sessions table of its own.** A session is 32 random bytes kept as a hash
  with an expiry and a revocation, which is an `api_tokens` row; a second table
  would be a second lookup path.
- **Passkeys (WebAuthn).** Phishing-resistant, but verifying an attestation
  needs CBOR and a library outside the budget, recovery is a project of its own,
  and access still does not follow the company's directory. A later RFC can add
  them as a second factor.
- **A one-time code by email instead of a password.** Nobody can sign in until
  mail works, and a mailbox becomes the only factor.
- **Trust a reverse proxy's identity header** (Cloudflare Access, Tailscale,
  oauth2-proxy). No code, but one proxy misconfiguration lets anyone in, and it
  is a second service. Possible later as an opt-in.
- **Optional two-factor.** Most people would not turn it on, and the console
  approves L2 actions.
- **Password and code in two requests.** A right password would answer
  differently from a wrong one, which tells a credential-stuffing run which
  passwords work.

## Dependency and scope impact

- New dependencies: none. `hashlib.scrypt`, `hmac`, `secrets`, `smtplib`, `ssl`
  and `email` from the standard library; `pyjwt` and `httpx` for OIDC. The
  console adds `uqr` (MIT, no dependencies) to draw the QR code.
- New required services: none. The mail server and the identity provider are
  optional and already the customer's.
- Public contract: seven capabilities, the `users` and `sso` scope areas,
  migration 039 and four settings. The `/auth/*` routes are documented in
  `docs/security-model.md` and are not frozen.

## Security considerations

- The cookie is never readable by script and the console keeps no secret in
  storage, so a script injected through log content cannot take the session
  away with it.
- A cross-site form, a `text/plain` post or a request from another port of the
  same host is refused by the `Origin` and content-type check, which `SameSite`
  does not cover across ports.
- Emailed links are built from `SHOC_PUBLIC_URL` only, never from the request,
  and go only to the stored address. Links travel in the URL fragment, which is
  not sent to servers or in `Referer`.
- A stolen mailbox can set a new password but not pass the code. An admin's
  reset link replaces both, so admins should confirm the request with the
  person another way first. Without mail, or when the mail cannot be sent,
  `user.invite` and `user.reset` return the link to the caller rather than lose
  it, which over MCP puts it in the assistant's context;
  configure mail where assistants manage people.
- The provider's say-so on an email is required before it links or admits
  anyone: a personal Google account on a company address has no `hd`, and a
  Microsoft guest's address is set by its home company.
- Joining through SSO gives `reader`, which reads every event and finding
  (`*:read`). Domains should be the company's own.
- The read-only agent role cannot read the new tables or `api_tokens`.

## Unresolved questions

- OAuth for remote MCP clients (Claude.ai, ChatGPT), built on this sign-in.
- Passkeys as a second factor.
- Whether an admin can require that a domain's people use SSO only.

## Adoption and migration

Migration 039 adds the tables and the column. Existing tokens keep working
everywhere; a browser that held one in `localStorage` signs in again, with the
same token or an account. The console's proxy adds `/auth/`, and deployments
set `SHOC_PUBLIC_URL`.
