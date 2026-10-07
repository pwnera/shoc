---
rfc: 0027
title: An identity action answers an EDR, Gateway or GitHub case for the login its user is linked to
status: accepted
authors: ["@Rettila"]
created: 2026-10-04
requirements: ["RSP-4", "RSP-2", "AGT-4", "ING-1"]
supersedes: null
---

# RFC 0027: An identity action answers an EDR, Gateway or GitHub case for the login its user is linked to

## Summary

`idp.revoke_sessions` and `idp.suspend_user` may answer a case from `edr`,
`cloudflare` or `github` when `identity.resolve` links the case's user to exactly
one identity-provider login. The action then acts on that login, never on the
name the case holds, and credential routing (RFC 0025) picks the IdP tenant from
the login's own events. If nothing links the user, or two logins could be it,
the action is blocked with the reason. This settles RFC 0013's unresolved
question 5 for these three platforms.

## Motivation

`out_of_scope` in `shoc/actions/base.py` refuses an action whose `platforms` do
not include a product of the case's rules. Read on 2026-10-04, that refused
`idp.revoke_sessions` on:

- `contain_infostealer` (`edr`): a program read the browser's cookie store, and
  the cookies are replayed from elsewhere within the hour. Isolating the laptop
  does not end those sessions.
- `contain_phishing_site_visit` and `hunt:cloudflare_access_first_login_country`
  in `contain_account_takeover` (`cloudflare`): the person typed a password
  into a proxy, or an Access login came from a new country.
- `github_oauth_app_authorized` in `revoke_third_party_app_access` (`github`):
  the member who granted the app signs in to GitHub through the IdP.

The steps were in the playbooks, marked optional, and never ran.
`tests/unit/test_rules_content.py` listed two of these rules in `CANNOT_ACT`.

Lifting the platform check alone would be wrong. An EDR alert names the local
account (`jdoe`, `ACME\jdoe`), which is not an IdP login. Sent to Okta it fails.
If the org happens to have an Okta user `jdoe`, it signs out the wrong person.

## Guide-level explanation

On an infostealer case for `jdoe` on `laptop-21.example.org`, the revoke step
renders `user: jdoe`. shoc asks who `jdoe` is:

```text
identity.resolve user:jdoe
→ user:jdoe signs in as jane.doe@example.com (signed in from LAPTOP-21).
```

The proposal goes out for `jane.doe@example.com`, with the link and its events in
the reason:

```text
Sign jane.doe@example.com out of every session … in idp:entra
reason: jdoe signs in as jane.doe@example.com (signed in from LAPTOP-21: evt-…, evt-…). …
```

If two people have signed in to the IdP from that laptop, or nothing ties `jdoe`
to a login, the action is blocked ("nothing links jdoe to an identity-provider
login"), the optional step is skipped, and the page still goes out.

The IR Commander sees `idp.revoke_sessions` in its catalogue on these cases,
with the target described as "user, for the IdP login identity.resolve links it
to". It may name either the case's user or that login. Any other login is
refused.

## Reference-level explanation

**Which actions.** An action declares `linked_from`, the platforms whose cases
it may answer through a link. `idp.revoke_sessions` and `idp.suspend_user` name
`edr`, `cloudflare` and `github`. `follows_link(action, platforms)` in
`shoc/actions/base.py` is true when the two intersect. `out_of_scope` is
unchanged.

**What links a name to a login** (`surveyor.logins`). Three links, read from the
event store over the last 30 days, strongest first. The first that yields any
login decides:

1. *Another platform's event names the login.* A mapping may declare `login:`
   as an `unmapped.<path>` or `raw.<path>`. GitHub's is
   `unmapped.external_identity_nameid`, the SAML identity that an organisation
   with single sign-on records on each audit event.
2. *Same name.* The IdP's events name the case's user as an actor. A Gateway or
   Access user is already the email the IdP knows.
3. *Same device.* The IdP's events show a login signing in from a host the name
   acted on. Okta's `device.name` and Entra's `deviceDetail.displayName` give the
   host. Hosts compare on their first DNS label (`LAPTOP-21` and
   `laptop-21.example.org` match). A name seen on more than 20 hosts, a shared
   local account like `admin`, gets no device link.

A candidate counts only when the IdP's events (`okta`, `entra`, `m365`, `azure`)
name it as an actor. One login is a link. Two or more from the same link are
none, and the answer lists them. `identity.resolve` returns the result as
`logins`, each with `via` and `event_uids`, and a single login clears
`unbridged`.

**Proposing** (`actions.propose`). When the case's platforms do not cover the
action and `follows_link` holds, shoc computes the link for each `user:` entity
of the case (up to ten). The proposed target must be one of those users or the
login one of them is linked to. If it is, the target parameter becomes the
login before routing and before the policy is asked, so `make_uid`, the plan,
the audit row and the vendor call all carry the login. The reason starts with
the link and its event IDs. Otherwise the action is `blocked` with the link's
reason. A blocked action cannot be approved, so the local name never reaches
`execute`.

**Routing.** `credentials.where_seen` reads the case's findings on the action's
platforms. A linked case has none, so it now falls back to the target's own
events on those platforms (`credentials.signed_in`). Each event gives the
platform (from `metadata_product`) and its `cloud_account_uid`, and `choose`
runs as in RFC 0025. A login seen in Okta and Entra is acted on in both. The
same fallback runs when an action proposed before any credential existed is
routed at execution.

**Content.** `Playbook.cannot_act_on` counts a step whose action names the
product in `linked_from`. `cloudflare_gateway_phishing_resolved` and
`github_oauth_app_authorized` leave `CANNOT_ACT`. The playbook text says the
step acts on the linked login.

Principles touched: 5 (bounded autonomy: the action stays L1 or L2 under the
same policy, and its target is a name the IdP's own events show), 6 (evidence
or nothing: the link cites its events or the action does not run).

## Drawbacks

- Every proposal on a linked case runs about five event queries per case user,
  each bounded by tenant, a 30-day window and a row limit.
- A laptop that a second person signed in from once in 30 days, say an IT
  technician, leaves it without a link. The page goes out, and a person revokes
  by hand.
- The device link depends on the IdP recording a device name: Okta only for
  devices enrolled in Okta Verify, Entra only for joined or registered devices.
- The `login:` key covers GitHub only. CrowdStrike and SentinelOne alerts that
  carry a UPN could declare theirs once a fixture confirms the field.

## Alternatives

- **Let the crew map the name.** `contain_infostealer` already asks "which IdP
  login belongs to the local account". A model's answer is shaped by log
  content, and the target of a sign-out should not be. The crew sees the same
  link through `identity.resolve`, and the runner does not take its word.
- **Read the link from the world graph.** `graph_edges` only joins names that
  share an event, never two user names, and it is rebuilt on the Surveyor's
  schedule. An infostealer case cannot wait for the next rebuild.
- **Add every IdP platform to the action's `platforms`.** The local name would
  reach the IdP unresolved.
- **A table of links a person maintains.** It goes stale the week someone
  joins. A person can still write a fact to memory, and the crew reads it, but
  it does not move an action's target.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: `identity.resolve` gains `logins`. Actions gain
  `linked_from`. Mappings gain an optional `login`. The Commander's catalogue
  lists `idp.*` on `edr`, `cloudflare` and `github` cases. No migration.

## Security considerations

- The target is a login the IdP's own events name, found from the case's own
  user. The crew, or a log line it repeats, cannot point the action at another
  login: anything other than the case's user or its linked login is blocked.
- An attacker on the laptop can create local accounts but cannot make the IdP
  record a sign-in from that laptop for someone else. An attacker who signs in
  to the IdP from the laptop under a second account creates two logins and
  therefore no link, which blocks containment and still pages. The failure mode is no action and a
  page, never the wrong person.
- An attacker who controls a GitHub account in an SSO organisation cannot
  change the SAML identity GitHub records for it.
- Routing reads accounts from the login's IdP events, so the action lands in
  the IdP tenant that saw the login.

## Unresolved questions

- Whether `contain_endpoint_compromise`, which isolates and pages, should also
  revoke the sessions of the host's linked login.
- `google` is not in `linked_from`. A Workspace user federated to Okta or Entra
  would link by same name, but Google has its own playbook and its own actions
  to come (RFC 0013).

## Adoption and migration

Nothing to run. Cases opened before the upgrade are linked when an action is
next proposed on them. The link reads events from the last 30 days, so it works
on old cases while their events are retained.
