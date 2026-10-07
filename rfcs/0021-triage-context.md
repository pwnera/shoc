---
rfc: 0021
title: Let the crew know shoc, the people who run it, and a person's decision
status: accepted
authors: ["@Rettila"]
created: 2026-10-02
requirements: ["AGT-1", "AGT-3", "AGT-6", "AGT-13", "RSP-1", "RSP-3", "SEC-2"]
supersedes: null
---

# RFC 0021: Let the crew know shoc, the people who run it, and a person's decision

## Summary

shoc records the non-secret id of every credential it is given, the address it
calls out from, the accounts of the person who runs it and of the company's own
automation, and every token request it makes. A finding whose every event is
shoc's own credential at work is marked `self` before any case opens, and kept.
A person closes a case with a disposition that is final for the crew and is
routed as theirs. A closed case stays closed. Amends D42, D43 and D44.

## Motivation

On 2026-10-01 two cases cost 3.1M tokens and were both shoc watching its own
installation:

- **Case A (1.35M tokens).** The "external OAuth client" was shoc's own service
  account, and the "unaccounted cloud host" was the VPS shoc runs on.
  `google_oauth_token_authorized` matched any operation containing `authorize`,
  so each token shoc fetched for itself, about once an hour, opened a finding.
  The operator closed the case at 21:34; a job handed back to the queue after
  15 minutes worked it anyway, set it to suspicious at 0.08, proposed revoking
  the operator's sessions and paged.
- **Case B (1.77M tokens).** The Tailscale client named "shoc" and the
  Cloudflare read token were shoc's own connector credentials. shoc's own
  tailnet node, at 100.64.0.7, was treated as exposed to the internet
  because 100.64.0.0/10 was read as public. A colleague's server setup joined
  the case only because the tailnet name linked every finding from that tailnet.
  After the operator wrote "it's me", the run proposed blocking their address,
  suspending them, disabling shoc's token and removing shoc's host.

Why the crew could not reach a benign verdict:

- Nothing told any role shoc's credential ids, its addresses, who the operator
  is, or when each source started sending.
- The claim check saw 16 summary columns, not the raw event. The scope, the
  client id and the permission names were only in the raw event, so 0 to 3 of 12
  claims counted as shown.
- The rebuttal that would make the Investigator answer the Challenger never ran:
  its budget gate compared the case's lifetime spend with a per-run budget.
- The operator's messages reached only the Investigator's first prompt. A manual
  close recorded no disposition, wrote no memory and set nothing.
- `UNIQUE (tenant_id, entity_key, state)` on `shoc.cases` would have failed the
  next close of a case on the same person.

How SOCs handle this: most "false positives" are real alerts explained by
legitimate activity (Alahmadi et al., USENIX Security 2022); products keep
inventories of service accounts and identities (CIS Control 5.5, Splunk ES
identity lists); Microsoft's triage agents run under their own labelled
identity; Elastic's agentic triage resolves by query whatever a query can
resolve; Sentinel, Splunk and Defender treat an analyst's closure as final and
never merge a new alert into a closed incident.

## Guide-level explanation

When a source is configured, shoc keeps what identifies the credential without
being it: the Google service account's numeric client id with the one scope it
uses, the Tailscale OAuth client id, the Cloudflare token id from
`tokens/verify`. A source configured before this learns it on its next pull.

```
$ shoc own list
credential  100000000000000000042  google_workspace  admin.reports.audit.readonly
credential  kSHOCCLIENT            tailscale
address     203.0.113.10
operator    operator@example.com
```

`own.add` records an address, an operator account or an automation account
(L2: over MCP the person confirms it). `own.remove` forgets one.

A finding is checked before it joins a case. It is shoc's own when every event
it cites is one of these:

- **use**: an event by shoc's credential within 60 seconds of a token request
  shoc recorded, from shoc's address when the event carries one, asking for no
  more than the recorded scope;
- **setup**: the creation or grant of shoc's credential, with exactly its scope,
  in the week before the source was configured.

Such a finding is marked `self`, with the reason and the events, and opens no
case. A stolen shoc key used from elsewhere, or at a time shoc asked for no
token, takes the normal path; so does any revoke, delete, roll or scope change
on shoc's credential, whenever it happens.

An agent's proposal against shoc's own credential or address, or against an
operator account, always waits for a person (L2). It is not blocked: a person
can still approve revoking a stolen shoc key.

A person closes a case with `case.close`:

```
case.close {case_uid, disposition: benign_expected,
            reason: "that was me setting up shoc's Tailscale client"}
```

The verdict cites the case's events, pending proposals are rejected, and a
memory fact is written about the rule and the resource for that time window,
for 90 days. It is never a fact about a person in general and never a
suppression of one. What people write into a case reaches every role in its own
section, marked unverified: it can raise the benign explanation, not settle it,
because a hijacked chat account can say "it's me" too.

## Reference-level explanation

- Migration 030: `shoc.own_identities`, `shoc.own_token_requests`,
  `shoc.source_history`, `connector_config.created_at`, and on `shoc.cases`
  `related_case_uid`, `closed_by`, `disposition_reason`, `token_cap`. The unique
  constraint on cases is dropped.
- `shoc/cases/own.py` holds the registry and `classify`. Connectors note token
  requests in process; `source.sync` writes them. `engine.intake` runs the check,
  then exact (rule, entity) suppressions, before any case opens.
- Case lifecycle: `run_case` stops on a closed case at the start, before the IR
  Commander and before writing the verdict. Jobs are handed back after 30
  minutes, not 15. A finding whose derived case id is closed opens a new case
  that names it. The account id no longer links findings.
- Pages: a `notify.*` action never re-wakes the crew; a page on a closed case
  becomes a digest line; `uncontainable_and_active` needs a finding seen in the
  last hour. Pages keep no confidence floor (RFC 0015).
- Model failures: JSON is parsed with `raw_decode`; 429, 5xx and 524 are retried
  with backoff. A run that fails after the Investigator answered keeps its
  verdict at confidence 0 and routes nothing (amends D42: no role chooses
  `needs_human`, and a broken run no longer throws away what it learnt).
- The rebuttal runs whenever the Challenger's argument rests on something; an
  invented one only on budget, now counted per run. The claim check and the
  dossier read the raw event as flat fields capped at 200 characters. A failed
  claim check says so instead of "0 of 12". `ReadOutput` has no default verdict.
- Addresses: 100.64.0.0/10 is not internet-routable. 2001:db8::/32 joins the
  documentation ranges.
- Mappings: Google's `API_CLIENT_NAME` and Cloudflare's `resource.response.id`
  map to `resource_uid`; reading one named parameter no longer drops the values
  of the others from `unmapped`.
- `google_oauth_token_authorized` selects exactly the token log's `authorize`;
  domain-wide delegation has its own rule. `cloudflare_api_token_revoked` makes
  taking shoc's token away reach a person.

Principles touched: 5 (bounded autonomy: own targets are L2), 6 (evidence or
nothing: the intake check cites its events), 7 (`tenant_id` on every new table).

## Drawbacks

- The check trusts shoc's own clock and records. A process that fetched a token
  and died before `source.sync` wrote it leaves that request unrecorded, and the
  next event by shoc's credential opens a case. That is the safe direction.
- Tailscale logs no address, so on Tailscale the time match is the only test.
- The setup window is a week before configuring; a credential made earlier and
  given to shoc later opens one case, once.

## Alternatives

- **A model turn over the same query.** Rejected: it states a fact, and a model
  would pay tokens to agree with it.
- **Suppress by entity name.** Rejected: a client called "shoc" proves nothing,
  and a suppression on a person makes them invisible.
- **Purge the foreign rows loaded on 2026-09-27.** Left to the operator: no
  capability deletes events, and a delete outside the audit chain is not ours.
