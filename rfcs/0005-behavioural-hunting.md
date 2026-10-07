---
rfc: 0005
title: Daily behavioural hunting
status: superseded in part by RFC 0022
authors: ["@Rettila"]
created: 2026-09-24
requirements: ["DET-8", "DET-9", "DET-10", "DET-11", "AGT-3"]
amends: ["D29", "AGT-3 cadence in architecture.md §5"]
---

# RFC 0005: Daily behavioural hunting

## Summary

Hunting in shoc today is indicator search: `hunt.run` takes one value and looks
for it, and `hunt.suggest` proposes more values to look for. That is enrichment
wearing a hunter's name. This RFC makes the Hunter what the role actually is: a
crew member that runs, every day, a budgeted set of *behavioural* hunts over the
telemetry and logs we already ingest, plus a daily read of the company's attack
surface, with threat intel choosing what gets hunted today.

Four pieces: hunt packs as content (DET-8), a daily hunt cycle that selects them
(DET-9), attack surface as a hunted, diffed inventory (DET-10), and a hunt
outcome contract that feeds the Tuner, the case engine and the weekly report
(DET-11).

## Motivation

A hunt asks *is this happening?* about a behaviour nobody has written a rule
for, and it is a success when the answer is no. An indicator lookup asks *have
we seen this value?*, a different and much smaller question, already answered in
bulk by DET-4 feeds and on demand by `intel.lookup` (RFC 0004).

Three things are missing as a result:

- **Behaviour.** Nothing in shoc can ask "which identities called an API today
  that they have never called in the last 30 days", "which key was used from a
  second ASN within an hour", "which repos were made public by someone who has
  never done it before". These are the questions that catch the attacker who
  brought no known-bad infrastructure with them, which is most of them.
- **Cadence.** The Hunter is weekly. A weekly hunt means a technique published
  on Monday is hunted on Friday. Detection runs every five minutes; hunting
  should be a day behind intel, not a week.
- **Surface.** Companies of 20–500 people are compromised through the thing
  nobody knew was exposed: the bucket made public last quarter, the security
  group opened for a contractor, the admin account with no MFA, the still-enabled
  key of someone who left. We already ingest the events that describe all of it
  and we do nothing with them.

And the connection the current design misses entirely: intel should *retarget*
hunting. A digested report (DET-7) names ATT&CK techniques. Those techniques
should decide which hunts run tomorrow. Today a digest produces indicators to
match and a list of plain-language suggestions nobody can execute.

## Guide-level explanation

### DET-8: hunt packs

A hunt is a YAML document in `content/hunts/`, compiled by the same Sigma-subset
compiler as a rule (DET-1), so it is canonical SQL over OCSF and runs unchanged
on every adapter:

```yaml
id: aws_identity_first_api_call
title: An identity calls an API it has never called before
hypothesis: >
  An attacker using stolen credentials performs actions the legitimate owner of
  those credentials has never performed. The first call of a sensitive API by a
  given identity is therefore worth a look, even when every call succeeds.
attack: [T1078.004, T1580]
logsource:
  product: aws
  service: cloudtrail
window: 1d
detection:
  selection:
    api.operation|in: [ListBuckets, GetSecretValue, ListUsers, DescribeInstances]
    status: Success
  condition: selection
baseline:
  first_seen: [actor.user.name, api.operation]
  lookback: 30d
pivot: [actor.user.name, src_endpoint.ip, cloud.account.uid]
triage: >
  Is there a change (a new job, a new tool, a new deploy) that explains this
  identity doing this for the first time today?
```

A pack differs from a rule in three ways, and the differences are the point:

- **No severity and no alert.** A pack returns an *observation set*, not
  findings. A pack that returns 300 rows is a working pack; a rule that does is
  a bug.
- **A baseline.** `first_seen` and `rare` are the two behavioural primitives
  rules do not need. `first_seen: [a, b]` keeps rows whose `(a, b)` tuple does
  not appear in the lookback window; `rare: {by: [...], seen_by_fewer_than: N}`
  keeps rows whose grouping is unusual across the population. Both compile to
  plain `NOT EXISTS` / `HAVING` over the same canonical schema, with no window
  function a dialect might not have, nothing SQLGlot cannot translate, and the
  conformance suite gets both.
- **A hypothesis and a triage question in prose.** They are what makes the
  result readable by a person who is not a hunter, and they are what the Hunter
  is given when it triages.

Packs ship with fixtures like rules do: one fixture that the pack must surface
and one it must leave alone.

### DET-9: the daily hunt cycle

`hunt.daily` is a capability run by the worker on a Postgres cron entry, with an
explicit budget (default: 12 packs, 15 minutes of store time, one run per pack
per day). Selection is deterministic and ranked in this order:

1. **Intel-driven.** Techniques named by any digest (DET-7), feed entry or KEV
   item in the last 7 days, joined to packs by ATT&CK ID. A technique with no
   pack is not silently dropped. It becomes a coverage gap for the Tuner, which
   is the honest answer to "we read about this and can't look for it".
2. **Incident-driven.** Packs whose `pivot` fields touch an entity behind a
   high or critical finding in the last 7 days.
3. **Rehearsal gaps.** Techniques the attack rehearsal (AGT-7) walked without a
   rule firing.
4. **Coverage debt.** Packs not run for the longest, so every pack runs on a
   floor cadence regardless of what the news says.

Everything above is a SQL query over tables we have. No model is involved in
choosing what to hunt, and the cycle runs with `SHOC_LLM_PROVIDER=none`.

### DET-10: attack surface as a daily hunt

Surface is derived from the logs and configuration events we already ingest,
**shoc scans nothing and reaches out to nobody**. Each daily run writes typed
`exposure` records with a stable key, and the value is the diff:

| Exposure | Derived from |
| --- | --- |
| Public bucket / object ACL | CloudTrail `PutBucketAcl`, `PutBucketPolicy` |
| Security group open to 0.0.0.0/0 | `AuthorizeSecurityGroupIngress` |
| Public repository, public gist, disabled branch protection | GitHub audit log |
| User or admin without MFA, dormant-but-enabled account | Okta / IdP events |
| Long-lived access key never rotated, key of a departed user | CloudTrail + IdP deprovisioning |
| New OAuth grant or third-party app with write scope | Okta / GitHub |

Three rules keep this useful rather than a second alert firehose: an exposure
that already existed yesterday is *not* re-raised; a **new** exposure is a
low-severity finding; and an exposure that intersects intel (a KEV CVE on an
exposed service, a public repo touched by an actor in an open case) escalates
and opens a case. Closure is diffed too, so the weekly report can say what got
fixed, not only what is wrong.

This is new scope: the PRD has no attack-surface requirement today. Accepting
this RFC means adding DET-10 to `docs/prd.md` for **v0.4**, after the Hunter
exists. DET-8, DET-9 and DET-11 land with the Hunter in v0.3.

### DET-11: what a hunt run produces

> RFC 0022 replaces this table: `clear` is recorded only for a pack whose data
> can answer it, `explained` writes nothing and needs a basis code can check,
> `inconclusive` is new, and `suspicious` raises a finding rather than a case.

Every run writes a row with an outcome, and the outcome is the contract with
the rest of the system:

| Outcome | Meaning | Goes to |
| --- | --- | --- |
| `clear` | The hypothesis did not hold today | The weekly report, as coverage |
| `explained` | Rows, all matching a known-good baseline | The Tuner, as a baseline fact in memory |
| `suspicious` | Rows a person should see | A case, with the rows as evidence |
| `gap` | The hunt could not run: field missing, source stale | Source health (OPS-1) |

`explained` writing to memory is what stops the same benign first-seen tuple
being surfaced every day forever, and it is why a hunt that finds nothing still
pays for itself.

## Reference-level explanation

- `content/hunts/*.yaml`, loaded like rules; `shoc/detect/hunts.py` for the pack
  loader and the two baseline primitives in the compiler.
- `shoc/agents/hunter.py` gains `select()` (the ranking above) and keeps
  `suggest()` for the indicator case.
- New capabilities: `hunt.pack` (run one pack), `hunt.daily` (run the cycle),
  `hunt.results` (read runs), `surface.list` (exposures, with `since`).
  `hunt.run` is unchanged: indicator search stays, as the narrow case it is.
- New tables: `hunt_packs` (state per pack: last run, outcome, cadence),
  `hunt_observations` (rows a run surfaced, with event UIDs for citation),
  `exposures` (key, kind, first_seen, last_seen, closed_at, evidence). All with
  `tenant_id` and RLS like everything else.
- The daily cycle is a Postgres cron entry and a `SKIP LOCKED` job, like the
  detection scheduler. No new scheduling machinery.

## Drawbacks and the cost we are accepting

**D29 is amended a third time.** Selecting, running and diffing hunts is
deterministic, but deciding whether an observation set is `explained` or
`suspicious` is judgement of the same kind the Investigator does. So the Hunter
gains a prompt and an output schema, and becomes the seventh role that uses a
model, used only to triage a pack that returned rows, never to write a query.
With `SHOC_LLM_PROVIDER=none` the triage step is skipped and every non-empty
observation set is listed in the daily brief for a human, which is worse but
correct.

A daily cycle costs store time every day on every backend, including metered
ones. That is why the budget is explicit, per-pack cadence is a floor rather
than a promise, and Databricks and Snowflake users can lower the pack budget
without editing content.

## Alternatives considered

- **Let the model write the hunt queries.** It is the obvious "AI-first" answer
  and it is wrong: unbounded, non-deterministic SQL against the company's
  warehouse, with an attacker-influenced report as part of the input. Code
  queries, the model triages.
- **Make hunts low-severity rules.** Rules carry alerting semantics,
  deduplication, severity, cases. A hunt that returns hundreds of rows is
  normal; putting that through the finding pipeline would bury real findings.
- **An external attack-surface scanner.** A service to run, outbound scanning
  from the customer's network, and a whole new blast radius, against principle
  3. Everything in DET-10 is already in the logs we ingest.
- **Anomaly detection with embeddings or a model.** Rejected until the evals
  justify it, consistent with the standing position on pgvector. `first_seen`
  and `rare` over 30 days catch most of what a small company needs and can be
  explained to the person being asked about them.
- **Keeping the weekly cadence and doing more per run.** A week of latency
  behind published intel is the specific failure this RFC exists to fix.
