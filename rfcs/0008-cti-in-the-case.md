---
rfc: 0008
title: CTI in the case, and an Investigator that can pivot
status: draft
authors: ["@Rettila"]
created: 2026-09-25
requirements: ["AGT-9", "AGT-10", "DET-12", "DET-4", "DET-6", "DET-7", "AGT-1", "AGT-2"]
amends: ["docs/agent-specs.md §8 (CTI), §2 (Investigator), the interaction map and the tool access matrix"]
depends_on: ["RFC 0003 (case-room protocol)", "RFC 0004 (CTI research)", "RFC 0006 (agent pool)"]
supersedes: null
---

# RFC 0008: CTI in the case, and an Investigator that can pivot

## Summary

Four things the SOC is described as doing, it does not do. CTI never touches a
case: indicators are matched by the detection cycle and researched on demand,
but nobody enriches the entities of a case that is already open, and nothing
compares the case's behaviour against the reports we have digested. CTI is not
a participant in the room: it has a persona and an output schema, and no seat.
The Investigator sees one fixed dossier and cannot ask a second question of the
data lake, so every pivot a human analyst would make by hand is unavailable to
it. And the indicator model is loose enough that a URL silently becomes a
domain: `https://cdn.example.com/a/payload.bin` is stored as the domain
`cdn.example.com`, which then matches every event that ever touched that CDN.

This RFC adds a deterministic CTI enrichment pass over an open case, gives CTI
a seat in the room, gives the Investigator a bounded pivot budget over the
event store, and replaces the five loose indicator strings with a typed
observable model in which derivation is an explicit, recorded, lossy step that
never inherits a verdict.

## Motivation

### 1. Nothing enriches a case

`shoc/detect/intel.py` matches indicators forward on every detection cycle and
backwards on a retro-hunt. `intel.lookup` (RFC 0004) researches one indicator
when somebody asks. Between them there is a hole: a case that is already open,
whose findings carry a dozen addresses, users, hashes and operations, and whose
dossier (`shoc/agents/loop.py:build_dossier`) contains findings, raw events,
tenant memory, the graph neighbourhood and the Surveyor's posture, and not one
word of threat intelligence. The Investigator is asked for a disposition on
`203.0.113.4` without being told that the address is on two feeds we already
pull, is a Tor exit, and appeared in a report we digested last week.

This is the enrichment step that every real SOC performs before an analyst
looks at an alert, and we perform it nowhere.

### 2. The digested reports are write-only

`intel.digest` (DET-7) reads a report into actors, malware, campaigns, ATT&CK
techniques and indicators, and stores it. Nothing reads it back. A case carries
`attack` technique IDs from its findings; a report carries technique IDs from
its digest; the two are never joined. The question "is what we are looking at
right now something we have read about?" justifies having a CTI function at
all, and it cannot be answered.

### 3. The Investigator gets one look

`build_dossier` is assembled once and the Investigator answers from it. Every
question a human analyst asks next is out of reach: what else did this key do
in the hour before, has this user ever signed in from this country, did anyone
else hit this endpoint, what happened on the host after the process ran. The
matrix in `docs/agent-specs.md` already grants the Investigator `events.query`
"(i)" (indirectly, assembled by the loop), but the loop assembles exactly one
query and then stops.

### 4. An indicator is a string with a loose label

`shoc/detect/intel.py` carries five types (`ip`, `domain`, `url`, `sha256`,
`cve`) and treats them casually:

- The URLhaus feed takes a malware distribution URL and stores its **host** as
  a domain indicator at confidence 0.75. A payload hosted on a compromised
  WordPress site, a Discord CDN or an S3 bucket turns the whole host into a
  known-bad domain, and every event touching it becomes a finding.
- `MATCH_COLUMNS` maps `url` to `src_endpoint_domain`, so a URL indicator is
  matched against domains, a type error written into a table.
- `host_of()` in `osint.py` flattens a URL to its host for research. That is
  correct for asking RDAP who owns it; it is not correct for deciding that the
  host is malicious, and the code does not distinguish the two uses.
- `md5` and `sha1` are classified by `osint.classify` but cannot be stored:
  `store_indicators` has no type constraint, so they land in a table nothing
  matches against.
- Everything is matched against `src_endpoint_*` only. An outbound connection
  to a C2 address has the address as the destination, and we have no
  destination columns at all.

A CTI function that is imprecise about this is worse than none: it manufactures
findings, and the first time an analyst is paged because a shared CDN was on a
feed, they stop reading our findings.

## Guide-level explanation

### A case that has been enriched

```
$ shoc case show C-8f21
Case C-8f21 · aws_key_from_new_asn · high · analysis

Intel (7 observables, 3 with something to say)
  ip:203.0.113.42        malicious  score 5.5  abuse.ch/feodo, tor_exit, history(14)
  url:http://203.0.113.42/x/p.bin  suspicious  score 2.0  urlhaus
    └ derived host ip:203.0.113.42 (from url, not itself an indicator)
  sha256:9f86d0…          unknown    score 0.0  no source had anything
  domain:cdn.example.com  benign     score -1.0 shared infrastructure (CDN)

Campaign match (2 of 5 techniques, 1 indicator)
  "Storm-0558 style token theft", digested 2026-09-18
  shared: T1078.004, T1528 · shared indicator: 203.0.113.42
```

In the room, CTI speaks before the Investigator does:

```
round 1 · CTI · observation:
  203.0.113.42 is a Feodo C2 on two feeds and a Tor exit; it is in our logs
  14 times in 90 days, all in the last six hours. The sha256 is unknown
  everywhere. cdn.example.com is a CDN edge and is not evidence of anything.
  Two of this case's five techniques (T1078.004, T1528) match a report we
  digested on 2026-09-18, which shares this address.
  [cites E-…, E-…]
```

### An Investigator that can ask

```
round 1 · Investigator · pivot (1 of 3):
  {"field": "actor.user.name", "value": "svc-deploy", "since": "-24h",
   "why": "did this service account do anything else from a new address?"}
  → 38 events, 4 new event_uids in evidence

round 1 · Investigator · hypothesis: … [cites E-…, E-…, E-…]
```

The pivot is a typed request against a whitelist of fields, not SQL. Three per
case at high severity, one at medium, none below. Everything it returns is
added to the evidence and becomes citable, so a verdict built on a pivot is
still a verdict with event UIDs behind it.

### An indicator that knows what it is

```yaml
# what URLhaus produces after this RFC
- type: url
  value: http://203.0.113.42/x/p.bin
  confidence: 0.75
  source: abuse.ch/urlhaus
- type: ipv4
  value: 203.0.113.42
  confidence: 0.30              # derived, and it says so
  derived_from: url:http://203.0.113.42/x/p.bin
  relation: host_of
  match: false                  # never matched on its own
```

## Reference-level explanation

### A. The observable model (DET-12)

A new module `shoc/detect/observables.py` owns what an indicator *is*. It is
deterministic, has no dependencies, and is the only place that classifies or
derives.

```python
KINDS = ("ipv4", "ipv6", "cidr", "domain", "fqdn", "url", "email",
         "md5", "sha1", "sha256", "cve", "asn", "user_agent",
         "file_path", "registry_key", "mutex", "jarm", "ja3")

@dataclass(frozen=True)
class Observable:
    kind: str
    value: str                 # normalised: lowercased host, punycode, no trailing dot
    derived_from: str = ""     # "url:http://…" when this came from another observable
    relation: str = ""         # host_of | domain_of | resolved_to | contained_in
```

Three rules bind it:

1. **Derivation is lossy and recorded.** `derive()` returns the host of a URL
   as an `ipv4`/`ipv6`/`domain` observable with `derived_from` and `relation`
   set. A derived observable is stored with `match = false` and its confidence
   floored at 0.3: it is context for an analyst, never a matching rule. Only a
   source that asserts the host itself (Feodo naming an address, a report
   naming a domain) produces a matchable host indicator.
2. **`domain` and `fqdn` and `ip` are different questions.** A domain
   indicator matches the registrable domain and its subdomains; an `fqdn`
   matches exactly. An address is never inferred from a domain (no resolution
   at match time; today's A record is not evidence about last week's event),
   and a domain is never inferred from an address (no reverse DNS as truth).
   A `resolved_to` edge may be *recorded* by research, with the time it was
   observed, and is shown to an analyst as context.
3. **Shared infrastructure is a property, not a verdict.** `osint.py` already
   detects CDN, cloud, Tor and VPN ranges. An observable that resolves to
   shared infrastructure can never carry a matchable indicator above
   confidence 0.5, and the enrichment says so in one sentence.

Migration: `shoc.iocs` gains `derived_from TEXT`, `relation TEXT`,
`match BOOLEAN NOT NULL DEFAULT true`, and a CHECK constraint on `type` over
`KINDS`. Existing `ip` rows become `ipv4`/`ipv6` by inspection; existing
URLhaus-derived `domain` rows are the reason this RFC exists and are deleted
rather than migrated; they are re-derived on the next feed pull with
`match = false`. `MATCH_COLUMNS` is rewritten per kind, and destination
columns (`dst_endpoint_ip`, `dst_endpoint_domain`, `dst_endpoint_port`) are
added to the OCSF layout, because outbound C2 is a destination and we cannot
currently see it. That layout change is a public contract change and is called
out below.

### B. Case enrichment (AGT-9)

A new capability `intel.enrich_case`, deterministic, no model:

1. Collect observables from the case: the `entities` and `evidence` of every
   finding, plus the `observables` column of every evidence event (already
   populated by the ingest mappings), classified through
   `observables.classify`. Cap at 25, ordered by how many events carry them.
2. Run `intel.lookup` for each. The cache makes this cheap and the existing
   internal/documentation guard already stops private values leaving.
3. Join the case's ATT&CK techniques and indicators against digested reports
   (`intel.digest` output): a report matching on two or more techniques, or on
   any indicator, is a campaign match with the overlap named. Technique
   matching is exact on the ID, and a sub-technique matches its parent.
4. Write the result to `shoc.case_intel` (one row per case per observable,
   with its verdict, score, sources and `derived_from`), publish
   `case.enriched`, and return it.

It runs when a case is opened, and again when a feed or a digest introduces an
indicator that the case already contains: the retro-hunt's logic, scoped to
open cases. `build_dossier` grows an "Intel" section rendered from
`shoc.case_intel`, labelled as what it is: third-party assertions about
infrastructure, not evidence about this company.

### C. CTI in the room (AGT-9)

CTI becomes a room participant with a second output schema,
`CtiEnrichmentOutput`, distinct from `CtiDigestOutput`:

```python
@dataclass
class CtiEnrichmentOutput:
    assessment: str            # three sentences at most
    notable: list[str]         # observables that change the picture, and why
    dismissed: list[str]       # observables an analyst should ignore, and why
    campaign_match: str        # named report and the overlap, or empty
    actor_hypothesis: str      # named only when the overlap supports it
    citations: list[str]       # event_uids the observables appeared in
    confidence: float
```

The model turn is narrative only: the scoring, the matching and the campaign
overlap are computed before it runs, and the model is shown the computed
result. It cannot invent an indicator, because its message is posted through
the room's citation check like everyone else's, and the observables it may
discuss are the ones in `shoc.case_intel`.

Position in the loop: **after** Sentinel and **before** the Investigator, at
`medium` severity and above, and skipped entirely when enrichment found nothing
with a verdict. An empty CTI turn is a wasted model call, and the room says
nothing rather than posting "no intelligence available". CTI may also be
re-asked when a pivot or a late enrichment introduces a new observable, subject
to the same budget as everyone else.

Two prompt rules matter, both from RFC 0004: the report and the OSINT answers
reach CTI inside an untrusted-data block, and CTI must say plainly when an
observable is *not* interesting. "Nothing here" is the answer most cases
deserve and the one an unconstrained model will not give.

### D. The Investigator pivots (AGT-10)

A pivot is a typed request, never SQL:

```python
@dataclass
class Pivot:
    field: str        # from PIVOTABLE, not free text
    value: str
    since: str = "-24h"
    until: str = ""
    why: str = ""     # one sentence, recorded in the room
```

`PIVOTABLE` is the subset of the OCSF layout worth pivoting on: the actor
fields, the source and destination endpoint fields, the session UID, the API
operation and service, the cloud account, the resource UID, the product. Each
pivot is compiled by the existing `shoc/capabilities/events.py:build_query`,
scoped to the tenant, capped at 200 rows and the case's retention window, and
its results are appended to the evidence set so the returned UIDs are citable.

Budget: three pivots at `critical`, three at `high`, one at `medium`, none
below. Pivots are a model call each and the severity ladder already decides
what a case is worth. Every pivot is posted to the room as a message of a new
kind, `pivot`, with its `why` and its row count, so the transcript shows what
the Investigator asked and not only what it concluded. `pivot` does not require
citations (it is a question, not a claim) and is added to `KINDS` in
`shoc/agents/room.py`.

This is the one change here that puts a model in a loop. The loop is bounded by
count, by the field whitelist, by row caps and by the room's existing token and
time budgets; a pivot that returns nothing ends the sequence.

### Principles touched

- **Headless first**: all four changes are capabilities
  (`intel.enrich_case`, `events.query` under a pivot budget) and room message
  kinds. No surface is hand-written.
- **Evidence or nothing**: strengthened. A pivot's rows become citable
  evidence; CTI's assessment is checked against the store like any other
  message; a derived observable can never become a finding on its own.
- **Minimal dependencies**: nothing new. The enrichment is SQL and the existing
  `httpx` OSINT sources.
- **Bounded autonomy**: unchanged. Nothing here acts; CTI and the Investigator
  read.

## Drawbacks

The pivot loop is the first place a model chooses what runs next, and that is a
real widening of the blast radius of a prompt injection in log content: a
crafted user-agent could ask for a pivot. The field whitelist and the row cap
bound the damage to "the model wasted one query", but the property that every
query in shoc is chosen by code is gone, and it will not come back.

Enrichment costs an `intel.lookup` per observable on every new case. The cache
and the 25-observable cap bound it, but a noisy day now makes outbound OSINT
calls proportional to case volume.

The observable rewrite invalidates stored indicators and changes the OCSF
layout, which is a migration for every existing install and a conformance-suite
change for every adapter.

## Alternatives

**Do nothing.** The SOC keeps producing dispositions that no analyst would
produce, because no analyst would answer without enriching first. The URLhaus
derivation keeps manufacturing findings on shared hosts, and the first one that
pages somebody at 3am costs more trust than this RFC costs effort.

**Enrich, but keep CTI out of the room.** Put the intel block in the dossier
and let the Investigator read it. Cheaper by one model call, and it was the
first draft of this RFC. It fails on the dismissal half: the Investigator is
incentivised to use what it is shown, and the value of a CTI turn is largely in
saying which four of the seven observables should be ignored. That argument has
to be made by someone whose job is not reaching a verdict.

**Give the Investigator free SQL instead of typed pivots.** More powerful, and
it makes injected log content able to write a query. Rejected.

**Keep one `ip` type and handle precision in prompts.** Rejected by principle:
a type error belongs in a type, not in a system prompt that a cheaper model
will ignore.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes:
  - `shoc.iocs`: new columns `derived_from`, `relation`, `match`; `type` gains
    a CHECK over `KINDS`; `ip` splits into `ipv4`/`ipv6`.
  - OCSF layout: new `dst_endpoint_ip`, `dst_endpoint_domain`,
    `dst_endpoint_port` columns and `FIELD_MAP` entries. Every adapter's
    conformance run changes; connector mappings gain destination observables
    where the source has them.
  - New table `shoc.case_intel`; new event type `case.enriched`.
  - New capabilities `intel.enrich_case`, scope `intel:read`.
  - Room message kinds gain `pivot`.
  - `intel.list` output gains the derivation fields.
- New requirement IDs for `docs/prd.md`: **AGT-9** (CTI enriches and speaks in
  a case), **AGT-10** (bounded Investigator pivoting), **DET-12** (typed
  observables with recorded derivation).

## Security considerations

Enrichment sends observables to third parties. The existing
`osint.is_internal` guard keeps private addresses, internal suffixes and
documentation ranges local, and it is now the guard for a code path that runs
on every case rather than on request. It needs a test per kind, not per call
site.

CTI's model turn reads OSINT summaries and digested reports, both of which are
third-party text. They are quoted through `safety.quote`, as report text
already is.

The pivot loop lets untrusted log content influence which query runs. Mitigated
by the whitelist, the row cap, the pivot count and the tenant scope; a pivot
cannot reach another tenant, another table or another time range than the
case's retention window.

Nothing here gains an action. CTI and the Investigator remain read-only, and
`action.run` stays on the playbook runner alone.

## Unresolved questions

- Should a campaign match raise a case's severity on its own, or only inform
  the Investigator? Raising severity from a third-party report means a vendor
  blog can page somebody. The conservative default is "inform only", and this
  RFC takes it.
- Does `resolved_to` belong in the graph (`shoc/agents/graph.py`) rather than
  in the indicator table? Probably yes, and it can move later.
- The 25-observable cap and the pivot budgets are guesses. They should come out
  of the eval harness (AGT-6) before v0.3 ships.
- Destination columns are a bigger change than this RFC: they affect every
  connector mapping. They may deserve splitting out.

## Adoption and migration

Forward-only migration adds the columns, the table and the constraint, and
deletes URLhaus-derived domain indicators so they can be re-derived correctly
on the next pull. Enrichment is on by default and degrades to nothing when no
source answers. The CTI room turn is on for `medium` and above and can be
turned off per tenant with the same configuration that sets budgets. Pivoting
is off by default for one release, on afterwards, so the eval harness has a
release in which to measure whether it changes verdict quality or only spends
tokens.
