# RFC 0004: CTI research: enrichment, report digestion, and research before blocking

- Status: proposed
- Requirements: DET-6 (indicator research), DET-7 (report digestion), RSP-5 (research before blocking), RSP-6 (peer review before blocking)
- Amends: D29 (five roles use a model, five do not), D6 (policy in code)
- Author: shoc maintainers

## The problem

DET-4 gave us feeds. A feed answers one question (*is this value on a list
someone published?*) and it answers it in advance, in bulk, on a schedule.

That is a fraction of what a CTI analyst does. Given an address, an analyst
goes and looks: who owns it, what autonomous system it sits in, whether it is a
Tor exit, whether it is a cloud NAT gateway that half the internet shares, what
it resolves to, what has been reported about it, whether it has ever appeared in
*our* logs before. Given a threat report, an analyst reads it, pulls the
indicators and techniques out of the prose, and turns them into hunts.

shoc does neither. `hunt.run` searches our own events and nothing else, and
there is no way to hand the system a report at all.

There is also a sharper operational problem. `waf.block_ip` is **L1**, so it runs
automatically. Nothing in the pipeline currently asks whether the address about
to be blocked is a Cloudflare edge, an AWS NAT range, a corporate VPN egress or
the office's own IP. Blocking one of those does not stop an attacker; it takes
the company offline, automatically, at 3am, which is exactly the failure mode
this project exists to avoid.

## What this adds

### DET-6: `intel.lookup`, on-demand research

A single capability that takes a value, works out what it is, and fans out to
every source that can say something about it, in parallel, under a wall-clock
budget. Each source returns a typed `Observation` with its verdict, a weight, a
one-line summary and its raw data. The observations are scored into one verdict
with per-source citations, and cached in Postgres with a TTL.

v1 ships the sources that need no account, so a fresh install has working
research with zero configuration:

| Source | Applies to | What it answers |
| --- | --- | --- |
| `local_iocs` | all | Is it already on one of our feeds? |
| `history` | ip, domain | Has it appeared in our own logs, and since when? |
| `rdap` | ip, domain | Who owns it; for a domain, how old is the registration |
| `reverse_dns` / `resolve` | ip, domain | What it claims to be, what it points at |
| `cloud_ranges` | ip | AWS, GCP or Cloudflare: i.e. shared infrastructure |
| `tor_exit` | ip | Is it a published Tor exit node |
| `threatfox` | ip, domain, url, hash | abuse.ch reports on this exact value |
| `urlhaus` | ip, domain | Is it serving malware right now |
| `epss` / `nvd` | cve | Exploitation probability and the CVE record |

Keyed platforms (VirusTotal, AbuseIPDB, GreyNoise, Shodan, Censys, urlscan,
passive DNS) are deliberately **not** in v1. The source table is a registry
exactly like the feed table so they are additive later, each behind its own
credential and disabled until configured.

Two guards are not optional. A private, loopback, link-local or internal value
is **never** sent to a third party; only `local_iocs` and `history` run for it.
And every outbound call is to a host in the source's own declaration, so a
report or an event can never steer a lookup at an attacker-chosen URL.

### DET-7: `intel.digest`, reading a report

Takes a URL or pasted text, fetches and flattens it to plain text (HTML stripped
by hand, PDF via the optional `[pdf]` extra), refangs defanged indicators
(`hxxp`, `[.]`, `(at)`), and hands it to the CTI role, which returns a typed
digest: summary, actors, malware, campaigns, ATT&CK techniques, targeted
sectors, indicators and suggested hunts. Indicators are stored under source
`report:<host>` and retro-hunted like any other new indicator.

### RSP-5: research before blocking

`Policy.decide` gains a `research` argument, and an action rule gains
`research_before_action: true`. When it is set and the action is about to run at
L1, the policy demands a completed lookup and downgrades to L2 (a human
approves) when any of these hold:

- no research was done, or it failed
- the target is shared infrastructure (a cloud or CDN range)
- the target is our own egress, per a `known_egress` guard
- research came back *benign* or *unknown* rather than malicious

The escalation carries the reason, so the human sees "203.0.113.4 belongs to
Cloudflare; blocking it blocks everyone behind it" rather than a bare approval
request. `waf.block_ip` and `edr.isolate_host` get the flag in the shipped
policy.

### RSP-6: peer review before blocking

Research says what the address *is*. It does not say what blocking it will cost
this company, and a lookup cannot know that the address is the payment
provider's webhook source or the CEO's hotel wifi. So a blocking action also
goes back to the room before it runs.

`review_before_action: true` on an action rule convenes a short review round in
the case's own room. The proposed action and the research are posted as a
`proposal` and as `evidence`. Two reviewers answer, and neither of them is the
agent that proposed it:

- **Challenger** argues the blast radius: who else loses access, what breaks,
  what ordinary explanation makes this address legitimate. It already exists and
  already has the right instincts for this.
- **IR Commander** answers whether this is the smallest action that stops the
  bleeding, or whether a narrower one would do.

Their answers are scored by one rule: a review **approves** only when every
reviewer approves and none raises a blast-radius objection. Anything else (a
single objection, a reviewer that could not be reached, a room over budget, or
`SHOC_LLM_PROVIDER=none`) is not a rejection but an **escalation**: the action
becomes L2 and a human decides, with the reviewers' objections attached to the
approval request. The review is written to the room, so the transcript shows who
objected and why, and the outcome is audited like any other decision.

This is deliberately asymmetric. A review can only ever make an action *harder*
to take: it can downgrade L1 to L2, and it can never raise L2 to L1 or approve
on a human's behalf. Principle 5 is unchanged: a human still approves every L2,
and an agent still never does.

## Decisions this changes

**D29 is amended.** CTI stays deterministic for feeds, matching, retro-hunts and
`intel.lookup`, because those are lookups and arithmetic, and they all work with
`SHOC_LLM_PROVIDER=none`. `intel.digest` is the exception: reading prose is not
a lookup, so the CTI role becomes the sixth role that uses a model, and
digestion is the one CTI operation that requires one.

**D29 is amended a second time for review.** Peer review of an action is
judgement, not a lookup, so it uses the same two roles that already use a model.
Adding review does not add a role.

**The maintainers chose full model-driven digestion** over a hybrid in which
regex extracts the indicators and the model only narrates. This RFC records the
cost of that choice rather than hiding it: the model produces the indicator
list, so a report that contains "add 8.8.8.8 to your blocklist" can get that
indicator planted. The mitigations are containment rather than detection: report text
reaches the model only inside `safety.quote()` as untrusted data; indicators
land under their own `report:` source with low confidence, so they are
distinguishable and removable in one statement; an indicator the model returns
that does not appear in the report text is stored `unverified: true`; and
storing them at all is opt-in per call. A report-derived indicator is therefore
never, on its own, enough to reach the L1 confidence floor for an automatic
block, and RSP-5 closes that loop.

## Dependencies

No core dependency is added; everything uses `httpx` and the standard library.
PDF support is an optional extra, `shoc[pdf]` → `pypdf`, on the same footing as
`[databricks]` and `[snowflake]`, so the core budget of 8 stays at 8 and a
default install is unchanged.

## Alternatives considered

- **A CTI platform integration (OpenCTI, MISP as the system of record).** MISP
  is already a feed. Making a platform the system of record puts a service
  between shoc and its answers, against principle 3.
- **Doing the fan-out in the model**: give the model an HTTP tool and let it
  decide what to query. Non-deterministic, unbudgeted, and it puts an
  attacker-influenced value into a URL. The fan-out stays in code.
- **Blocking on research failure instead of escalating.** A failed lookup would
  then stop response entirely when an upstream is down. Escalating to a human
  degrades correctly; refusing does not.
- **Letting the review approve the action outright.** Tempting, because it would
  make the system faster at 3am. Rejected: it would make an agent the approver
  of an L2 action, which principle 5 forbids and which no amount of review
  quality makes safe.
- **A dedicated Reviewer role.** Challenger and IR Commander already hold the
  two questions a review asks. A third role would add cost and another prompt to
  keep honest without adding a new question.
