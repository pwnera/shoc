# RFC 0006: The agent pool: intel, posture and review

- Status: proposed
- Requirements: AGT-3 (roles), AGT-4 (graph and memory), AGT-7 (rehearsal), RSP-6 (peer review), OPS-1
- Amends: D32 (CTI is deterministic except for reading a report); D29 is already amended by RFC 0005
- Depends on: RFC 0004 (CTI research), RFC 0005 (daily behavioural hunting)
- Author: shoc maintainers
- Full specs: `docs/agent-specs.md`
- Benchmark against real SOC practice: `docs/soc-practice-benchmark.md`, whose
  thirteen proposed changes (dispositions, ADS rule metadata, hunt backlog, PIRs,
  the notification clock, source quality) extend this RFC and need one of their own

## The problem

`docs/agent-specs.md` was written by describing each agent as a person you had
hired. Four of them did not survive the description.

1. **The Hunter is not hunting**: it pops indicators nobody has retro-hunted
   from a queue, which is IOC search wearing a hunting label. This RFC raised
   it and **RFC 0005 answers it**; the entry stays here only so the four gaps
   this page opened with are all accounted for.
2. **CTI is two different things.** After RFC 0004 the role covers feeds and
   `intel.lookup` (deterministic) and `intel.digest` (judgement). D32 records
   this as "deterministic except when it isn't", which makes the pool's model
   boundary unreadable.
3. **Nobody owns posture.** Four agents need to know what the company actually
   runs: the Investigator (is this identity privileged?), the IR Commander
   (what does suspending it cost?), CTI (is this CVE relevant?), the Rehearsal
   (what are the real entry points?). All four currently guess.
4. **The Challenger does two jobs.** "Is this actually bad?" is answered from
   the case evidence. "What breaks if we block this?" is answered from the
   company's graph and memory, which the Challenger is never shown. One persona
   was arguing blast radius from the attack narrative.

## What this changes

### 1. The Hunter: settled by RFC 0005, not here

The first draft of this RFC gave the Hunter a model that filled a typed
`HuntPlan` grammar. **RFC 0005 (daily behavioural hunting) supersedes that**,
and is the better answer: hunts are YAML packs in `content/hunts/` compiled by
the same Sigma-subset compiler as a rule, with two new baseline primitives
(`first_seen`, `rare`); selection is a deterministic ranked query (intel,
incident, rehearsal gap, coverage debt) and the model is used **only to triage
an observation set that came back**, never to express a query.

That keeps hunts reviewable content with fixtures, like every other detection
in this repo, instead of a grammar a model fills each morning. `docs/agent-specs.md`
§8 now describes the Hunter as RFC 0005 designs it. The spec adds nothing to
that design except the persona and the boundaries.

### 2. CTI keeps the judgement; the rest becomes the intel plane (amends D32)

Feeds and `intel.lookup` stop being an agent and become a service any agent may
call, described in RFC 0004. CTI is the role that reads a report and decides
what it means here, and it must ask the Surveyor whether the company runs the
affected thing before writing `relevance`. Guards are unchanged.

### 3. A new agent: the Surveyor (eleventh role, no model)

**Boundary with RFC 0005 (DET-10), unresolved.** RFC 0005 derives attack
surface as a daily hunt owned by the Hunter, writing typed `exposure` records
and diffing them. This RFC gives posture to a Surveyor. These are the same
tables seen from two directions and **only one of them should own the write
path**. The recommendation below is that DET-10's daily diff stays the Hunter's
mechanism and the Surveyor owns the `exposures` table, the identity and asset
picture around it, and the questions other agents ask of it, but that is the
first thing this review should settle, not something either RFC should assume.


Maintains the asset, identity and exposure picture **derived from ingested
events**: no scanner, no host agent, no new service. Answers `posture.get` and
`posture.exposure` with event citations. Deterministic on purpose: the answer
must be identical every time it is asked.

It has an honest limit. Events show what happened, not what merely exists, so
full posture needs a configuration-snapshot connector kind (AWS Config, Okta and
GitHub org state). Until that lands the Surveyor answers from activity only and
says so in every answer.

### 4. A new agent: the Operator (review only, cheap model)

Takes the blast-radius half of the review from the Challenger. Reads the graph
neighbourhood of the target and tenant memory (the inputs that actually answer
the question) plus the CTI research. Reviews alongside the IR Commander, which
still answers whether the action is the smallest that would do.

**A deterministic guard runs first:** more than `MAX_SHARED_PRINCIPALS`
(default 3) distinct principals behind the target in the window escalates to L2
**without asking a model**. Uncertainty, and a failed graph or memory lookup,
are refusals. A review can still only ever make an action harder to take.

## Consequences

- The pool becomes twelve agents: the Surveyor is the eleventh, the Operator
  the twelfth: **seven use a model, five do not** (plus the
  rehearsal personas, the playbook runner and the human, none of which do).
  D29's "five and five" and D32 are superseded.
- New capabilities: `posture.get` and `posture.exposure`. Hunt storage belongs
  to RFC 0005.
- `shoc/cases/review.py:REVIEWERS` becomes `(OPERATOR, COMMANDER)`.
- `SHOC_LLM_PROVIDER=none` still works: hunting falls back to the deterministic
  candidate queue, CTI to feeds and lookups, and every review escalates to L2.
- No new dependency. The hunt compiler reuses SQLGlot and the rule field list;
  posture is SQL over events already ingested.

## Alternatives considered

- **A model-written hunt grammar** (this RFC's first draft). Rejected in favour
  of RFC 0005's packs: a hunt that is content has fixtures, review and a diff;
  a hunt a model composes each morning has none of those, and a report the CTI
  role just read is upstream of it.
- **Give posture to Ops.** One fewer role, but Ops watches shoc's pipeline and
  the Surveyor watches the company. Merging them produces a health check that
  cannot answer "do we run this?".
- **Leave the review with the Challenger** and just show it the graph. Possible,
  but the prompt then holds two incompatible instincts (argue it is benign,
  argue it will break) and the failure mode is a reviewer that approves.

## Open questions

Carried in `docs/agent-specs.md`: the hunt grammar's width, the daily hunt's
running cost, whether `MAX_SHARED_PRINCIPALS = 3` is right, whether the Surveyor
ships activity-only, and the Operator/Ops name collision.
