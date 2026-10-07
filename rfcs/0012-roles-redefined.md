---
rfc: 0012
title: Redefine every role
status: accepted   # as built and as amended by D55, D57, D58, D67, D74, D77, D78, D79; see "As built"
authors: ["@Rettila"]
created: 2026-09-27
requirements: ["AGT-1", "AGT-2", "AGT-3", "RSP-2", "RSP-6", "RSP-7", "DET-4", "OPS-1", "ING-1"]
supersedes: ["the rounds and the Orchestrator of RFC 0003", "peer scheduling in RFC 0010"]
---

# RFC 0012: Redefine every role

## Summary

The crew is rebuilt around who actually runs it. Two roles are deleted, one is
split, one is added, and the five roles that had no model get one. The
Investigator stops waiting for rounds and calls the other roles while it is
thinking, so the openspace becomes the record of a case rather than the mechanism
that drives it. `needs_human` stops being a verdict anyone may choose.

## As built (2026-10-02)

The code follows this RFC as later decisions amended it. Where the two differ,
the code and `docs/decisions.md` hold, and the sections after this one record
the proposal as it was written.

**Built as proposed.**

- Roles call roles (D41). `Role.peers` names who a role may ask, and the
  `ask_<role>` tools in `shoc/agents/tools.py` run the peer with its own
  principal and its own tools. Each exchange is written to the openspace as a
  `request` and an `answer`. The ceiling is six peer calls per case
  (`MAX_PEER_CALLS` in `shoc/agents/loop.py`), the same at every severity.
  `roles.interested` and the `domain` lists are gone. `request`, `answer` and
  `interject` stay valid kinds; nothing writes `interject`.
- No role may choose `needs_human` (D42). A case still reaches it with no model,
  with an uncited verdict, or when a run breaks before the Investigator answers.
- The Orchestrator and the Operator are deleted (D45). The Investigator closes a
  case that needs no response and the IR Commander one that does; a missed
  deadline nudges once and pages the second time (D51, `shoc/cases/unattended.py`).
- The Challenger argues against whichever verdict was reached, once per run. Its
  suppression is written by `routing.suppress_draft`, active at once and capped
  at seven days.
- The Detection Engineer merges its own rules behind fixtures, a backtest and the
  ADS form, and narrows a shipped rule only by an exclusion composed at load time
  (D48, amended by D55 and D77). A second benign close within 30 days opens an
  item for it; the third-suppression rule was dropped.
- The weekly report's figures come from queries and it is sent with no model.

**Changed by later decisions.**

- The Reporter is the Manager, the operator's one contact (RFC 0015, D58).
- The Integrator is code in `shoc/agents/integrator.py`; a model only moves a
  mapping's field paths after a vendor changes shape (D74). `roles.ALL` holds
  ten roles, and the Integrator makes eleven members.
- The Hunter keeps `clear`, runs reviewed packs on data that is ready and writes
  no queries of its own (RFC 0022, D79). A pack that confirmed two true-positive
  cases goes to the Detection Engineer's backlog.
- The KEV feed and the Surveyor's "exploitable now" question were removed (D57),
  so D47 counts five Surveyor questions.
- The Investigator and the Manager may ask CTI; the Hunter and the Detection
  Engineer have no CTI peer (RFC 0022, D77). The abuse.ch feeds are on by
  default and announced (D57).

**Not built.**

- Sentinel. Its prompt and `SentinelOutput` exist and nothing calls them. The
  case engine groups findings by shared entity (`shoc/cases/engine.py`), with no
  graph-path or campaign grouping and no deferral. With no model the pipeline
  does not stop: cases open and end in `needs_human`.
- A model in Ops, and a Surveyor agent above its queries. Ops makes no model
  call; the Surveyor uses one only when a peer asks what an address, host or
  identity is. `shoc/agents/surveyor.py` still computes `exploitable`, which now
  checks nothing.
- Asset identity as a lookup every role must make. Only the Investigator, the
  Commander, CTI and the Manager have the Surveyor as a peer.
  `Proposal.blast_radius` is written to the openspace and never reaches the
  policy. An unanswered blast radius becomes an objection in
  `shoc/cases/review.py`, which escalates the action to L2 instead of stopping
  it, and only for actions whose policy asks for a review.
- Forensic collection as an action. `stage: collect` sorts first, but no
  collection action type exists. The fallback and window an L2 proposal names
  are not enforced: every action waits four hours and is then rejected or
  abandoned.
- The exception report (D52). Only the weekly report is scheduled.
- CTI's indicator store. The schema's expiry, do-not-match and derivation fields
  are ignored, and every indicator gets 90 days.
- Configuration snapshots (D49).
- The tools in `NOT_BUILT` in `shoc/agents/roles.py`.

## Motivation

The pool was designed as a SOC shift: roles take turns, a shift lead decides the
meeting is over, a dispatcher reads the ticket out loud, and five roles are
deterministic because their work looked like arithmetic. Every one of those
choices assumed something this product does not have.

**There is no shift.** The company has one technical person and they do not open
the tool. RFC 0011 put deadlines on the things that waited for them, but the
roles themselves still behave as though somebody is reading: the Sentinel
restates findings for a reader, the Reporter writes a per-shift handover to an
incoming analyst who does not exist, and the Orchestrator's job is to decide a
meeting has converged.

**There are no rounds worth defending.** RFC 0011 gave agents tools, so an
Investigator can widen a window and check an address. What it kept was the round
structure around that: to learn what an address is to the company, the
Investigator posts a `request`, the scheduler grants somebody a turn, the Operator
may or may not be one of them, and two requests per round compete with one
interruption. The Investigator can query eight capabilities directly and must go
through a scheduler to ask a colleague a question. The scheduler is the slow path
and the expensive one.

**Five roles were deterministic because their output looked mechanical.** D29 and
D32 split the pool by whether the work was "lookups and arithmetic". That test
confused the *answer* with the *job*. Rule health is arithmetic; deciding which
detection to write next is not. Source freshness is a query; deciding that a dark
source means the SOC should stop claiming coverage is not. Twelve hunt packs a day
is a budget; a hypothesis about what an adversary is doing here is the entire
discipline, and the module that ran the packs called the model only at the end, to
triage rows. A role whose judgement has been factored out is not a role.

**The verdict taxonomy has an exit nobody walks through.** `needs_human` is an
honest answer in a staffed SOC. Here it is a case that sits in `analysis` until a
deadline fires, and RFC 0011's own remedy for it is to tell the case that nobody
is coming and send the crew back. A disposition whose handling is "pretend it was
not chosen" should not be offered.

**Two roles were arguing the same evidence from opposite ends of the room.** The
Operator knew what an address was to the company, and that knowledge was reachable
only if somebody scheduled it or its terms matched a message. The words it
declared (`shared`, `production`, `deploy`) are in almost every message anybody
writes, so it won interruption slots on cases it had nothing to say about, and the
Investigator inferred what an address was whenever the Operator was not called.
Knowing that a range is the office is inventory. Inventory is the Surveyor's.

## Guide-level explanation

Thirteen members become eleven, and each one now finishes something.

A finding lands. **Sentinel** decides what case it belongs to: it groups by the
entities the findings share, by the graph paths between them, and by the campaign
they match, and it either opens a case, attaches the finding to an open one, or
defers it. It cannot drop anything. It has no seat in the discussion, and with no
model configured the pipeline stops rather than guessing at case shapes.

The case goes to the **Investigator**, which owns it end to end. It builds a
timeline starting in the source that alerted (a CloudTrail finding starts in
CloudTrail) and extends outward by resolved identity and by indicator. Then it
works hypotheses against that timeline. When it needs to know what an address is
to the company it asks the **Surveyor**; when it needs to know what a command line
is, it asks **CTI**. Both are calls inside its own loop, not requests posted to a
room. It commits to one of four dispositions, always sets the severity, and cites
per claim, including the queries that came back empty, because that is why an
explanation was ruled out.

The **Challenger** then argues the other side, whichever side that is: it attacks a
malicious verdict with the ordinary explanation and a benign verdict with the
attack. It is grounded in what the company has written down, in this
environment's own baseline, and in a checklist of the explanations everybody
forgets. Its objections do not overrule the Investigator, and they cannot be
skipped: a surviving explanation has to be ruled out with cited evidence before
the case closes. When it wins on "that is normal here", it drafts the narrow,
expiring suppression itself.

If anything needs doing, the **IR Commander** proposes it, and then stays on the
case until the response is finished. Every proposal carries the blast radius,
cited from the Surveyor; an uncertain blast radius means the action does not run.
Forensic collection is a typed L1 action ordered before containment, so the
evidence survives the thing that would destroy it. Every L2 proposal names a
fallback and the window after which the fallback runs, and the critical band pages
instead of waiting.

The **Hunter** plans its own day: intel CTI handed over, the findings Sentinel
deferred, the coverage debt nobody would choose, and the techniques recent cases
showed that CTI says are worth chasing. It writes its own queries, costs them
before running them, triages what comes back, and sends survivors through Sentinel
like any other finding.

**CTI** reads what applies to this company's stack, sector and size, discards what
does not, and owns the indicator store: typing, expiry, deduplication and a
permanent do-not-match list for the indicators that would burn us. It answers
questions for the Investigator, the Hunter and the Detection Engineer, and every
claim it makes says where it came from. It fetches nothing until the operator says
it may.

The **Surveyor** keeps its deterministic queries and gains an agent above them,
plus the question the Operator used to answer: what is this address, host or
identity to us. The **Detection Engineer** writes rules and merges them, behind
fixtures, a backtest against real history and a filled ADS form, and reverts its
own work when it turns noisy. **Ops** acts on broken ingest and states plainly what
the SOC currently cannot see. The **Integrator** gets sources connected and mapped
and does not call one onboarded until an event from it has become a finding. The
**Reporter** stops writing a handover and writes an exception report only when
something genuinely needs a person.

## Reference-level explanation

### Structural change 1: roles are callable

`Request` and the `request` / `answer` message kinds are removed from the
scheduling path. A role's tool list may now contain other roles, and calling one
runs that role against the current case with the question as input. The reply is
returned to the caller and written to `shoc.openspace_messages` with the caller
recorded, so the transcript is unchanged as a record: the same messages appear,
ordered by when they were produced rather than by whose turn it was.

This touches principle 2 (agents use the same capabilities as people) rather than
weakening it: a role invoked this way is invoked through the registry, with its
own principal and scopes, and the call is audited like any other.

Peer budgets move from "two requests and one interruption per round" to a per-case
ceiling on role invocations, enforced where the tool budget is already enforced.
`roles.interested` and the `domain` term lists are deleted; nothing routes by
keyword any more, because nothing needs to guess who might want to speak.

### Structural change 2: `needs_human` is not a verdict

`InvestigatorOutput.verdict` loses the value. The case disposition column keeps
it, because a case can still reach it without anybody choosing it: no model
configured, an LLM failure, a citation set that did not survive verification
(D25). What changes is that no role may select it as an answer. A case the
evidence does not settle is `suspicious` with low confidence, which earns a
reversible containment rather than a queue position.

### Deletions

**Orchestrator.** Convergence was a property of rounds. The case is closed by
whoever held it last: the Investigator when no response was needed, the IR
Commander when one was. Its routing job (which disposition sends work where)
stays in `shoc/cases/routing.py`, where it already lives.

**Operator.** Its two halves go to the roles that own the evidence each needs.
Asset identity becomes a Surveyor lookup every role must call for an external
address, host or identity. Action review becomes a required, cited field on every
Commander proposal, and an uncertain answer stops the action, exactly as the
Operator's refusal did.

### The split: one CTI, two jobs

CTI keeps one name. The reading half runs on a schedule with no case attached and
owns the indicator store; the answering half is a callable service. A reader does
not need to know which half answered, and the split is internal: two prompts and
two output schemas under one role name, as today.

### The new role: Integrator

Source onboarding was Ops's, and it is too large to sit inside a role whose job is
measuring. The Integrator finishes per source: discover what should be connected
by reading what already is, produce least-privilege scopes with the click path for
that product, then verify, sample and map without further help. It does not call a
source onboarded until an event from it has become a finding, and it keeps
ownership of that source's mapping while dormant. Its order is identity,
productivity, EDR, cloud, and then the sources that hold the company's value (the
code host, the CRM, the payment provider), raised above where enterprise lists put
them, because that is what is being taken.

### Every role is model-backed

D29 and D32 are superseded. Where a role's answer must be identical every time it
is asked, the answer stays a query and the model sits above it: the Surveyor's six
questions are unchanged, and the agent decides what to look at and what the
inventory means. The Reporter's figures still come from queries, and a report is
complete and sendable with no model at all; prose is the optional part.

### Deleted questions and outcomes

The Surveyor's "what is exploitable now" is removed. It joined the exposed set
against KEV, and shoc ships no KEV feed; vulnerability relevance is answered by
CTI, per case, from the reports it has actually read.

The Hunter's `clear` outcome is removed. A hunt that found nothing proves nothing
unless the data could have shown it, and that claim belongs to source quality. A
fifth outcome is added: a hunt worth running twice is a missing rule, and its query
is the starting point for the Detection Engineer.

### Configuration snapshots

Inventory stops being a side effect of activity. A connector may now declare a
snapshot kind alongside log ingest (a describe pass over cloud resources, the
IdP's users and network zones, the VCS org state, the EDR device list), and the
Surveyor answers from both. The caveat that an idle machine is invisible goes
away, along with the honest limit that carried it.

### New decisions

| # | Decision | Why | Consequence |
| --- | --- | --- | --- |
| D41 | A role may call another role while it is thinking | Asking a colleague a question went through a scheduler while querying eight capabilities did not | `Request` and the `request`/`answer` kinds leave the scheduling path; `roles.interested` and `domain` are deleted; peer budget becomes a per-case invocation ceiling |
| D42 | No role may choose `needs_human` | Its own handling is to tell the case nobody is coming and send the crew back | `InvestigatorOutput.verdict` loses the value; the column keeps it for cases that reach it without being chosen |
| D43 | Sentinel shapes cases and has no seat | Restating findings for a reader who is not there is formatting; deciding what a case is is work | Runs at intake and again on new findings; groups by entity, graph path and campaign; with no model the pipeline stops rather than guessing |
| D44 | A finding is never dropped | Discarding is how a real attack dies quietly in tier one | Sentinel defers, merges or opens; deferred findings are the Hunter's agenda, and a hunt outcome closes them |
| D45 | The Operator is deleted | Knowing that a range is the office is inventory, and reviewing an action needs the evidence the proposer already holds | Asset identity is a Surveyor lookup every role must call; blast radius is a cited field on every proposal, and uncertainty stops the action |
| D46 | The Challenger argues against the verdict, whichever it is | A wrong `benign_expected` is the failure nobody ever notices | One call per case, direction set by the verdict; surviving explanations must be ruled out with cited evidence; it drafts its own suppression when it wins |
| D47 | Every crew role uses a model (supersedes D29, D32) | The old test confused a mechanical answer with a mechanical job | Deterministic queries stay deterministic and the agent sits above them; the Reporter's numbers and the Surveyor's six questions are unchanged |
| D48 | The Detection Engineer merges its own work (supersedes D27) | A detection nobody merges is not a detection, and the queue is where they died | Gate: fixtures pass, a backtest against real history, a filled ADS form. It reverts its own rule on noise. The third suppression for one pattern narrows the rule instead |
| D49 | Configuration snapshots are a connector kind | Events show what happened, so an account that exists and never acts was invisible | Connectors may declare a snapshot pass; the Surveyor answers from events and snapshots, and its event-only caveat is removed |
| D50 | Source onboarding is its own role | It is the hardest thing a company with no security team does, and it was a bullet inside Ops | The Integrator finishes per source, ending at "an event from this source became a finding", and owns that source's mapping |
| D51 | The holder closes the case, against a deadline | Nothing closed cases once the Orchestrator was gone | The Investigator closes when no response was needed, the Commander when one was; every case carries a severity-derived deadline, and a second expiry pages |
| D52 | The handover becomes an exception report | There is no incoming shift, and a report nobody needs trains the operator to ignore the ones they do | Sent only when a decision genuinely requires a person; actions taken, coverage lost and expiries go in the weekly |

## Drawbacks

**A self-merging Detection Engineer can degrade the SOC on its own.** The gate is
three tests and a form, and the revert watches noise only. A rule that is wrong
in a way that produces few findings survives.

**Direct calls remove the ceiling rounds provided.** A round budget bounded a case
by construction. A per-case invocation ceiling does the same job, but it is now
the only thing standing between a confused Investigator and a large bill, which is
why Ops owns the budget and treats an expensive case as a signal in itself.

**Deleting the Operator removes a second opinion.** The Commander now proposes and
states the blast radius. The mitigation is the citation requirement, not another
agent, and a role checking its own work is weaker than a role checking someone
else's.

**Every role using a model raises the floor cost of running shoc** and makes more
of the product depend on `SHOC_LLM_PROVIDER`. Ingest, detection, the store and the
reports still work without one; triage no longer does, and that is now explicit
rather than a surprise.

## Alternatives

**Do nothing.** The crew works and RFC 0011 fixed its worst dead ends. What
remains is a pool shaped like a shift roster, which is why the Sentinel narrates,
the Orchestrator adjudicates and the Reporter hands over.

**Keep rounds and fix routing.** Better term lists and more interruption slots
would have let CTI and the Operator speak more often. It leaves the Investigator
unable to ask a direct question, and it keeps a scheduler on the critical path of
every question a role has for another.

**Keep the deterministic five and add a model only where a gap was proven.** The
narrower change, and the one D29 already tried. The gaps are not individually
dramatic; the pattern is that each of those roles had its judgement removed and
kept its name.

**Split the Investigator.** Considered and rejected: separating evidence from
judgement, or scoping from verdict, leaves nobody accountable for the answer, and
the parts spend more arguing than one role spends reasoning.

## Dependency and scope impact

- **New dependencies**: none.
- **New required services**: none.
- **Public contract changes**: `InvestigatorOutput.verdict` loses `needs_human`;
  `Request` and the `request`/`answer` openspace kinds leave the scheduling path;
  the `Operator` and `Orchestrator` role names disappear; `Integrator` appears;
  the Surveyor loses its exploitability question; the Hunter loses the `clear`
  outcome and gains a detection-proposal outcome; connectors gain an optional
  snapshot kind. `contract/v1.json` is updated in the same commit.

## Security considerations

**A self-merging detection agent is a write path into `content/`.** D27 existed
because a model that can edit detections can disable them. The replacement is not
trust: it is that the agent may add and narrow, its merges are recorded as its
own, and a merge that turns noisy is reverted automatically. Deleting a rule a
human wrote is not in scope for this RFC and stays a human action.

**Role invocation is a new call graph.** A role calling a role must not become a
way to borrow scopes. Each invocation runs with the invoked role's own principal
and capability list, not the caller's, and the invocation is audited. A cycle is
bounded by the same per-case ceiling as any other call.

**Forensic collection reads more than the crew reads today.** It is L1 because
reading breaks nothing, and it is scoped per action like any other action, which
means it appears in the catalogue, in the policy and in the audit log rather than
as an implicit capability of the Commander.

**Nothing here changes how untrusted log content is handled.** Report text, tool
results, live lookup answers and sampled events reach a model only inside
`safety.quote()`. CTI's outbound fetching stays off until the operator enables it,
and `osint.is_internal` still applies to every lookup.

## Unresolved questions

- The Scribe, the rehearsal personas, the playbook runner and the human member
  were not part of this pass and are unchanged. The Scribe in particular is still
  proposed-only, and its record-keeping overlaps the case record the Investigator
  now owns.
- What the per-case invocation ceiling should be, and whether it varies by
  severity.
- Whether the Detection Engineer's revert should also cover silent rules, given
  that reverting one removes the coverage it was written for.
- What the Integrator does when the operator never supplies credentials.

## Adoption and migration

Forward-only, in the order the roles depend on each other.

1. `shoc/agents/roles.py` first: the registry of prompts and schemas, including
   the deleted roles and the removed verdict. Nothing calls the new roles yet.
2. The loop: role invocation replacing `Request`, and case closing moving to the
   holder.
3. Sentinel ahead of the case engine, with the pipeline stopping when no model is
   configured.
4. The five newly model-backed roles, one commit each, each keeping its existing
   deterministic queries.
5. The Integrator, and the snapshot connector kind it needs.

Existing installs keep their open cases: a case in `needs_human` stays there and
is worked by `shoc/cases/unattended.py` as it is today. No migration rewrites a
historical disposition, because a verdict recorded under the old taxonomy was
still true when it was made.
