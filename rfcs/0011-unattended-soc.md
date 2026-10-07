---
rfc: 0011
title: Investigate by looking things up, and finish without a human
status: draft
authors: ["@Rettila"]
created: 2026-09-26
requirements: ["AGT-1", "AGT-2", "AGT-3", "RSP-2", "RSP-3", "RSP-6", "OPS-1"]
supersedes: null
---

# RFC 0011: Investigate by looking things up, and finish without a human

## Summary

Agents get to query the store while they are thinking, instead of being handed
one fixed dossier and asked for a verdict. CTI is asked about every case whose
evidence contains something researchable, rather than waiting to be caught by a
keyword. And everything whose resting state was "a human will decide this" gets a
deadline, because the human this product is built for does not open it most days.

## Motivation

Three faults, all found in one real case. `CASE-9f7294571950d508fb74` opened on
an Okta account that signed in from a new country and then modified a SAML
identity provider. The crew read it, the IR Commander proposed
`okta.revoke_sessions` at L1 (reversible, pre-approved, exactly the action the
policy exists to allow), and nothing happened. The proposal was a line of JSON in
`shoc.openspace_messages`. No `shoc.actions` row was ever written, so nothing
could have run it.

Underneath that were two more:

- **The Commander named an action that does not exist.** `okta.revoke_sessions`
  is called `idp.revoke_sessions`; two of its other proposals named nothing at
  all. The Commander was writing action names from memory.
- **Autonomy was decided against a confidence the case did not have yet.** The
  verdict is recorded after the Commander speaks, so `Policy.decide` saw
  `confidence = 0.0` and escalated every L1 proposal to "a human approves". Even
  with the wiring in place, no action would ever have run automatically.

Separately, the investigation itself cannot pivot. `LLMClient.complete` takes a
string and returns a string, and `build_dossier` assembles everything an agent
will ever see before the discussion starts: at most forty events, one graph hop,
what the tenant has told us. An analyst who cannot widen the window, check
whether the address appeared last month, or ask what else the account touched is
not investigating; they are commenting on a sample. Meanwhile `events.query`,
`intel.lookup`, `graph.neighbours`, `posture.exposure` and `memory.search` all
exist as typed, scoped capabilities that no agent can call.

And CTI was silent on every case. It has no scheduled turn anywhere in
`run_case`; it can only interrupt, interruptions are capped at one per round, and
`roles.interested` returned candidates in dictionary order with CTI declared
last. Challenger's terms include `benign` and `expected` and Operator's include
`shared` and `production`, words in nearly every message anybody writes, so the
one slot was taken before CTI was considered. A case about a file hash, a command
line or an ATT&CK technique contains none of CTI's words at all.

The thing that ties these together is who runs shoc. The company has between 20
and 500 people and its only technical person does not look at the tool except
when something is critical. An action parked at L2, a case routed to
`needs_human`, a button in the console: each of these is a no-op in that setting.

## Guide-level explanation

An investigation now reads like one. The Investigator is given the case and a set
of read capabilities, and the openspace records what it checked:

```
round 1 · CTI · observation: 203.0.113.55 has been on abuse.ch since June as
  Feodo C2. Worth checking: other keys used from the same address.
  [Looked up: intel_lookup, intel_reports]
round 1 · Investigator · hypothesis: The key enumerated the account from
  203.0.113.55 at 02:14 and read 64 objects. No other principal has used that
  address in 30 days, and the account has never signed in outside Germany.
  Severity moved from medium to critical: an access key in use from known C2.
  [Looked up: events_query x3, graph_neighbours, memory_search]
round 1 · IR Commander · proposal: {"action": "aws.disable_access_key",
  "target": "AKIA…", "autonomy": "L1", "state": "approved"}
```

That last line is an action row, not a sentence. `aws.disable_access_key` is L1
in `content/policy.yaml`, the case is critical and confident, so it is queued and
runs. `idp.suspend_user` is L2, so it waits, but only for four hours:

```
$ shoc case get CASE-…
severity: critical      (raised by Investigator: an access key in use from known C2)
actions:
  aws.disable_access_key  AKIA…             done       ran automatically
  idp.suspend_user        bob@example.com   proposed   decide by 06:14
```

Past `decide_by`, `shoc/cases/unattended.py` resolves it. On a `high` or
`critical` case it pages. On anything lower it rejects the action and writes into
the case what was not done and why, because that is the honest record: an action
left `proposed` reads months later as something that was about to happen.

A case sitting on `needs_human` is told, in the openspace, that nobody is coming,
and the crew is sent back to it to reach a disposition or propose something
reversible it can do by itself. The shift report gains a section for what
happened while the operator was away, and one line that would have caught the CTI
bug on its own: which agents never spoke.

## Reference-level explanation

**Tool use (`shoc/agents/llm.py`, `shoc/agents/tools.py`).** `Turn` grows
`calls` and `call_id`, `Completion` grows `calls` and `lookups`, and `complete`
takes an optional `tools`. Both clients translate to their own protocol
(Anthropic carries tool results in user messages and consecutive results must
share one, OpenAI uses `role: "tool"`), and `complete_typed` loops up to
`MAX_TOOL_STEPS`, then tells the agent its lookups are spent and asks for the
answer. Nothing is cut off mid-thought.

`shoc/agents/tools.py` builds tool definitions from the registry and executes
them through `Capability.invoke`, so every existing check applies unchanged:
principal, scope, autonomy, typed input, audit. A role declares its capabilities
in `Role.tools`, and the `Caller` it is given holds exactly those capabilities'
scopes and nothing else. Every offered capability is a read. Results are wrapped
by `safety.quote` and capped, because a query answer is log content written by
whoever is being investigated.

This touches principle 5. Bounded autonomy said agents read and only the playbook
runner acts; that is unchanged. What changes is that reading is no longer limited
to what somebody assembled in advance.

**Observables (`shoc/agents/observables.py`).** The case's events and findings
are read for hashes, external addresses, domains, URLs, CVEs, techniques and
command-line shapes, each typed precisely: a URL is not a domain and a domain is
not an address. The three documentation ranges are readmitted by name, since
Python counts them as private and every fixture in the repo uses them. Stored
indicators and digested reports are matched against what was found: exactly on
the technique array, and by text search of a report's digest for a command-line
shape, which is how a human would find it. CTI is asked when something
researchable is present or a report matches; a bare technique is not enough,
because almost every finding carries one.

**Interruptions (`shoc/agents/roles.py`).** `cares_about` returns the longest
matching term rather than the first, `interested` ranks by that length, and the
terms that were ordinary English are gone. A longer term is a more specific claim
on a message.

**Budget (`shoc/agents/openspace.py`).** `Budget.for_case` takes severity as a
floor and raises it for what the case contains. `_should_continue` no longer
refuses a second round below `high`, which is why most cases (mediums) never
heard a benign explanation.

**Severity (`shoc/cases/engine.py`).** `set_severity` lets the Investigator
correct what a rule guessed from a pattern before any of the case existed. It
requires a reason, publishes `case.severity_changed`, and is said out loud in the
openspace. It is not a way to grant an action: the policy still wants confidence,
citations, reversibility and, for a block, research and a peer review.

**Migration 017.** `actions.decide_by`, `actions.chased_at`, `cases.worked_at`,
and indexes for undecided and unrun actions. `worked_at` is backfilled from the
last openspace message so the first sweep does not treat every open case as new.

**The sweep.** `worker.NEEDS_ATTENTION` replaces `tokens_used = 0`, which is true
exactly once. A case comes back when the crew has never worked it, when a
finding, a completed action or an injected fact is newer than `worked_at`, or
when `unattended` has told it nobody is coming. `run_case` continues from the
last round rather than restarting, and Sentinel states what changed.

## Drawbacks

Tool use multiplies model calls: an agent that pivots six times costs seven
completions instead of one. The step cap and the token budget bound it, but a
case now costs more than it did, and the cheapest cases cost more than they need
to. `Budget.for_case` is the lever, and it is a guess.

Letting the Investigator move severity gives a model a say in whether a human is
woken. A log line crafted to look alarming can now buy a page. That is a noisy
failure rather than a dangerous one (paging is reversible and the action gates
are unchanged), but it is new.

Rejecting an undecided action after four hours will occasionally throw away
something the operator would have approved on Monday. The alternative is an
action that was never taken and never recorded as not taken, which is worse.

## Alternatives

**Do nothing.** The measured outcome is the case above: an L1 containment action
that was allowed, proposed and never performed, on a product sold as a 24/7 SOC.

**Better prompts.** The Commander's invented action name is a prompt problem and
was fixed by showing it the catalogue. The other five faults are not: no prompt
makes an agent able to query a table it has no tool for, or wins CTI an
interruption slot that ranking gives to someone else.

**A wider dossier instead of tool use.** Cheaper and bounded, and it was the
current design. It fails for the same reason a bigger sample is not an
investigation: what to look at next depends on what the last answer was.

**Raise everything to L1.** Would make actions happen, at the cost of the
autonomy policy meaning anything. Deadlines keep the policy and remove the
waiting.

**Page for everything unresolved.** Spends the operator's attention, which is the
scarcest thing in the system, and trains them to ignore the pager.

## Dependency and scope impact

- New dependencies: none. Tool use is `httpx` and the registry.
- New required services: none.
- Public contract changes: `case.investigate` gains `actions`;
  `InvestigatorOutput` gains `severity` and `severity_reason`; a new
  `CtiOpinionOutput`; a new `case.severity_changed` stream event; job kinds
  `action.run` and `unattended`; migration 017.

## Security considerations

Agents reach capabilities through `Capability.invoke`, so nothing is bypassed and
an agent principal is still refused every L2 capability (D8). The scopes a role
holds are derived from the capabilities it is offered, so a role with three tools
cannot reach a fourth. Every capability offered is a read; an action is still
proposed to the policy and never called by an agent.

The new attack surface is a tool result. It is log content, it is wrapped by
`safety.quote` and truncated, and the data rules in the system prompt already
cover it, but an agent that can query now chooses what enters its own context,
so a crafted log line can steer which query is run next. What it cannot do is
change the answer's shape: citations are still verified against the store and an
uncited verdict is still downgraded.

`unattended` proposes a page and rejects an action. It approves nothing, runs
nothing, and raises nothing's autonomy. `run_approved_actions` executes actions
the policy or a human already approved, in the worker, the same way the playbook
runner does; `action.run` as a capability stays closed to agent principals.

## Unresolved questions

Four hours for `DECIDE_WITHIN_HOURS` and six for `NUDGE_AFTER_HOURS` are
judgements, not measurements, and they should be per-tenant settings in
`content/policy.yaml` once there is one install to measure. `MAX_TOOL_STEPS` at
six is the same kind of guess. Whether an agent should be able to raise severity,
as opposed to only lowering it, is worth revisiting after the evals have run
against a case with injected content in it.

## Adoption and migration

Forward-only, no flag. `shoc migrate` adds the three columns and backfills
`worked_at`. Tool use is on for any role with `tools` declared and a model that
supports it; a client that ignores `tools` degrades to the single round trip it
always was, and a role with no connection (a unit test) answers from the prompt.
Existing installs gain the `unattended` schedule at first worker boot, which will
resolve the backlog of actions and cases that have been waiting, noisily, once.
