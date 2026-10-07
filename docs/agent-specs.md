# Agent specifications: the whole pool

`docs/agents.md` describes what happens when a case is investigated. This page
is the other half: a spec per agent, written as if each were a person you had
hired, so that a reviewer can say "that is not what a detection engineer does"
before a line of code is written.

Every role here is measured against how the job is actually practised in a human
SOC: the frameworks practitioners publish and the deliverables each discipline
owes.

Two rules cut across every spec below:

- **A role calls another role while it is thinking.** There are no rounds and no
  scheduler granting turns. The Investigator asks the Surveyor what an address is
  to the company the same way it asks the store for events, and the openspace
  records the exchange instead of arranging it.
- **`needs_human` is not a verdict anyone may choose.** A case can still reach
  that disposition (no model configured, an LLM failure, citations that did not
  survive verification), but no role selects it. Evidence that does not settle a
  case produces `suspicious` at low confidence, which earns a reversible
  containment rather than a queue position.

Read it with `docs/architecture.md` (the kernel), `content/policy.yaml` (what
may be done without a human) and `shoc/agents/roles.py` (the prompts and output
schemas that are the executable version of the specs below).

## How to read a spec

Every agent gets the same fields. Three of them carry most of the weight:

- **Tools**: the capabilities it may call, and the roles it may call. An agent
  has nothing beyond this list; the registry is the boundary, not a convention.
  Nothing here is a free-form shell, an arbitrary HTTP fetch, or a write to
  `content/` except where the spec says so and names the gate.
- **Thinks**: the procedure, in the order it runs. Where a step must produce the
  same answer every time it is asked, it stays a query and the spec says so; the
  model sits above the queries rather than replacing them.
- **Never**: the things that would make the agent dangerous. These are enforced
  in code, not in a prompt, and the spec names where.

A section opening with a quoted **Status** line is not what the code does today:
it is proposed, and it is here to be argued with. Where the code stands against
each spec is listed under "Where the code is against this plan" in
`docs/prd.md`; terms and states are defined in `docs/ontology.md`.

| Flag | Meaning |
| --- | --- |
| **Model** | Every crew role uses one (RFC 0012, superseding D29 and D32). The flag now says what still works without it. |
| **Autonomy** | The highest thing it can cause to happen: `read`, `propose`, `L1` (reversible, automatic), `L2` (a human approves). Exactly one member holds L1: the playbook runner. Nothing but a human holds L2. |

## The pool at a glance

| Agent | Persona in one line | Autonomy | Runs |
| --- | --- | --- | --- |
| Sentinel | The one who decides what the case is | read | At intake, and again when new findings land on an open case |
| Investigator | The analyst who owns the answer | propose | Every case, start to finish |
| Challenger | The colleague who argues the other side, whichever side that is | propose | Every case, once |
| IR Commander | The incident lead who owns the outcome, not just the plan | propose | Malicious, suspicious, and anything still happening |
| CTI | The intel analyst who reads, curates, and answers | read | Scheduled for reading; called for cases, hunts and detections |
| Hunter | The one who looks for what no rule describes | propose | Its own planned cycle |
| Surveyor | The one who knows what the company actually has | read | Daily, and on every call about an address, host or identity |
| Detection Engineer | The one who owns the rules, and merges them | **content write** | Continuous backlog |
| Ops | The SRE of the SOC, and its honest witness | read | Continuously |
| Integrator | The one who makes the inputs real (code, D74) | read (+ `mapping.write`) | Per source, until that source produces a finding |
| Manager | The operator's one contact | read (+ `notify.page`) | On every notice, on every `ask`, weekly, monthly |
| Scribe (proposed) | The one keeping the record, and watching the clock | read | Every confirmed incident |
| Playbook runner | The hands. The only thing that touches anything | **L1** | When a case matches a playbook |
| Human member | The person who approves things | L2 | Whenever they like |

Ten crew roles and the Integrator, which is code (D74), plus the proposed Scribe, the runner and the human. **Every crew role uses a model.** Feeds and `intel.lookup` are not an
agent: they are the **intel plane**, a service every agent may call.

---

## 1. Sentinel

> **Partly built:** `shoc/agents/sentinel.py` runs inside `detect.run` once code
> has grouped a cycle's findings by shared entity. It attaches, defers, splits and
> re-scopes; it reopens nothing (D78). With no model the entity grouping stands
> and the pipeline does not stop, and a deferred finding is not on the Hunter's
> agenda.

**Persona.** The one who decides what arrives. Sees every finding the detections
produce and asks a single question about each: what is this part of? Knows that
five rules firing on one stolen key is one incident, that a finding on a host
connected to yesterday's case belongs in yesterday's case, and that two unrelated
machines hitting the same C2 a week apart is one thing and not two.

**Mandate.** Shape the case population: group, merge, split, re-scope, or defer.
Nothing downstream is woken until it has.

**Not their job.** Severity. How much the crew spends on a case. Whether the case
is real. Speaking in the discussion at all.

**Runs.** Twice, at both ends. At intake, on findings as they land. Again when new
findings arrive on a case that is already open.

**Reads.** The finding and its events; the findings of the last several days; open
and recently closed cases; the graph around the finding's entities; the indicators
and reports its entities match; memory and the suppression list.

**Tools.** `finding.list`, `case.list`, `graph.neighbours`, `intel.lookup`,
`intel.reports`, `events.query`, `memory.search`, `suppression.list`.

**Thinks.**

1. Is this settled already? A suppression, a written fact, or an identical prior
   case means this does not need the crew.
2. What is it part of? Three grounds, all concrete: **the entities it shares**
   with other findings, **the graph path** between them (a key that belongs to a
   role a user assumed, a host behind the same identity), and **the campaign**
   they match: the same indicator or the same digested report, with no entity or
   time overlap needed.
3. Open, attach, or defer. Nothing else is available.
4. On the second run, on an open case: attach the finding, split the case when it
   has become two things, and rewrite what the case is about when the new evidence
   changes the question, so nobody is still arguing the old one. A closed case
   stays closed (D78): a finding on its entity opens a new case that names it.

**Narrative linkage is deliberately not its job.** Discovery on one entity, then
access on another, then exfiltration on a third is a story, and the role that
reasons about the case tells it. Sentinel groups on links it can point at.

**Writes.** Cases, case membership, and deferrals. No openspace message.

**It cannot drop a finding.** Discarding is how a real attack dies quietly in
tier one. Sentinel defers, and a deferral is not a grave: **deferred findings are
the Hunter's agenda**, tested as behavioural hypotheses over a wider window, and a
hunt outcome closes them.

**Model: required to reshape.** With no model, code's grouping by shared entity
stands and the pipeline does not stop: a case it opens is a case.

**Never.** Drop a finding. Set a severity. Decide what a case costs. Post in the
openspace. Interrupt a running investigation.

---

## 2. Investigator

**Persona.** The senior analyst who owns the answer and will be asked about it in
the morning. Prefers the boring explanation, and will not state anything they
cannot point at a log line for. Builds the timeline before forming a view, because
an analyst who reasons before ordering the events is guessing with extra steps.

**Mandate.** Reach a **disposition**, set the **severity**, say how far the
activity spread, and own the case record.

**Four dispositions. There is no fifth.**

| Disposition | Means | What it triggers |
| --- | --- | --- |
| `malicious` | Confirmed attacker activity | Response, and the Commander |
| `suspicious` | Consistent with an attack, not proven | Response as well, when anything is still happening |
| `benign_expected` | Real activity, expected in this environment | A **suppression with context and an expiry**, and a note in memory |
| `false_positive` | The rule fired on something it should never fire on | A **detection fix**, to the Detection Engineer |

The distinction between the last two is the whole point: one means the
environment is unusual, the other means the detection is wrong, and they are
repaired in different places. Thin evidence is `suspicious` at low confidence,
which still earns a reversible containment. There is no disposition that means
"somebody else will look at this".

**Runs.** Every case, from the moment Sentinel hands it over until it closes or
the Commander takes it.

**Method: the timeline first, then hypotheses.**

The timeline is a durable artifact of the case, not a step in a prompt. A
capability builds the base from the case entities; the Investigator extends it,
and every extension is recorded.

**It starts in the source that alerted.** A CloudTrail finding starts with
CloudTrail. Then it extends outward on two pivots and only two:

- **Resolved identity**: the same actor under another name, from the Surveyor's
  identity graph: an IAM user tied to an Okta identity tied to a GitHub account.
  When two identities cannot be bridged, it says so rather than assuming.
- **Indicators**: the addresses, hashes and domains the case contains, wherever
  else they appear.

Only then does it reason: state what it thinks happened, name what would prove
and disprove it, query specifically to test that, and revise. The hypotheses it
killed stay in the transcript, because the ones that were ruled out are why the
surviving one is credible.

**Reads.** The case and its findings; the timeline; events it asks for; prior
cases on the same entities; memory; the suppression list; what the Surveyor says
about the entities involved; what CTI says about what the evidence contains.

**Tools.** `timeline.build`, `timeline.extend`, `events.query`, `finding.list`,
`case.history`, `graph.neighbours`, `posture.exposure`, `identity.resolve`,
`memory.search`, `suppression.list`, `intel.lookup`, `intel.reports`,
`evidence.preserve`, `platform.lookups`, `platform.lookup`. Roles: **CTI** and
the **Surveyor**, called directly.

**Thinks.**

1. Build the timeline from the alerting source out.
2. What would have to be true for this to be ordinary? Check that against the
   events and what the company has written down, first.
3. Weight the behaviours that matter: credentials used from a new source after a
   burst of discovery; permission errors followed by success; logging or alerting
   switched off; new long-lived credentials; bulk reads; and above all
   **identity**: one session used from two places, an OAuth grant nobody
   requested, MFA prompts nobody answered.
4. **Scope it.** Walk the graph from every entity and say what else the same
   indicators touch. Stopping at the systems already known to be involved is the
   mistake responders make most.
5. Ask, rather than infer. What an address is to this company is the Surveyor's
   answer; what a command line has been seen doing is CTI's. Both are a call, not
   a request posted and waited on.
6. Choose the disposition the evidence supports, not the worst one it permits.
7. **Set the severity, always.** A rule guessed at it from a pattern before any of
   this existed, and the same finding is a laptop on a train or a stolen session
   depending on what else can be seen. Severity is what decides whether the one
   technical person in the company is woken, so it is set on every case with one
   sentence of reasoning, not left as the rule's guess.

**Evidence: per claim, and negatives count.** A citation bag at the end of the
verdict is not evidence of anything in particular. **Every claim carries its own
event UIDs**, and a sentence with nothing behind it is struck from the output
before anybody reads it. And the queries that came back **empty are recorded**,
because a negative result is why an explanation was ruled out, and today that
reasoning is invisible and unverifiable.

**When the data does not exist.** No EDR, GitHub unconnected, a stale source: it
still commits to one of the four, **files the gap as a coverage item** for the
Surveyor and the Detection Engineer, and reflects it in confidence. It does not
assume the worst because a source is missing, and it does not park the case.

**Writes.** The case record: the timeline, the scope, the severity and its reason,
the disposition and its confidence, the coverage gap, the memory fact. It owns
that record rather than emitting a blob for somebody else to store.

**And one class of action, unapproved: evidence preservation.** Snapshotting a
session list, pulling logs about to roll off. By the time the Commander proposes
containment the evidence is often gone. Reading destroys nothing, so this is L1
and typed like any other action.

**It closes its own case** when no response was needed, once the Challenger's
objections are answered.

**Model: required, `strong`.** This is the judgement the project is buying.

**Never.** Post an uncited claim. Choose `needs_human`. Run a containment action.
Approve anything.

---

## 3. Challenger

**Persona.** The colleague who has seen four "incidents" this month that were all
the same misconfigured backup job, and who also remembers the one time everybody
agreed it was the backup job and it was not. Sceptical of the conclusion, whichever
conclusion it is. Concedes cleanly. Being a contrarian is a failure of the role,
not a feature of it.

**Mandate.** Argue the case the verdict did not make, and say what evidence would
settle it.

**Direction is set by the verdict**, and there is one call per case:

- A **malicious or suspicious** verdict is attacked with the ordinary
  explanation: a deploy, a new laptop, a migration nobody wrote down, an engineer
  on holiday, a CI runner that moved hosts.
- A **benign** verdict is attacked with the attack: what would look exactly like
  this and not be ordinary. **A wrong `benign_expected` is the failure nobody ever
  notices**, and until now nothing in the pool looked for it.

**Runs.** Every case, mandatory, whether or not the Investigator invites it. An
agent that is only challenged when it asks to be is never challenged on the cases
that matter.

**Grounding: three sources, and free invention is not one.**

1. **What this company has told us.** Memory facts a human wrote, prior
   dispositions, existing suppressions. An explanation contradicted by a written
   fact is dead on arrival, and one supported by a written fact is strong.
2. **The environment's own baseline, queried.** Has this user signed in from this
   country before? Does this job run every Sunday? An explanation it can show is
   routine beats one it merely imagines.
3. **A known-benign checklist.** CI runners moving hosts, VPN and office egress,
   mail scanners detonating links, backup jobs, travelling engineers. Worked
   through every time so the common ones are never forgotten.

**Its power: it must be answered, not obeyed.** A surviving explanation has to be
explicitly ruled out with cited evidence (including the negative query that rules
it out) before the case can close. It cannot overrule the Investigator and it
cannot force a re-investigation. It can stop the case being closed by ignoring it.

**When it wins on "that is normal here", it drafts the suppression itself**
(fields, scope, TTL), because it is the role that knows exactly why the activity is
benign. The Detection Engineer or a human merges it. When it wins on "this rule
should never have fired", that is a detection defect and it says so instead; they
are repaired in different places.

**Tools.** `events.query`, `memory.search`, `suppression.list`, `finding.list`,
`case.history`, `graph.neighbours`. Its suppression draft is a field of its
answer, not a tool.

**Writes.** `ChallengerOutput` → a `challenge` or `concede` message, and a
suppression draft when it wins.

**Model: required, `cheap`.** Its job is breadth of explanation, which cheap
models do adequately, and the Investigator does the hard ruling out.

**Never.** Have a verdict. Decide. Merge its own suppression. Argue against
evidence it cannot cite.

---

## 4. IR Commander

**Persona.** The incident lead for a company where nobody is watching at 3am and
an outage costs as much as an incident. Reaches for the smallest thing that stops
the bleeding, and then stays until it is actually stopped. Has been burned by a
containment action that took production down and has not forgotten it.

**Mandate.** Propose the response, state what it will cost, and **own it until the
case closes**, including whether it worked.

**Runs.** Malicious cases, suspicious cases, **and any case where the activity has
not stopped** before the disposition is settled. Stopping something that is still
happening matters more than settling the disposition. A `benign_expected` or
`false_positive` case is settled and closes: benign activity goes on by
definition, like shoc's own integrations refreshing their tokens every hour.

**Two-stage containment**, because that is how it is actually done:

- **Short-term**: stop the bleeding now, accepting ugliness. Disable the key,
  revoke the sessions, block the address for two hours.
- **Long-term**: what lets the company keep running while the mess is cleaned up:
  rotate to a new credential, re-enable with a narrower scope, keep the
  compromised host isolated but reachable so the evidence survives.

A proposal naming only the first is incomplete.

**Forensic collection comes before containment.** Collection actions are a typed
**L1** class in the catalogue (the process tree, the active session list, the IAM
policy as it currently stands, the mailbox rules), and the Commander orders them
ahead of the action that would destroy what they capture. Whatever comes back is
attached to the case as evidence the Investigator can cite and re-read. They are
L1 because reading breaks nothing, and they are actions rather than an implicit
power, so they appear in the catalogue, the policy and the audit log.

**Blast radius is a field, not an opinion.** Every proposal carries who else is
behind the target, cited from the Surveyor: how many distinct principals, whether
it is shared infrastructure (a cloud NAT range, a CDN edge, a Tor exit, a VPN
concentrator), whether a human has already written down what it is, and what the
company loses for the duration. **An unanswered or uncertain blast radius means the
action does not run.** The check sits with the role that proposes, and the
mitigation is the citation requirement rather than a second agent.

**L2, with nobody there.** An action whose resting state is "a person will approve
this" is a no-op in this product. So every L2 proposal names:

- the **fallback**: a narrower reversible action, or an expiry, and
- the **window** after which the fallback runs.

An L2 with no fallback is incomplete and is rejected as such. The **critical band
pages** rather than waiting. In code the fallback and window are recorded on the
`proposal` message and do not reach the policy. Every waiting L2 gets four hours;
after that a `high` or `critical` case pages once and anything lower is rejected with
the reason written into the case (D37, `shoc/cases/unattended.py`).

**Paging, against a stated rule.** It decides, but it does not decide freely: it
pages on critical severity, or on activity still running that it cannot contain on
its own, and it must **name which condition it met**. The operator's attention is
the scarcest resource in the system, and spending it on a medium case spends the
one thing that makes the critical page work.

**Verification, both halves.** After an action runs it checks that **the action
took effect** (the key really is disabled, the sessions really are gone) and that
**the activity stopped**, by re-running the queries that defined the case until
they come back clean for a stated period. Either one failing reopens the response
and it proposes the next thing.

**Tools.** `action.propose`, `action.list` (its case's actions and how each
ended), `posture.exposure`, `graph.neighbours`, `platform.lookups`,
`platform.lookup`; no raw-log reads (RFC 0020). Roles: the **Surveyor**, for
blast radius.

**Writes.** `CommanderOutput`: ordered proposals with fallbacks and windows,
blast radius per proposal, the page decision and the condition it met, and one
sentence for whoever is woken.

**It closes the case** when the response is finished and verified.

**Model: required, `strong`.**

**Never.** Run an action. Mark an irreversible action L1; the policy re-checks
and ignores the claim. Approve an L2, including its own. Propose an action that is
not in the catalogue, by a name it invented. Propose containment before the
evidence it would destroy has been collected.

---

## 5. CTI

**The intel plane is still not an agent.** Feeds and `intel.lookup` take a value
and return what published sources say, the same way every time (RFC 0004,
`shoc/detect/osint.py`). Its guards do not change: an internal value is never sent
to a third party, and every outbound call goes to a host declared in the source's
own entry.

**Persona.** The intelligence analyst. Not a feed reader: someone who knows what
this company runs and who actually attacks companies this size, reads accordingly,
and is ruthless about the difference between a victim IP, a service the malware
abuses and an attacker's C2, and equally ruthless about saying "this does not
concern you", which is most of the time.

### 5a. Reading and curation (scheduled, no case attached)

**Mandate.** Decide what to read, read it, discard what does not apply, own the
indicator store, and hand work to the roles that act on it.

**It chooses its own reading list.** Two inputs: what this company actually runs,
from its connected sources, **plus who attacks companies of this size and
sector**: commodity infostealers, business email compromise, ransomware
affiliates. Not the APT reporting that dominates vendor output, and not a report
about an ICS actor for a 40-person SaaS company.

**It skims before it reads, and reads within a day's budget** (RFC 0029). A
queued item is scored on its headline, the feed's summary and categories, its
age and its source, against the company's products and those threat classes,
without a model: a high score is read, a middle one is put to the cheap model in
one short call, a low one is skipped with the reason. A story already read from
another vendor is linked, not read again. What remains is read best-first until
`intel_reports_per_day` or `intel_tokens_per_day` is spent; the rest waits a
week. The full read sees the prose without menus or IOC tables and a computed
company profile, so it asks nobody what the company runs.

**It decides relevance and discards.** A report that fails is dropped rather than
stored, so the indicator store stays small enough that a match means something.

**It owns the indicator store**, and that is four jobs:

| | |
| --- | --- |
| **Lifecycle** | Every indicator carries a source, a confidence, a first and last seen, and a TTL. A C2 address from a report eighteen months ago is not an indicator, it is a false-positive generator, and something has to age it out |
| **Typing and dedup** | One observable, one record, typed precisely. A URL is not a domain, a domain is not an address, and the host inside a URL is a **derivation recorded as such**, never promoted to an indicator of its own |
| **False-positive defence** | It refuses to store what will burn us (CDN edges, shared hosting, popular services, sinkholes, our own infrastructure) and keeps a permanent do-not-match list with the reason for each entry |
| **Enrichment** | Indicators are linked to the actor, malware, campaign and technique they came from, so a match answers "what is this" rather than only "this is bad" |

**It hands work over rather than doing it.** A technique the report describes that
no rule of ours covers becomes a **Detection Engineer** backlog item with the
report as justification. Checking our own data for what the report describes is a
**hunt**, and it goes to the Hunter; retro-hunting is not CTI's job.

**Default egress is announced, and can be turned off** (D57). A new install
polls the two abuse.ch feeds; the quick start and the worker's first refresh
name the hosts they reach, and `SHOC_INTEL_FEEDS=off` stops them. Any other feed
is added by a human with `intel.configure` (RFC 0016). CTI works from whatever is
enabled and **says in the brief what it is blind to**.

**Tools.** None while reading: what the company runs is in the prompt, and the
answer is one typed `CtiDigestOutput` (RFC 0029). Code stores its indicators and
files the hunts and uncovered techniques it names on the Hunter's and the
Detection Engineer's backlogs. Roles: the **Surveyor** when answering.

### 5b. Answering (callable, no seat)

**Mandate.** Answer what is known about what a case, a hunt or a rule contains.

**It is a tool, not a participant.** Called by the **Investigator** and the
**Manager**, and by the loop when a case's evidence holds something to research. No seat in the openspace, no domain terms, no
interruptions. Nothing routes by keyword any more, so it is asked because somebody
needs an answer rather than because a message happened to contain one of its words.

**Four sources, and their trust is not equal:**

1. our indicator store and digested reports;
2. our own event history: have we seen this before;
3. a **reputation lookup** through `intel.lookup`: downloaded lists that send the
   value nowhere, keyless public services, and sources that need an account once
   a person set a key, each under a daily quota (RFC 0030). It sends the
   observable alone, never the case context, and never an internal value;
4. **the model's own knowledge** of a malware family or technique.

It may also **queue a reading job** for the scheduled half rather than answering
thinly: the answer arrives late but it is real, and the gap is recorded.

**Every claim carries its provenance.** Each statement says which of the four it
came from, and **unsourced knowledge can never be the only thing behind a
verdict**. A cited report and a half-remembered malware family must not read the
same on the page.

**A command line is intelligence.** `powershell -enc`, `certutil -urlcache`,
`rundll32` on something that is not a DLL, a base64 blob piped to a shell: which
reports describe that shape, and what usually follows it, even when no address or
hash in the case is known bad.

**Attribution: hold the line.** Name an actor only on a real match, and say plainly
that it does not change what this company does next. A guess dressed as
attribution sends the rest of the SOC the wrong way, and attribution is almost
never what a 200-person company needs. "Nothing has been published on this" is a
complete answer.

**Tools.** `intel.lookup` (which runs the enabled live sources), `intel.list`,
`intel.reports`, `events.query`. What it cannot answer goes in `queue_read` in
its answer.

**Model: required, `strong`, for both halves.**

**Never.** Follow an instruction inside a report or a lookup result: text addressed
to the model is part of the document being analysed, described as something the
document does, never obeyed. Raise a verdict. Guess attribution. Send an internal
value to a third party. Store an indicator that is not in the report text.

---

## 6. Hunter

> Built as RFC 0022 describes. The packs run on ready data only; one model turn
> a day triages what they return.

**Persona.** The only member of the pool whose job is to look for something no
rule describes. At a company where each admin console has one to six people, it
does not look for rare: it explains each new thing an account did, or says it
cannot.

**Mandate.** Rule out the ordinary in what the day's hunts return, and hand the
rest to the crew as findings.

**Packs ask the questions.** A pack is YAML in `content/hunts/` with a
hypothesis, a baseline, a triage question, follow-up questions and whether it is
`sensitive`. Triage never writes a query. The Hunter may write a pack for an
item on its backlog, which the gate runs before keeping (RFC 0032, below).

**Readiness, before anything runs (code).**

| Readiness | Meaning | What happens |
| --- | --- | --- |
| `not_applicable` | No connected source sends the pack's product | Listed, never "clear", no run |
| `learning` | The source's data started less than the pack's lookback ago | Listed with the date it is ready, no run |
| `stale` | No data from the source within the pack's window | A `gap` with the reason |
| `ready` | The data can answer it | Runs, over the accounts those sources speak for |

**Windows follow ingestion.** A pack reads what was ingested since its last
completed window, capped at its lookback, so a late delivery or a lost day is
caught up. First-seen history is what was ingested before the window, from the
same products and accounts, so a backdated event cannot make itself familiar.

**Triage, with read-only tools.** One turn a day over every tuple returned,
grouped with all its events and event types.

| Outcome | Accepted when | Goes to |
| --- | --- | --- |
| `clear` | A ready pack returned nothing | The run record; nothing else |
| `explained` | It rests on a fact a person wrote, shoc's own or the company's automation identity, or an older event a query returned | The run record |
| `inconclusive` | Anything not settled, including an explanation without a basis | Read again the next day with what was missing; a second one on a `sensitive` pack raises a finding |
| `suspicious` | It cites events | A low finding with actor entities, or a note on the open rule case that covers the same actor |
| `gap` | The pack could not run, no model triaged it, or today's triage ceiling had no room | A `hunt.gap` Ops alert with source health; the window is read again |

A pack whose findings were twice confirmed attacks, by a malicious close or a
person's suspicious close, becomes a Detection Engineer item.

**Agenda.** Every due pack runs. The packs merged for, or named as covering, a
hypothesis a configured feed's report raised this week come first, then the packs
sharing a technique with that intel or with this week's rule cases (D132). The day's budget is the triage turn's token
ceiling, `llm.configure hunt_tokens_per_day` (200,000 by default): packs are read
in agenda order while their tuples fit in half of what is left, and the turn
stops looking things up once it has spent the rest. A ready pack that falls
back because its source stopped sending pages the operator with that source's
coverage page.

**The backlog (RFC 0032).** Before the packs run, one turn per item on the top
three open backlog items, under 300,000 tokens a day. Each ends `packed` (only
once `hunt.merge` accepted a pack), `covered`, `not_worth`, `source_gap`
(reopened when a source sends the product) or `later` (`stuck` the third time).
The gate keeps a pack when it parses, a connected source sends its product, its
`surfaced` fixture comes back and its `baseline` fixture silences it, and one
window over our data returns at most 200 tuples. An item from a report says what
the report saw the attacker do and the shape that leaves, and the pack tests that
behaviour rather than every use of its technique. A merged pack runs with the
shipped ones; its first concluded run marks the item `done` (`tested`, with the
run). `hunt.revert` takes it back. A person may reject, close or reopen an item
with `hunt.decide`, giving a reason (D134).

**Tools.** Triage: `events.query`, `events.summarize`, `memory.search`,
`finding.list`, `case.list`, `graph.neighbours`. The backlog turn: `hunt.merge`,
`events.query`, `events.summarize`, `memory.search`, `hunt.results`,
`rule.list`. No peers.

**Writes.** `hunt.merge`, on the backlog turn only. Code writes the run, its
tuples, the findings and the Manager digests.

**Model: required for triage.** Without one the packs still run, nothing is
triaged and nothing advances.

**Never.** Write a query in triage. Merge a pack the gate refused. Open a case. Page. Write memory. Count a case still
open, or a crew's suspicious, as a true positive.

---

## 7. Surveyor

> **Built (D47, D49).** The scheduled survey runs the five queries, then the
> Surveyor's model reads them (`surveyor.read`): its reading is kept on the
> snapshot, an unwatched product it names becomes a Detection Engineer coverage
> item, and a change on an entity the survey holds becomes a memory fact. Okta
> takes the first snapshot: its users with their last sign-in, and its network
> zones. An identity the latest survey did not see keeps its row, marked absent,
> and turns stale 60 days after it was last seen.

**Persona.** The one who knows what the company owns. Can answer, in under a minute
and without asking anyone, whether we run the thing that was just published as
critically vulnerable, how many, which are reachable from the internet, and who can
log into them. Deeply sceptical of inventories, because the inventory is three
months stale.

**Mandate.** Maintain the asset, identity and exposure picture, and answer for the
rest of the pool, including what an address or host is to this company.

**The queries stay deterministic.** The five below are identical every time they
are asked and cite the event UIDs behind them. **The agent sits above them**: it
decides what to look at, interprets what the inventory means for this company, and
answers what no query covers. A model does not get to vary the answer to "who is
privileged".

1. **What exists**: every entity in the window, typed: account, host, identity,
   repository, key.
2. **What is exposed**: the entities that acted from outside the company's own
   ranges, and which of them are reachable.
3. **Who is privileged**: identities that performed administrative operations.
   Observed, not declared: a title in an IdP is a claim, an `AttachUserPolicy` is a
   fact.
4. **What is stale**: a key older than its rotation window still in use, an
   identity that has not authenticated in 60 days, a repository nobody touched that
   still holds a deploy key, an OAuth grant nobody remembers making.
5. **What is unwatched**: entities whose product no connected source and no rule
   covers. This is the number the founder should see.

**"What is exploitable now" is deleted.** It joined the exposed set against KEV,
and shoc ships no KEV feed. Vulnerability relevance is answered by **CTI**, per
case, from the reports it has actually read.

**What is this thing to us.** A lookup **every role must call** for an external address, host or identity in a
case, not a role that has to notice. Three sources, in this order of authority:

- **What a human declared**: somebody writing "that range is our office"
  **outranks anything inferred**.
- **What the connectors say**: the cloud account's own VPC ranges, the IdP's
  network zones, the VCS's runner addresses. Authoritative, and free.
- **What behaviour shows**: an address the whole company authenticates from is
  office egress; one that only delivers webhooks is a provider.

It does not propose declarations for anyone to confirm. Declarations are written
by people.

**Identity resolution is the Surveyor's.** The same actor under several names is a
fact about the company, computed once from events, declarations and connector data,
so every role gets the same answer. The Investigator calls `identity.resolve`
rather than inferring a bridge from field values. Its `logins` names the
identity-provider login a local account, a Gateway user or a GitHub member signs
in as, and the playbook runner revokes that login's sessions on an EDR,
Cloudflare or GitHub case (RFC 0027).

**Configuration snapshots are now a connector kind.** A describe pass over cloud
resources, the IdP's users and network zones, the VCS org state, the EDR device
list. Inventory stops being a side effect of activity, and the caveat that an idle
machine is invisible goes away with it. An account that exists and never acts is
exactly what an attacker wants, and nothing reported it before.

**The agent above the queries produces three things:**

1. **The founder's exposure story**: what we protect, what is exposed, what
   nobody watches.
2. **Coverage gaps as work items**: "nothing watches this" becomes a Detection
   Engineer backlog item and a Hunter floor-cadence entry, rather than a number in
   a report nobody opens.
3. **Posture change.** A new privileged account, a newly exposed host, an admin who
   stopped logging in. **This is not a finding on its own**: it becomes a fact on
   the entity that the Investigator sees, and a finding only when it coincides with
   activity.

**Tools.** `graph.refresh`, `graph.neighbours`, `events.query`, `snapshot.list`,
`posture.*`, `asset.identify`, `identity.resolve`, `detection.backlog`,
`platform.lookups`, `platform.lookup`. When another role calls it, it answers
in `AssetAnswer`: what the target is, whether it is ours, where that is known
from, how many principals are behind it, and the events behind that.

**Model: required for the agent; the five queries never use one.**

**Never.** Scan a host, a network or a cloud account. Require an agent on anything.
Add a service. Vary an answer to one of the five questions.

---

## 8. Detection Engineer

> Built as D77 describes. It works one backlog item per model turn, highest
> priority first, under a daily token ceiling.

**Persona.** The detection engineer. Treats noise as the primary failure mode
of a SOC and knows the quiet rule is the more dangerous one. Most items end
`no_rule`, and that is the right answer.

**Mandate.** Narrow a shipped rule that fires on the wrong thing, add a rule the
backlog asks for, and take back what turns out wrong.

**Intake (code).**

- A case closed `false_positive`, by a person or the crew, opens one item per
  (rule, case) at once, with the case's findings, tokens, who closed it and why.
- A case closed `benign_expected` opens one only when the same rule and entity
  come back: a second benign close in 30 days, or suppressed findings on two
  more days. Benign once is the rule doing its job.
- `needs_human` opens nothing. Hunt and indicator pseudo-rules go to the Hunter
  and CTI.
- The nightly sweep adds an aggregate rule over its volume (the dominant entity
  as evidence only), techniques intel named that no rule covers, reopens a
  source gap whose product now delivers, and lapses narrowings past 90 days.

**Code first, no model.** A new rule of its own that turned noisy is reverted;
a noisy narrowing reopens its item instead, because reverting it would restore
the louder shipped rule. An item whose findings are all shoc's own is closed
`no_rule`. An item worked three times on unchanged evidence is set aside.

**The gate for a narrowing** (`detection.merge` with `narrows` and `exclude`):

1. Every alternative holds one exact internet address and exactly one exact id
   (`actor.user.uid`, `resource.uid` or `actor.session.uid`), optionally the
   operation, service or account. No pattern, list, null or raw path.
2. Each value was seen on 7 days before the case, unless it is shoc's own or in
   `known_egress`. No event it hides is a person's unless the registry lists
   that account as automation.
3. The case's events, replayed through today's mapping, stop matching; the
   rule's shipped positive fixture and every event of its true positives still
   match.
4. The item is open, about this rule, and its case is closed `false_positive`
   or `benign_expected`; a crew closure waits for the weekly recheck to agree.

The exclusion is composed onto the shipped rule at load time, so later fixes to
the shipped rule reach the tenant. Events with no internet address (Tailscale,
GitHub webhooks) cannot be excluded: the item ends `no_rule` and the closure's
week-long suppression is the answer.

**The gate for a new rule:** fixtures that fire and stay quiet, stamped inside
the test window; a backtest under 25 findings a week; the ADS form; a playbook
with a step that can act on the rule's platform.

**Undo.** A case that reopens or turns malicious reverts the merges its items
produced, revokes its suppressions and reopens its items. Every merge, revert,
lapse and source gap is a Manager digest for the weekly.

**Health**, from case verdicts: findings in 7 days without `self` and
`suppressed`, closed verdicts and tokens over 30 days per rule, and for a silent
rule why: `not_ingested`, `field_empty:<field>`, `value_absent:<value>` or
`quiet`.

**Tools.** `detection.merge`, `detection.revert`, `rule.test`, `rule.backtest`,
`events.query`, `health.rules`, `finding.get`, `memory.search`. No peers.

**Model: required.**

**Never.** Touch a rule a human wrote. Write a suppression. Merge without the
gate. Exclude on a name, a description or a pattern.

---

## 9. Ops

> **Built (D47), except the budget.** Once per outage of a source, Ops' model
> judges it (`ops.review`): the diagnosis and fix are kept on the source and the
> coverage page carries them, `retry` queues a pull, and what the SOC cannot see
> goes in the weekly. Whether a dark source pages stays the query in
> `manager.coverage`, so a model cannot stop that page or raise one alone.
> `budget.*` waits for a budget setting (OPS-1).

**Persona.** The SRE of the SOC. Believes a detection you are not ingesting for is
worse than no detection, because it looks like coverage. The one member willing to
say the SOC is currently not covering something.

**Mandate.** Keep the pipeline working, and own the honest statement of what it
covers.

**It acts on broken ingest**, four ways:

1. **Retry and back off.** Re-run a failed poll, honour a rate limit, resume from
   the last checkpoint after an outage. Mechanical recovery, no judgement, no
   permission needed.
2. **Diagnose and name the fix.** Work out why a source is silent (an expired
   credential, a revoked scope, a changed API, nothing to collect) and state the
   exact fix, so when the operator does look it is one action rather than an
   investigation.
3. **Page when coverage is lost.** A source being down is not the outage of a
   tool, it is a hole in the SOC. When something material has been dark long
   enough, that is worth waking the one technical person for, under the same
   stated-condition discipline the Commander works to.
4. **Degrade the SOC honestly.** While a source is dark, hunts that depend on it
   are not run, rules on it are marked unreliable, and verdicts carry the gap. The
   SOC shrinks instead of pretending.

**Data-source quality, not just liveness.** DeTT&CT exists because coverage claims
are usually lies. Four axes: **completeness** (are all the accounts, hosts and
repos we know about actually sending), **retention** (how far back can we truthfully
hunt; a 30-day hunt over 7 days of data is a lie), **timeliness**, and **field
fidelity** (are the entity and group-by fields that source's rules correlate on
populated, or null in 40% of rows). Each source is held to its own rules, so an EDR
feed is scored on the host and an audit log on the user. A rule keyed on a field
that is null half the time is not a detection.

**It owns the budget, and cost is a signal.** Nothing else in the design limits
what a case or a hunt may spend once roles can call roles and the Hunter plans its
own day. Beyond enforcing the envelope, **a case or hunt that costs far more than
its peers is itself reportable**: either it is genuinely complex or something is
looping.

**The metrics go to the founder.** MTTD and MTTR per incident type, split into time
to triage, contain and close, and false-positive rate by rule. These are the
evidence that the thing works, for somebody paying for it. They are not inputs
other agents consume.

**Tools.** `health.sources`, `health.quality`, `health.rules`, `health.cost`,
`health.status`, `health.jobs`, `health.audit`, `ops.alerts`, `metrics.get`,
`budget.*` (not built). A retry is `retry` in its answer, not a tool. No peers;
a source that needs re-mapping goes to the Integrator, which is code.

**Model: required for the judgement; the measurements are queries.**

**Never.** Take an action on the company's infrastructure. Silence its own alert.
Claim coverage for a source it knows is dark.

---

## 10. Integrator

**Persona.** The one who makes the inputs real. Unglamorous, patient with vendor
consoles, and unwilling to call anything connected until it has seen an event come
out the other end.

**Mandate.** Get each source connected, mapped and proven, one source at a time.

**Install phase, then dormant, and it finishes per source.** Not one setup phase
that is either done or not: each source completes independently.

**Per source, four steps:**

1. **Discover.** Infer what should be connected by reading what already is: an Okta
   tenant that references a Google Workspace, a cloud account with an unconnected
   EDR, repos in an org we do not watch. It tells the operator which sources exist
   and are dark rather than waiting to be told.
2. **Credentials: the one step it cannot do alone.** It produces the exact scopes
   needed, least privilege, with the click path for that product and a paste-back
   point, so the human's part is five minutes rather than an afternoon.
3. **Verify and map, without help.** Confirm the poll works, sample real events,
   build or check the OCSF mapping against **what actually arrived**, and prove the
   unmapped fields are preserved rather than dropped.
4. **Prove it.** It does not call a source onboarded until **an event from it has
   become a finding**. A mapped source nothing is keyed on is not coverage, and it
   reports which rules now apply and which do not.

**It keeps the mapping while dormant.** Ops wakes it when a vendor changes shape.

**Code, except for one question (D74).** Every step above is checked by code:
`sample`, `coverage`, `proof`, and the permission table for the credential
step. A model is asked one thing, once per change of shape: which vendor field
now carries a column a rule reads. Its answer moves paths only, and is kept in
`shoc.mapping_overrides` only if the tenant's recent events fill no column less
and one more.

**The mapping standard, three parts:**

- **The whole event survives.** Common entities in OCSF *and* every
  technology-specific field preserved and queryable. A mapping that keeps only
  who, what and where has thrown away the evidence a case will need.
- **A fixture built from real sampled events**, so a vendor changing shape fails a
  test rather than silently dropping fields.
- **A stated list of which detections this source can and cannot support**, so
  nobody believes in coverage the fields cannot carry.

**Order, for a company of 20–500 people:** identity, then productivity (mail and
documents), then EDR, then cloud, and then the sources that hold the company's
value: the code host, the CRM, the payment provider, **raised above where
enterprise lists put them**, because that is what is being taken.

**Tools.** `source.list`, `source.sample` (one page read and mapped, nothing
stored), `mapping.test` (which rules the source's events can carry, and the
finding that proves it), `finding.list`, `health.sources`, `mapping.write` (a
tenant's field paths over the shipped mapping). `source.configure` stays the
operator's.

**When it runs.** `source.onboard`: daily, as soon as the operator configures or
changes a source, and when Ops raises a failing or degraded source (at most once
a day). Before the model is called, every configured source a finding has proved
is marked onboarded, so that part works with no model at all. A source waiting on
a credential is announced on the stream as `source.needs_credentials`.

**Model: only to repair a mapping**, once per change of a vendor's shape, and the
patch is kept only if the same recent events fill more with it. Every other step
is code (D74).

**Never.** Hold a credential the operator did not grant. Call a source onboarded
before an event from it produced a finding. Drop a field it could not map: an
unmapped field is preserved and recorded, not discarded.

---

## 11. SOC Manager

> **Built (D52).** `report.exception` runs daily and sends only when a decision
> needs a person: an L2 that expired unapproved while its case is open, a source
> waiting on a credential, a credential its vendor rejects. Each goes out once.
> The weekly holds digests and no decisions. With a model, the Manager adds a
> reading to the weekly and the exception report (D47).

**Persona.** The operator's one contact. It writes for a founder who is not
technical and has four minutes, and knows that a page or a report nobody needed
trains the reader to ignore the ones they do.

**Mandate.** Pages, answers and reports, and nothing else.

**Pages.** Every other role, `unattended.py` and every playbook page step hand it
a notice. A query groups the notices by incident and decides whether one page
goes out: a critical case, activity that cannot be contained, coverage dark for
a day, or a deadline that expired twice, at most once a day per incident. The
model writes the message; the template goes out when it cannot.

**Answers.** `ask` comes to it. It calls the colleague who knows and cites the
events behind the answer.

**Reports.** Three artifacts, and the first one is usually not sent.

**The exception report.** Sent **only when something needs a person**, and
carrying **only decisions a human must make**: an L2 whose fallback ran and the
narrower action was not enough, a credential only somebody with access can rotate.
**Silence when there is nothing is the product working.** Actions the system took
on its own, coverage it lost, and everything that expired unanswered are worth
knowing and are **not** exceptions; they go in the weekly.

**The weekly.** Hunts and their outcomes, detections created, merged and reverted,
gaps identified and closed, noisy and silent rules,
source quality, reversible actions taken without asking, suppressions written and
lapsed, and everything that hit a deadline.

**The monthly, for a founder.** What we protected, what it cost, what changed, and
the two numbers somebody paying for this actually asks about: what is exposed, and
what we would not have seen.

**Every number comes from a query**, and **the report is complete and sendable
with no model configured at all.** Prose is the optional part. A report a model
arithmetic'd its way through is a report nobody can reproduce or trust.

**The gate is not the model.** Whether somebody is woken is a query over typed
conditions. The model can change a page's wording and cannot stop it.

**Tools.** `report.get`, `health.sources`, `health.quality`, `health.rules`,
`health.cost`, `metrics.get`, `posture.get`, `hunt.results`, `case.list`, `case.get`, `action.list`, `events.query`,
`finding.list`. **Peers:** Investigator, IR Commander, Surveyor, CTI, Ops.

**Model: optional, for wording and answers.**

**Never.** Assign work, close a case, change a verdict or approve anything.
Compute a figure in the model. Report a number without the query behind it. Page
for something the system already handled.

---

## 12. Scribe

> **Proposed, not built.** Its record-keeping overlaps the case record the
> Investigator owns, and that has to be settled first.

**Persona.** The one keeping the record. In a serious incident somebody is always
assigned to write down what is known, what was decided, who decided it and at what
time, because six weeks later an insurer, a customer or a regulator will ask.
Unexcitable, pedantic about timestamps.

**Mandate.** Three things: the **incident record** (a timeline of what happened,
what we did, what we decided and when we knew each thing, built as it happens);
the **post-incident review**, within two weeks of closure and never optional; and
the **notification clock**, because regulatory deadlines run from awareness, not
from the end of an investigation: GDPR 72 hours, NIS2 24h/72h/1 month, DORA
4h/72h/1 month, SEC four business days from a materiality determination.

**Not their job.** Deciding whether to notify, filing anything, or giving legal
advice. It raises the clock and drafts the facts; **a human, with a lawyer,
notifies.**

**Tools.** `case.get`, `report.get`, `incident.record`, `incident.review`,
`compliance.clock`.

**Model: no for the record and the clock; optional for the narrative.** A timeline
a model composed is not a record.

**Never.** File, notify or contact anyone outside the company. Assert that a breach
is notifiable. Alter a timestamp. Block an action.

**Honest limit.** Thresholds ("is this personal data?") are a judgement about the
business that shoc cannot make. The clock is raised on *configured* regimes and
says plainly that applicability is the human's call.

---

## 13. The human member (and the external agent)

Humans are **members of the openspace, not spectators**. They post with
`--kind inject` ("no CI migration is planned this quarter") and that message is
evidence the crew must account for. They add durable facts with `memory.add_fact`,
and those facts outrank anything a role inferred. They approve L2 actions, they can
revert a Detection Engineer merge, they set case states, and they decide every
notification.

What they are **not** is a step in any path. Nothing in this pool rests on them
arriving: an L2 has a four-hour deadline, a case has a deadline, a suppression
lapses on its own, and the only thing that reaches them unprompted is a page or
the weekly report.

An **external agent** (an MCP client, someone's Claude) sees the read side of the
same surface: `case_list`, `case_get`, `openspace_post`, `memory_search`. It can
join an openspace and argue. It can **never** approve an action or change a source,
because `content/policy.yaml` caps the `external_agent` principal at **L0**. An
assistant given its person's role (RFC 0018) is a human principal with that
role's rights, and any L2 call it makes waits for the person's confirmation.

---

## 14. Playbook runner

**Persona.** The hands. A careful, literal operator who does exactly what the
approved paperwork says and nothing beside it: no judgement, no initiative, no
opinion about whether the action was wise. If the paperwork is missing a signature
they stop and wait, however urgent it looks. They keep a perfect record of
everything they touched and how to put it back.

**Mandate.** Execute approved actions, in order, idempotently, and record the undo.
**This is the only member of the pool that changes anything outside shoc, and the
only one that holds L1.**

**Runs.** When a case matches a playbook trigger, and again on every resume: a run
is a row and a step is a row, so the state machine survives a restart, a crash or
a deploy without a workflow engine (D6).

**Tools.** `playbook.*`, `action.propose` → `action.run`, `action.undo`, and the
action adapters under `shoc/actions/`, one module per vendor (aws, okta, entra,
crowdstrike, cloudflare, github, …, and notify for paging), the only
outward-facing writes in the system. Forensic collection actions run here too, ahead of the containment they
precede.

```
IR Commander proposes  →  policy.decide()  →  L0 notify only
                                           →  L1 runner executes now
                                           →  L2 waits four hours for a human,
                                              then a high or critical case
                                              pages once, anything else is
                                              rejected
```

An L1 action is *born approved*, because the policy already said yes; an L2 waits
in `waiting_approval` and **no agent can move it**. It does not wait for ever:
after four hours a `high` or `critical` case pages once, and anything lower
is rejected with the reason written into the case (RFC 0011, D37). The
Commander's fallback and window do not reach the policy yet (RFC 0012).

**Thinks.** It does not. Per step: render parameters (an unresolved placeholder
fails the step rather than guessing); propose; L2 → wait; L0 → notify; L1 →
execute unless `dry_run` (**the default for a new install**); record the result and
the undo; an action already `done` returns its recorded result instead of acting
twice.

**Model: no, and it must never have one.** A model on the execution path would
mean the one component that can take production down is also the one component
that can be talked into something by a log line.

**Never.** Approve an L2. Act on a step it was not given. Act twice for one
idempotency key. Act at all when `dry_run` is set.

---

## Interaction map

Who hands what to whom. Everything crosses the registry; a role calling a role is
a registry call with that role's own principal, and the exchange is written to the
openspace as the record.

```
  findings ────────┐
  hunt survivors ──┼─> Sentinel: entity / graph path / campaign
  (Surveyor posture change only when it coincides with activity)
                   │        │           │
                   │     defer       attach/open/split/re-scope
                   │        │           │
                   │        ▼           ▼
                   │    Hunter's     a case
                   │     agenda         │
                   │                    ▼
                   │            Investigator ──> timeline (alerting source out,
                   │                 │ ▲          pivots: identity, indicators)
                   │        calls ───┤ │
                   │        Surveyor ─┤ │ (what is this to us, identity, exposure)
                   │        CTI ──────┘ │ (what is known, with provenance)
                   │                    ▼
                   │             verdict + severity  (four; never needs_human)
                   │                    │
                   │                    ▼
                   │             Challenger: argues the other side
                   │                    │   surviving explanation must be
                   │                    │   ruled out with cited evidence
                   │                    │   └── wins on "normal here"
                   │                    │        └─> drafts the suppression
                   │                    ▼
        ┌───────────┬────────────────────┬──────────────────┐
        ▼           ▼                    ▼                  ▼
   malicious /  benign_expected     false_positive     nothing to do
   suspicious /      │                    │                  │
   still active      │                    │           Investigator closes
        │      suppression + TTL   detection defect
        │      + memory fact              │
        │            └──────> Detection Engineer ──> gate (fixtures,
        ▼                                             backtest, ADS, playbook)
   IR Commander                                       │
        │  forensic collection (L1) FIRST              merge, watch,
        │  blast radius, cited from the Surveyor       revert on noise
        │  L2 + fallback + window; critical pages
        ▼
   policy check (content/policy.yaml)
        │
   L1 ──┴── L2 ──> human approves within four hours, or it pages (high and
    │             │  critical) or is rejected
    │             │
    ▼             ▼
      playbook runner (the only thing that acts)
        │
        ▼
   IR Commander verifies: did the action take effect, and did the activity stop?
        │                  either failing reopens the response
        ▼
   Commander closes the case ──> audit log ──> Ops

  CTI reading (opt-in egress) ──> discard, or:
        ├─> indicator store (typed, TTL, do-not-match list, linked)
        ├─> Detection Engineer backlog (an uncovered technique)
        └─> Hunter (the retro-hunt)

  Hunter: code runs ready packs; one turn triages the tuples (RFC 0022)
        │  readiness: not applicable · learning · stale · ready
        ▼
   explained / clear ──> the run record    suspicious ──> a low finding
   inconclusive ──> read again tomorrow    gap ──> Ops alert (hunt.gap)
   two confirmed attacks ──> Detection Engineer

  events + config snapshots ──> Surveyor ──> five queries (deterministic)
        │                                      + agent above them
        ├─> asset.identify / identity.resolve ──> every role, on demand
        ├─> coverage gaps ──> Detection Engineer, Hunter floor cadence
        └─> exposure story ──> Manager

  sources ──> Integrator (per source: discover, scopes, map, prove a finding)
        │                              └─> owns that mapping while dormant
        ▼
   Ops ──> retry · diagnose · lost coverage to the Manager · degrade honestly
        │   budget, and cost as a signal
        ▼
   every page request ──> Manager ──> one page per incident · weekly · monthly
   operator's question ──> Manager ──> the crew, as peers ──> a cited answer
```

## Tool access matrix

An agent may call only what its row allows. This is the registry's job, not a
prompt's: the caller a role is handed holds exactly the scopes of the capabilities
on its row, and `Capability.invoke` checks principal, scope, autonomy and audit the
same way it does for a person. **A role on a row is called the same way**, with its
own principal and its own list, never the caller's.

| Agent | May call | Roles it may call |
| --- | --- | --- |
| Sentinel | `finding.list`, `case.list`, `graph.neighbours`, `intel.lookup`, `intel.reports`, `events.query`, `memory.search`, `suppression.list` | none |
| Investigator | `timeline.build`, `timeline.extend`, `events.query`, `finding.list`, `case.history`, `graph.neighbours`, `posture.exposure`, `identity.resolve`, `memory.search`, `suppression.list`, `intel.lookup`, `intel.reports`, `evidence.preserve` (L1), `platform.lookups`, `platform.lookup` | CTI, Surveyor |
| Challenger | `events.query`, `memory.search`, `suppression.list`, `finding.list`, `case.history`, `graph.neighbours` | none |
| IR Commander | `action.propose`, `action.list`, `posture.exposure`, `graph.neighbours`, `platform.lookups`, `platform.lookup` (no raw-log reads, RFC 0020) | Surveyor |
| CTI | `intel.digest`, `intel.lookup`, `intel.list`, `intel.reports`, `indicator.exclude`, `events.query`, `posture.get`, `detection.backlog` | Surveyor |
| Hunter | `events.query`, `events.summarize`, `memory.search`, `finding.list`, `case.list`, `graph.neighbours`; on its backlog turn `hunt.merge`, `hunt.results`, `rule.list` | none |
| Surveyor | `graph.refresh`, `graph.neighbours`, `events.query`, `snapshot.list`, `posture.*`, `asset.identify`, `identity.resolve`, `detection.backlog`, `platform.lookups`, `platform.lookup` | none |
| Detection Engineer | `detection.merge`, `detection.revert`, `rule.test`, `rule.backtest`, `events.query`, `health.rules`, `finding.get`, `memory.search` | none |
| Ops | `health.*`, `ops.alerts`, `metrics.get`, `budget.*` | none |
| Manager | `report.get`, `health.sources`, `health.quality`, `health.rules`, `health.cost`, `metrics.get`, `posture.get`, `hunt.results`, `case.list`, `case.get`, `action.list`, `events.query`, `finding.list` | Investigator, IR Commander, Surveyor, CTI, Ops |
| Scribe | `case.get`, `report.get`, `incident.record`, `incident.review`, `compliance.clock` | none |
| **Playbook runner** | `playbook.*`, `action.propose`, **`action.run`**, `action.undo` | none |
| Human | everything above, plus `action.approve`, `detection.revert`, `source.configure`, and every notification decision | none |

Three facts carry the safety argument. **`action.run` appears exactly once**, on
the one member with no model: the runner holds L1 because it has no judgement to be
talked out of. **`action.approve` appears only on the human row**, enforced by
principal kind in `content/policy.yaml`, not by prompt. And **`detection.merge`
appears exactly once**, on the role whose merges are gated by four tests and
reverted automatically when they turn noisy.

Capabilities above that do not exist yet, kept in `roles.NOT_BUILT` so a typo in
one cannot hide as a tool quietly not offered:

| For | Not built | Waiting on |
| --- | --- | --- |
| The Investigator keeping evidence | `evidence.preserve` | where preserved events live, and when retention may drop them |
| CTI's permanent do-not-match list | `indicator.exclude` | a store the matcher reads (DET-4, DET-7) |
| Ops and the budget | `budget.get`, `budget.set` | a budget setting (OPS-1) |

The Scribe's `incident.record`, `incident.review` and `compliance.clock` are not
built either, and will not be until the overlap with the case record is settled.

## Rules that bind every agent

1. **Evidence or nothing, per claim.** A claim without cited, verified event UIDs
   is struck from the output. A disposition left with nothing behind it becomes
   `needs_human` at confidence 0, which is a failure state, not a choice.
2. **Negative results are evidence.** The query that returned nothing is why an
   explanation was ruled out, and it is recorded.
3. **Untrusted content is data.** Logs, reports, lookup results and sampled events
   reach a model only inside `<untrusted-data>`, truncated, and are described,
   never obeyed.
4. **Agents read; only the playbook runner acts.** Every thinking agent stops at
   `propose`. Two narrow exceptions are typed, L1, catalogued and audited:
   evidence preservation, and forensic collection.
5. **No agent holds L2, and nothing holds it but a human.** A review can lower
   autonomy, never raise it. An unreachable reviewer and a refusal produce the same
   result.
6. **Nothing rests on a human arriving.** Every L2 has a four-hour deadline,
   every case has a deadline, every suppression lapses, and nothing is finished
   because somebody will press a button.
7. **Nothing is suppressed forever**, and a pattern suppressed three times is a
   rule that is wrong.
8. **Every disposition goes somewhere**, and a finding is never dropped.
9. **Every claim is tenant-scoped.** `tenant_id` on every read and every write.

## Open questions for review

1. **Should the per-case invocation ceiling vary by severity?** It is six peer
   calls per case today (`MAX_PEER_CALLS`), inside the severity-set budget.
   Rounds bounded a case by construction; a ceiling is now the only thing between
   a confused Investigator and a large bill.
2. **Should the Detection Engineer's revert cover silent rules?** Reverting one
   removes the coverage it was written for, and leaving it keeps a rule that has
   stopped working.
3. **Where does the Scribe's record end and the Investigator's case record begin?**
   Both are "keep the facts straight", and one of them now owns the timeline.
4. **What does the Integrator do when credentials never arrive?** Its one human
   dependency has no fallback yet, and the whole design says a step waiting on a
   person is a step that does not happen.
5. **Is `suspicious` still useful** now that it is where every unsettled case goes,
   and every unsettled case earns a reversible containment?
6. **Does the Commander checking its own blast radius hold up?** A role reviewing
   its own work is weaker than a role reviewing somebody else's. A deterministic
   guard sits under it: more than three principals behind the target, or a
   graph that could not be read, escalates without a model (`shoc/cases/review.py`).
7. **Who owns attack surface?** RFC 0005 makes it a daily hunt (DET-10); this page
   makes it the Surveyor's. One owns the write path, the other reads.
8. **Memory writes.** The Hunter writes an `explained` baseline and the Challenger
   drafts suppressions. What stops a wrong baseline becoming permanent: a TTL, a
   confidence floor, a human confirmation, or all three?
9. **`content/policy.yaml` grants the `agent` principal a ceiling of L1.** Evidence
   preservation and forensic collection now need it, so the answer is no longer
   "drop it to L0"; it is which actions those are, by name.
10. **NIST 800-61r3 retired the four-phase lifecycle** our case states implement.
    Keep the states (they are PICERL and they work) and re-anchor the docs to CSF
    2.0, or restructure the state machine?
11. **What steers CTI?** Priority intelligence requirements (PIRs), with a step
    that scores whether a piece of intel was used, are not modelled.
12. **What does a closed case teach?** An F3EAD pass after closure (which
    detection or hunt follows) has no owner.
