# The crew

> This page is how a case is worked at run time. What each role is for is
> specified in [`agent-specs.md`](agent-specs.md), terms and states are defined
> in [`ontology.md`](ontology.md), and where the code does not yet do what these
> pages say is listed under "Where the code is against this plan" in
> [`prd.md`](prd.md).

shoc's agents do not run free. Every claim carries the event IDs behind it, a
role may only call the capabilities it declared, and nothing waits for a person
to arrive. A role that needs something a colleague knows **calls them**, and the
openspace records the exchange rather than arranging it.

## What a case is

Findings that share an entity (`key:AKIA…`, `user:deploy-ci`,
`ip:203.0.113.55`) become one case: a leaked access key that triggers five rules
is one case, because every finding names the same key, user and address.
With a model configured, Sentinel then reads every case a detection cycle
touched (`shoc/agents/sentinel.py`). It may attach a finding to another open case
when it names the link (a graph path, a shared indicator or report), defer one
that a suppression, a fact a person wrote or a closed case already settles, by
that record's id, split off
findings that have become a different case, and rewrite the case's title. A
deferred finding is kept with status `deferred` and comes back when a newer
event refreshes it. Each decision is stored on the finding
(`evidence.sentinel`); Sentinel posts nothing in the openspace. An attach with no
named link is not carried out, and neither is a deferral whose id names no
active suppression, no fact a person wrote and no closed case: a log line that
imitates a memory fact names nothing that exists. A case left with no findings is
closed.

Cases move through NIST 800-61 states: `triage → analysis → containment →
eradication → recovery → post_incident → closed`. Only the transitions in
`shoc/cases/engine.py` are possible, so neither a human nor an agent can skip a
step by accident.

## Who speaks, and when

| Role | Posts | On |
| --- | --- | --- |
| None | `observation`: what the detections saw | Every case, before any model runs |
| Investigator | `hypothesis`: a disposition, a severity and the scope, cited | Every case |
| Challenger | `challenge` or `concede`: the side the verdict did not take, from the dossier and the verdict alone | Every case, once |
| Investigator | `evidence`: the answer to it | Whenever the Challenger did not concede |
| None | `observation`: the confidence the policy will read, and what it is made of | Every case, after the Investigator's last word |
| IR Commander | `proposal`, then `decision` | Malicious, suspicious, or anything still happening |

The opening message needs no model: it states what fired, straight from the
findings, because silence is the one outcome the loop may not produce. **The case
is closed by whoever held it last**: the Investigator when nothing needed doing,
the IR Commander when something did.

## Looking things up, and asking colleagues

Each role declares the capabilities it may call while it is thinking, and the
call goes through `Capability.invoke` like any other caller's, with the same principal,
scope, autonomy and audit. The full matrix is in
[`agent-specs.md`](agent-specs.md#tool-access-matrix). A declared capability
that does not exist yet is listed in `roles.NOT_BUILT` and is not offered, and
the role's prompt names the ones it lacks so the model does not reason around a
tool it was never given. An agent never calls `action.run`.

**Asking a colleague is a tool call.** `ask_cti`, `ask_surveyor`: the question
goes out, the answer comes back inside the caller's own turn, and the exchange is
written to the openspace as a `request` and an `answer`. Every peer call is also
a row in the audit chain (`ask_surveyor` under `agent:Investigator`), which is the
only record of one made outside a case: the Manager answering `ask`. A peer call
runs with **the peer's own principal and capability list, never the caller's**,
so it is not a way to borrow scopes, and never above the caller's scopes either:
a question asked with `ask:read` cannot end in a proposal. A peer may ask its own
peers, under the same ceiling. A role cannot call itself, cannot call one it did
not declare, and cannot ask the same question twice. Six peer calls per case.
When the evidence holds something CTI can research, or a report we read
describes it, and the Investigator's first turn did not ask CTI, the loop asks it
on the Investigator's behalf, and the Challenger and the Investigator's answer
read what it said (AGT-11).

CTI answers with a **provenance on every claim** (our store, a report we
digested, a live lookup, or its own knowledge), and unsourced knowledge can never
be the only thing behind a verdict. The Surveyor answers what a target is to this
company: a human's written declaration outranks anything inferred, and `unknown`
is a real answer.

Answers are log content and third-party text, so they arrive inside
`<untrusted-data>` and truncated. What was looked up is recorded on the message
the agent then posts, e.g. `[Looked up: events_query x3, graph_neighbours]`.

A turn makes at most six rounds of lookups and twelve lookups in all, however
many it asks for at once; past either, it is told to answer from what it has.
Every round re-sends the whole conversation, so an answer older than the latest
round is shown shortened to 1,500 characters. The agent can look it up again,
and the whole answer still counts when a claim cites an event in it. A colleague
answering a question gets three rounds and six lookups: it answers one question
in three sentences, it does not open an investigation of its own.

## The four dispositions

| Disposition | Means | Where it goes |
| --- | --- | --- |
| `malicious` | Confirmed attacker activity | IR Commander, and the case state machine |
| `suspicious` | Consistent with an attack, not proven | The same, with a lower confidence |
| `benign_expected` | Real activity, expected here | A suppression scoped to the entity, with an expiry, and a note in memory |
| `false_positive` | The rule fired on something it should never fire on | The Detection Engineer, as a defect |

**No role may choose `needs_human`.** A case still reaches it without anybody
selecting it (no model configured, an LLM failure, citations that did not
survive verification), and it is a failure state, not an answer. Thin evidence
is `suspicious`. Its reversible actions run on their own when the measured
confidence clears the policy's floor, and otherwise wait four hours for a person
before the unattended sweep resolves them. Either is a better answer than a
queue position.

`shoc/cases/routing.py` writes the suppression or the backlog item and records
what it did in `case_routing`, so "every disposition goes somewhere" is a row
rather than a claim. A case carrying the older merged `benign` verdict reads as
`benign_expected`.

## Severity

The Investigator **always** sets the severity, with one sentence of reasoning.
Nobody is watching this tool most days, so severity is the whole difference
between waking the one technical person in the company and handling it alone.
The change is said in the openspace and published as `case.severity_changed`.

## Budgets

Every run of the crew on a case has a budget in tokens and wall time. Severity
sets the floor:

| Severity | Tokens | Seconds |
| --- | --- | --- |
| informational | 60k | 300 |
| low | 100k | 420 |
| medium | 200k | 600 |
| high | 300k | 900 |
| critical | 500k | 1200 |

What the case contains raises it. Three or more researchable observables buy
another 30k tokens and two minutes; a report that already describes this
activity buys 60k and three instead. When the Investigator moves the severity, the budget
is recomputed around it. Six peer calls per case sit on top.

Each turn gets a share of the run's budget, and the colleagues it asks are paid
from that share: the Investigator's first turn 35%, the Challenger 12%, the
Investigator's answer to it 15%, the Commander 15%, and each colleague asked 10%.
The rest covers the claim check and a turn's last step, which can run past its
share.
A turn that reaches its share stops looking things up and answers. Before shares,
the Investigator's first turn on a busy case spent the whole run on lookups and
the case went to a person with its conclusion discarded.

The budget is checked before the Challenger speaks and before the Commander
does. A run that has spent it stops there: the case gets a `needs_human` decision
that says which budget ran out, `case.budget_exhausted` is published, and the
case is routed to a person with what the crew found attached. A Challenger that
did speak is always answered, whatever it rests on, so a verdict never stands
over an unanswered objection.

## Nothing waits for a person

Every case carries a **deadline derived from its severity**, enforced by the
scheduler rather than by an agent: 1 hour for critical, 4 for high, 24 for medium
and 72 below that (`shoc/cases/unattended.py`). On expiry the role holding the
case is re-woken and must either close it or say what it is still waiting for,
and **a `high` or `critical` case that expires twice pages**. A `needs_human`
case is sent back after 6 hours at most. An L2 action waits four hours; see
[`response.md`](response.md#when-nobody-approves).

## Evidence or nothing

- **Per claim, not per verdict.** Every statement the Investigator makes carries
  its own event UIDs, and a claim with no surviving citation is struck before
  anybody reads it.
- **Negative results count.** The queries that came back empty are recorded,
  because an absence is why an explanation was ruled out.
- Citations are verified against the event store before a message is written. An
  event ID the model invented is dropped; if none survive, the message is refused
  and downgraded to an `observation` marked `[uncited, downgraded]`.
- A verdict whose citations do not survive becomes `needs_human` at confidence 0,
  enforced in `shoc/cases/engine.py:set_verdict`, for humans and agents alike.

## Confidence is measured, not asked for

The policy's `min_confidence` used to read the number the Investigator wrote
about itself, and self-reported confidence runs high, higher still after an
agent has gathered evidence with tools. The number the policy reads now comes
from two checks that ask the Investigator nothing (`shoc/agents/checks.py`,
RFC 0020):

- Agreement. `SHOC_CREW_SAMPLES` independent reads of the dossier (2 by
  default), on the cheap model, with no tools and none of the Investigator's
  reasoning, each reach a disposition. The Investigator's own answer before the
  Challenger spoke is a read too, so a verdict that flipped under pressure
  counts as a disagreement. Agreement is the share on the same side, attack or
  benign, as the final verdict.
- Support. Each claim is shown, with only the events it cites, to a checker that
  is not told the verdict. Support is the share it finds shown by those events.
  A claim that cites no event that exists is unsupported without a model call.

The confidence is the smaller of the Investigator's number and agreement times
support. A check that cannot run counts as failed. The openspace records the
parts, e.g. `Confidence 0.67: 2 of 3 independent read(s) reach the attack side;
4 of 4 claim(s) are shown by the events they cite; the Investigator said 0.90.`
Playbook triggers read the same number.

Once a week, `case.recheck` reads up to five cases the crew closed as
`benign_expected` or `false_positive` again, blind, on the strong model. A read
on the attack side reopens the case and queues the crew; it takes no action and
pages nobody.

## Missing data is a coverage bug, not a stall

No EDR, GitHub unconnected, a stale source: the Investigator still commits to one
of the four dispositions, **files the gap as a coverage item**, and lets it lower
its confidence. It does not leave the case open, and it does not treat a missing
source as evidence that nothing happened.

## Untrusted log content

Log fields are written by whoever attacked the company, so they reach a model
only inside an `<untrusted-data>` block, and the system prompt states that
nothing inside such a block is an instruction. The same applies to a threat
report, a live reputation lookup and a sampled event from a new source. Every
`<` inside a block is written `\u003c`, so a log line carrying
`</untrusted-data>` cannot end the block early. The graph, posture, observables
and the case summary are quoted too, because entity names come from the logs.
Long values are truncated. We do not try to detect injection attempts.

Delimiters alone do not stop a determined attacker, so the parts that act do not
rely on them:

- The IR Commander decides from the claims that passed their check, the case's
  entities and its indicators. It has no raw-log tool and is not shown the
  evidence block.
- An action's target has to appear in the events the verdict cites, the case's
  entities, its indicators or a platform read the Commander made. One that
  appears nowhere is proposed as L2 and waits for a person with a deadline.
- Memory is shown by who wrote it. Only a fact a human principal added is
  presented as what the company told us; the crew's own closures and the
  Hunter's baselines are shown as earlier conclusions, which the Challenger may
  not treat as a written fact.

Five scenarios check that the verdict does not move: `prompt_injection`, and
variants that close the tag (`_breakout`), split one instruction across three
user agents (`_split`), forge shoc's own memory and Surveyor formats
(`_provenance`), and call the attack a drill (`_persona`).

## Talking to the openspace

Humans are members, not spectators:

```bash
shoc case list --state triage
shoc case get CASE-1a2b…
shoc openspace post --case-uid CASE-1a2b… --kind inject \
  --body "No CI migration is planned this quarter"
shoc memory add-fact "The VPN pool is 10.8.0.0/16" --subject network
shoc case investigate CASE-1a2b…
```

A fact a human writes down outranks anything a role inferred. An `inject` sends
the crew back to a case; a `request` a person posts is recorded, and nothing
answers it. An external agent over MCP can read, join an openspace and post, but
never approve an action or change a source. An assistant given its person's role
can do what that role allows, and any L2 call it makes waits for that person's
confirmation ([`security-model.md`](security-model.md#an-assistant-asks-the-person-confirms)).

## Models

Every crew role uses a model. Where an answer must be identical every time it is
asked, **it stays a query and the model sits above it**:

| Role | What stays deterministic |
| --- | --- |
| Surveyor | Its five questions (what exists, what is exposed, who is privileged, what is stale, what is unwatched), each citing the events behind it |
| Manager | Every figure, and whether a page goes out. A page is complete and sendable with no model; the wording is the optional part |
| Detection Engineer | Intake, rule health, the gate and its replay of stored events. The model decides what, if anything, to change |
| Ops | Freshness, quality, spend and stuck approvals. The model decides what to do about them |
| Hunter | Readiness, the windows and the query. The model rules out the ordinary, and code accepts an explanation only on a basis it can check |

With `SHOC_LLM_PROVIDER=none`, ingest, detection, case grouping, the store, the
intel plane and the reports still work. **Investigation does not**: the crew
does not run, each new case is handed to the Manager, and a case worked anyway is
set to `needs_human` with its evidence attached. `intel.digest` refuses without a
model, and the review that guards a blocking action escalates to a human.

```bash
export SHOC_LLM_PROVIDER=anthropic       # or openai, or none (the default)
export SHOC_LLM_API_KEY=…
export SHOC_LLM_MODEL=claude-sonnet-5    # optional
export SHOC_LLM_MODEL_CHEAP=…            # optional: the model for "cheap" roles
export SHOC_CREW_SAMPLES=2               # independent reads behind a confidence
```

Each role has a `model_hint`. With `SHOC_LLM_MODEL_CHEAP` set, the roles marked
cheap that the code calls today (Sentinel, the Challenger, the Surveyor, Ops and the Manager),
the independent reads and the claim checker run on it; without it everything
runs on one model. A different cheap
model also gives the reads a second model family to disagree with.

On the Anthropic API the reply is constrained to the role's schema (structured
outputs), the prompt prefix is cached across the steps of a tool loop, and a
request the model's safety classifier declines is retried on the API's fallback
model where the model supports one. A decline that still comes back is an error
the case records, not an empty answer. Any OpenAI-compatible endpoint works with
`SHOC_LLM_PROVIDER=openai` and `SHOC_LLM_BASE_URL`: vLLM, Ollama, Databricks
model serving. A model a gateway serves on `/responses` only, such as
DeepSeek V4.1 Flash on Kie, takes `SHOC_LLM_PROVIDER=openai-responses`. There the
schema is in the prompt and the reply is parsed and validated, with one retry.

On a running deployment, `llm.configure` changes the provider, either model,
the endpoint or the key, and the next case uses the new settings with nothing
restarted (RFC 0007). It is L2 and human-only, so no agent can change the model
it runs on. A stored field wins over its `SHOC_LLM_*` variable; a field never
stored keeps the environment's value, and `--clear` drops the stored row.
`llm.show` names the model in use and which fields were stored. A stored base
URL must name a host in `SHOC_LLM_BASE_URL_ALLOWLIST`, which defaults to the
host of `SHOC_LLM_BASE_URL` plus the Anthropic and OpenAI APIs, because
whoever sets the endpoint receives every case's evidence.

```bash
shoc llm configure --provider anthropic --model claude-sonnet-5
shoc llm show
```

## Reviewing an action before it runs

An action marked `review_before_action` in `content/policy.yaml` is reviewed
before it runs automatically, and **the IR Commander answers for its own
proposal**: who else is behind this target, and whether a narrower action would
do. An **unanswered blast radius refuses the action in code**, not only in the
prompt. So does a count of somebody behind the target that cites none of the
case's events: the review is shown those event ids, and a citation of anything
else does not count. A review that names a narrower action, or one that would
stop the attacker where this one does not, has not approved this one.

A deterministic guard runs **before** the model is asked. If more than three
distinct principals have been seen behind the target, or the graph could not be
read, the action escalates with no model involved. A review can only make an
action harder to take; it never raises an action's autonomy.

## One contact: the SOC Manager

Nothing in the crew talks to the operator except the SOC Manager (RFC 0015). The
Commander, Ops, `unattended.py` and every playbook page step hand it a notice,
and a pending L2 leaves one too.

**Whether anybody is woken is a query.** Notices are grouped by incident (the
same case, or cases on the same entity), and a group pages only on a named
condition: a critical case, activity that cannot be contained, coverage dark (a
source for a day, or the whole schedule for an hour), a deadline that expired
twice, an audit log that no longer verifies, or a high or critical malicious case
that no action has contained for real, checked 15 minutes after its verdict and
when its playbook ends. It pages at most once a day per incident. A notice with
no condition waits for the weekly.

**The Manager writes the page, not the decision.** Given the group, the model
writes one message with its citations. With no model, a failure, or a citation
the group does not contain, a fixed template goes out instead. The page goes to
PagerDuty as a `notify.page` action and is mirrored to Slack with Approve buttons
for whatever its cases are waiting on.

**Questions come back through it.** `ask`, over REST, MCP or `/shoc <question>`
in Slack, goes to the Manager, which calls the Investigator, the Commander, the
Surveyor, CTI or Ops for what they know, and cites the events behind its answer.
Each call may carry the earlier turns of the conversation, which reach the model
quoted as data like the question. Without a model, or without evidence that
survives the store, `ask` answers as `search` does: typed queries, no model, and
`intent: search` in the answer so the caller can tell.

The Manager assigns nothing, closes nothing and approves nothing. Approvals and
injected facts stay direct capabilities, so a broken Manager cannot stand between
a person and a decision. Every number in a report comes from a table; a model may
narrate, never count.

## Measuring it

How the crew is scored and how a change is checked is in
[`evals.md`](evals.md). In short, `evals/` replays recorded attacks and scores
what came out:

```bash
python -m evals.run                    # detection quality, no model needed
python -m evals.run --investigate      # also scores verdicts, needs an LLM
python -m evals.run --investigate --repeat 3 --alpha 0.1
python -m evals.run --markdown evals/RESULTS.md
```

Detection scoring runs on every pull request. `benign_ci_day` measures the
opposite of recall: every rule that fires on an ordinary day is a false positive
somebody has to read. `benign_key_rotation` is the lookalike: a rule fires, and
the right verdict is `benign_expected` because a person wrote down that the
rotation happens every month. A scenario's `memory:` seeds those facts, and its
`must_look_up:` names the tools an analyst would have had to call, read back
from the openspace.

`--repeat k` runs each scenario k times and passes it only if every run passes.
The runs also calibrate the policy: `min_confidence` in the summary is the lowest
floor at which, by conformal risk control over these runs, an automatic verdict
is wrong at most `--alpha` of the time. It is `null` when there are too few runs
to promise that, and `1.01` when no confidence the crew reached is safe to act
on. The number is a recommendation for `content/policy.yaml`; nothing writes it
there.
