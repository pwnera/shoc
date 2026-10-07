---
rfc: 0020
title: Gate automatic actions on measured confidence, and keep raw logs away from the role that acts
status: accepted
authors: ["@Rettila"]
created: 2026-09-30
requirements: ["AGT-1", "AGT-2", "AGT-6", "SEC-2", "RSP-3"]
supersedes: null
---

# RFC 0020: Gate automatic actions on measured confidence, and keep raw logs away from the role that acts

## Summary

The confidence the policy reads before an action runs on its own is no longer the
number the Investigator writes about itself. It is the smaller of that number and
two measurements: how many independent reads of the case land on the same side,
and how many of the Investigator's claims are shown by the events they cite. The
IR Commander stops reading raw logs, and an action whose target the case's
evidence never showed cannot run without a person. A weekly job rereads a sample
of the cases the crew closed as benign. The eval harness gains repeated runs,
lookup grading and a calibrated `min_confidence`.

## Motivation

A review of how the crew is prompted, against published research and the AI SOC
products that describe their design, found these gaps in the code as it stood:

- `min_confidence: 0.85` gates `aws.disable_access_key`, and the value it read
  was the model's own. Verbalised confidence is overconfident (Xiong et al.,
  ICLR 2024, arXiv:2306.13063), and more so after an agent gathers evidence
  with tools (arXiv:2601.07264). OpenSec (arXiv:2601.21083) measured frontier
  models containing in most episodes with a high false-positive share.
- The Investigator prompt said a low-confidence `suspicious` "earns a reversible
  containment". The policy sent anything under 0.8 to a human. The prompt and
  the policy disagreed.
- `validate_citations` checks that an event exists, not that it shows the claim.
  Up to 57% of citations in RAG answers are post-rationalised (arXiv:2412.18004).
- The Challenger read the Investigator's reasoning and argued once, and the
  Investigator then answered it. Challenged with "are you sure?", models flip
  46% of answers (FlipFlop, arXiv:2311.08596), and most of what multi-agent debate
  gains is majority voting (arXiv:2508.17536).
- `safety.quote` did not escape `</untrusted-data>` inside a payload, and the
  graph, posture and observables sections of the dossier were raw JSON. Delimiter
  prompting alone left 41.7% attack success in AgentDojo (arXiv:2406.13352), and
  adaptive attacks break prompt-level defences (arXiv:2510.09023).
- The IR Commander read the raw dossier and picked action targets, and nothing
  tied a target to the evidence. Argument tampering is the residual risk even
  under plan-then-execute (arXiv:2506.08837).
- `routing._remember` stored the crew's own benign closures in memory, and the
  dossier showed them as "What this company has told us before", which the
  Challenger ranks as its strongest ground. One case talked into benign became the
  written fact that cleared the next.

## Guide-level explanation

After the Investigator's last word, the openspace carries one more line that no
model wrote:

```
Confidence 0.67: 2 of 3 independent read(s) reach the attack side; 4 of 4
claim(s) are shown by the events they cite; the Investigator said 0.90.
```

That is the number `content/policy.yaml` compares with `min_confidence`, and the
number playbook triggers read. Two settings shape it:

```bash
export SHOC_CREW_SAMPLES=2          # independent reads beside the Investigator's own
export SHOC_LLM_MODEL_CHEAP=…       # the model for the reads, the checker and cheap roles
```

The evals say where the floor should sit:

```bash
python -m evals.run --investigate --repeat 3 --alpha 0.1
# "min_confidence": 0.85  -> the lowest floor with at most 10% wrong automatic verdicts
```

## Reference-level explanation

`shoc/agents/checks.py` holds the measurement.

- `reads` runs `SHOC_CREW_SAMPLES` completions of `ReadOutput` (a disposition and
  two sentences) under the Investigator's prompt, from the dossier alone, with no
  tools, on the cheap model. The Investigator's first-pass disposition is added
  as a read when the Challenger round made it answer again.
- `check_claims` shows each claim (up to 12), with only the events it cites (up to
  5), to a checker prompt that is not told the verdict, and reads back
  `supported`, `unsupported` or `contradicted` per claim. A claim whose cited
  events do not exist is unsupported without a call.
- `derive` returns `min(stated, agreement × support)`, where agreement is the
  share of reads on the final verdict's side (attack: malicious or suspicious;
  benign: benign_expected or false_positive) and support is supported ÷ checked.
  A failed read is dropped; a failed check counts as unsupported.

`loop.run_case` calls `derive` before it records the interim verdict, posts the
note, and records the measured number. The Challenger's prompt carries the
dossier and the verdict, not the Investigator's reasoning.

The IR Commander's prompt carries `_brief`: the case summary, its entities, its
scope, the claims that passed the check and the observables. `events.query` and
`timeline.extend` leave its tool list. `_grounded` checks each proposal's target
against the cited events, the case's entities, its observables and the text of
the Commander's own tool results (a platform lookup is where an inbox rule id
comes from). `CrewProposal.grounded` flows to `policy.decide(grounded=...)`,
which moves an ungrounded L1 to L2 with the reason written down. The existing
four-hour deadline then applies.

Containment: `safety.quote` replaces every `<` in the body with `<`, which is
also the JSON escape, so a JSON body stays valid JSON. Every dossier section built
from events is quoted. `memory.split` separates facts a human principal added from
everything else, and the dossier and the Hunter's triage show the two under
different headings.

Prompting:

- Roles whose declared tools include unbuilt ones are told which in their prompt
  (`Role.__post_init__`).
- `InvestigatorOutput`, `ReviewOutput` and `HuntOutcome` list evidence fields
  before the verdict.
- Bold emphasis is gone from role prompts.
- The Hunter's triage returns a typed `Triage` instead of a line starting
  `EXPLAINED`.
- Each playbook gains an `example:`, a worked answer from an invented case, shown
  in the dossier inside `<example>` tags.

The model client:

- `for_hint` runs cheap roles on `SHOC_LLM_MODEL_CHEAP`.
- On the Anthropic API, `complete_typed` sends the schema as
  `output_config.format`, `strict_schema` makes every property required and drops
  titles, and the request sets top-level `cache_control`.
- `stop_reason: "refusal"` raises `UpstreamError`, and models that support it ask
  for `fallbacks: "default"`.
- The last turn of a tool loop and the parse retry keep the tools declared.
- `SHOC_LLM_MAX_TOKENS` defaults to 16000, and the read timeout is 600 seconds.

`shoc/agents/recheck.py` runs weekly as `case.recheck`. It rereads up to five
cases closed as `benign_expected` or `false_positive` in the past seven days, once
each, on the strong model. A read on the attack side reopens the case to `triage`
and queues `case.investigate`.

`evals/run.py`:

- `--repeat` gives pass^k.
- `must_look_up` grades the tools recorded in the openspace notes.
- `memory` seeds human facts.
- `act_threshold` computes the conformal risk control floor (Angelopoulos et al.,
  2022) over the runs. The loss is 1 when a verdict at or above the threshold is
  wrong.

New scenarios:

- Injection variants: `prompt_injection_breakout`, `_split`, `_provenance` and
  `_persona`.
- `benign_key_rotation`, the first benign scenario in which a rule fires, so the
  first to score a benign verdict.

Principles touched: 5 (bounded autonomy) and 6 (evidence or nothing), both
tightened.

## Drawbacks

- Each case costs more: two cheap reads over the dossier and one cheap check
  call. On a quiet install that is a handful of extra calls a day.
- A verdict with no claims, or whose checker cannot run, now measures 0, so its
  L1 actions wait four hours for their fallback. That is slower containment in
  exchange for not acting on an unchecked verdict.
- The Commander without `events.query` cannot confirm a detail the Investigator
  did not establish. It can ask the Surveyor, which still reads the dossier.
- String containment is a coarse grounding test. A target that appears in the
  case only as a substring of something else passes.

## Alternatives

- Keep the self-reported number and raise `min_confidence`. This does not fix
  calibration; it only moves the threshold on an uncalibrated number.
- Run the full tool-using investigation three times and vote. This is closer to
  self-consistency, and three times the cost of the most expensive turn.
- NLI model for claim checking. This would need a new dependency, and the budget
  is for security machinery. The cheap model does the same job with what we have.
- CaMeL-style planning with a quarantined model (arXiv:2503.18813). This is the
  stronger design, but it is a rewrite of the loop. Context minimisation and
  target grounding take the part of it that protects actions.
- Do nothing. The gaps listed under Motivation stay.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes:
  - `Proposal` and `CrewProposal` gain `grounded`, and `policy.decide` gains
    `grounded`.
  - `InvestigatorOutput`, `ReviewOutput` and `HuntOutcome` reorder their fields.
  - Playbook YAML gains an optional `example`.
  - Scenario YAML gains `memory` and `must_look_up`.
  - A new job kind, `case.recheck`.
  - New settings `SHOC_LLM_MODEL_CHEAP` and `SHOC_CREW_SAMPLES`; the default of
    `SHOC_LLM_MAX_TOKENS` moves from 2048 to 16000.

## Security considerations

This touches `shoc/agents/`, `shoc/cases/` and the policy, so it needs two
reviewers once the project has them.

- It narrows what an injected log line can do:
  - It cannot close the data block.
  - It cannot reach the role that picks targets as raw text.
  - It cannot make a target it names run unattended unless that target is in
    the cited evidence.
  - It cannot have a crew closure presented as a human's statement.
  - A persuaded verdict now needs independent reads and a claim checker that
    did not see the Investigator's reasoning to go along with it.
- It does not stop an injection that persuades every read the same way. The
  split, provenance and persona scenarios exist to measure that.
- Nothing here raises an action's autonomy. The recheck reopens cases and
  queues the crew; it proposes and runs nothing.

## Unresolved questions

- The calibrated floor needs more scenarios than exist. Twelve of the 14 open a
  case, so `--repeat 3` gives 36 scored runs, and `alpha` must be at least 1/37.
  The target is 20 to 50 scenarios with benign lookalikes for each attack.
- Whether the reads should run on a different model family by default, since
  that is where debate and voting gain the most (arXiv:2502.08788).
- An LLM judge for investigation quality needs expert-labelled cases before it
  can be calibrated, and there are none yet.

## Adoption and migration

It is on by default after upgrade. Existing cases keep the confidence they have.
`SHOC_CREW_SAMPLES=0` leaves only the Investigator's own reads to agree. Run the
evals with `--repeat` before changing `min_confidence` in `content/policy.yaml`.
