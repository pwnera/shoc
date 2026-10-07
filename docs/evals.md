# Evaluating the crew

> How shoc measures its agents, and how a change to a prompt, a tool, a budget
> or a model is checked before it ships. What each role is for is in
> [`agent-specs.md`](agent-specs.md); how a case is worked is in
> [`agents.md`](agents.md).

A crew role is a prompt, a typed output, a list of tools and a budget. None of
these can be checked by reading them. A change is good when the crew decides
more cases correctly on data it has not seen tuned against, at a cost the
budget allows, and worse when it does not. Everything on this page exists to
answer that question with a number.

## What is measured

Two harnesses, one per kind of input.

**Scenarios** (`python -m evals.run`) replay a recorded attack, or an ordinary
day, through the real pipeline: ingest, the rules, Sentinel, the case loop, the
Commander's proposals and the Manager's answers. Each lives in
`evals/scenarios/<id>/` as the vendor's own records (`events.json`) and what
should come out (`expected.yaml`).

| Field | Scores | Role |
| --- | --- | --- |
| `expected_rules`, `must_not_fire` | Which rules fire, and which must not | Detections |
| `min_cases`, `max_cases` | How the findings were grouped; an attack stage Sentinel deferred fails the run | Sentinel |
| `expected_verdict`, `minimum_confidence` | The disposition, and the measured confidence behind it | Investigator, Challenger, claim check |
| `minimum_severity` | The severity the Investigator set | Investigator |
| `must_look_up` | Tools an analyst would have had to call | Investigator, peers |
| `forbidden_verdicts`, `injection` | A verdict the logs tried to talk the crew into | Every role that reads logs |
| `must_propose` | The action that stops it, on its target | IR Commander |
| `forbidden_targets`, `no_page`, `max_tokens` | Actions, pages and spend the case must not cause | IR Commander |
| `expected_hunts` | What a hunt pack concludes: `not_applicable`, `learning` and `clear` without a model, `explained`, `inconclusive` and `suspicious` with one | Hunter |
| `close`, `de` | What a person's close hands the Detection Engineer, and what it merges | Detection Engineer |
| `ask` | A question the operator would ask, what the answer must name, and that it cites stored events | Manager |
| `memory` | Facts a person wrote down before the attack | None |

**Probes** (`python -m evals.roles`) put one decision to a role that a replayed
case does not reach, in `evals/probes/<role>.yaml`:

| Role | Probe | Scored |
| --- | --- | --- |
| Ops | A source dark with a given error | Which sources it queues a retry for; what each diagnosis names |
| Integrator | A vendor renamed a field a rule reads | Whether the repaired mapping fills the column again |
| CTI | A threat report | The indicators, typed; values it must leave out; techniques; `keep` |
| IR Commander | An action waiting for review, with the graph and written facts about its target | Whether it approves |
| Claim check | Claims, each with the events it cites | Which claims those events show |
| Surveyor | A question about an address or a credential | Whether it is the company's own, and how it knows |
| Manager | The notices behind a page | Whether its wording is sent rather than the template, and names what to act on |
| Manager, reading a report | A weekly report after a replayed attack | That every number in the reading is one of the report's |

A probe or a scenario scores the decision, never the wording. A prompt can be
rewritten freely as long as the decisions hold.

## Running it

```bash
python -m evals.run                                  # detection only, no model
python -m evals.run --investigate                    # the crew, with the configured model
python -m evals.run --investigate --repeat 3         # pass^3, and a calibrated min_confidence
python -m evals.run --investigate okta_mfa_fatigue   # one scenario
python -m evals.run --investigate --json now.json --baseline before.json
python -m evals.roles                                # every probe
python -m evals.roles cti review/disable_leaked_key  # some roles, or one probe
```

Each scenario run and each probe gets its own tenant, so runs can go in
parallel against one database. They spend the configured model's tokens like
production does: on deepseek-v4-1-flash a full `--investigate` pass was about
six million tokens and the probes about three hundred thousand, so rerun the
scenarios a change touches with `--repeat` and keep full passes for the end. `--json` keeps everything, including each run's
tenant and the case's openspace as text, one line per message: what to read
first when a run fails. `--baseline` names the scenarios that started passing or
stopped since an earlier report.

The summary carries the numbers that matter between runs:

- `verdict_accuracy` over every scored run, and `passed` with pass^k: a
  scenario passes only when all k runs do.
- `needs_human`: runs that ended without a disposition. Nobody is coming
  (D37), so each is a cost even where a scenario forbids nothing about it.
- `challenge_fixed` and `challenge_broke`: verdicts the Challenger turned
  right, and verdicts it talked the Investigator out of.
- `min_confidence`: the policy floor at which an automatic verdict is wrong at
  most `--alpha` of the time (RFC 0020). It is a recommendation for
  `content/policy.yaml`; nothing writes it there.
- `tokens`: what the run cost.

Replays carry documentation addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and example domains in place of real ones. A model knows these
ranges, and without a word it argues from "TEST-NET, not routable". Every
scenario and probe tenant gets one written fact saying they stand for real
public addresses.

## The loop

1. **Run the whole set** with the model production uses, and keep the JSON.
2. **Read the failures, not the score.** For each failing run, read its
   openspace in the report and put the failure in one bucket:
   - *data*: the scenario is wrong or unrealistic, such as a city that does not
     match its country or a probe whose expected answer was itself the
     mistake. Fix the scenario and say why in the commit.
   - *context*: the crew could not see what it needed, such as a truncated raw
     field, a missing lookup or a fact nobody wrote. Fix what reaches the
     prompt.
   - *budget*: the run stopped before a verdict, or a turn spent the run.
     Fix the cost before the budget.
   - *reasoning*: the crew saw everything and chose wrong. Fix the role's
     prompt or output schema, in the place the model reads when it decides.
   - *harness*: the scorer is wrong.
3. **Change one thing**, then rerun the failing scenarios with `--repeat 3`
   until they pass every time.
4. **Rerun the whole set with `--baseline`** and look at what regressed. A fix
   that buys one scenario with another is not a fix.
5. **Ship the change with its numbers** in the commit or pull request:
   verdict accuracy, pass^k, `needs_human`, tokens, before and after.

Pull requests that touch `shoc/agents/`, the action review, `content/` or
`evals/` run the scenarios and the probes in CI when a model key is configured
(`.github/workflows/evals.yml`), and every release publishes both reports.

## Where new cases come from

A scenario is added when the crew gets something wrong, and the best source of
those is a person correcting it. `python -m evals.capture CASE-… --out DIR`
writes a case a person closed as a scenario: the vendor records behind its
findings and an `expected.yaml` holding their disposition. Replay the directory
with `python -m evals.run --scenarios DIR --investigate`.

Captured scenarios are the company's own logs and stay private. One goes into
`evals/scenarios/` only after every address, name and id in it is replaced
with documentation values and fake ones, and it keeps the attack it records.

Every attack scenario wants a benign twin that fires the same rules: an
always-malicious crew must fail the set (`tests/unit/test_evals.py` checks it).
