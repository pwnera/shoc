---
rfc: 0033
title: People merge playbooks at runtime, made of the actions shoc has
status: accepted
authors: ["@Rettila"]
created: 2026-10-06
requirements: ["RSP-2", "RSP-4", "API-4"]
supersedes: null
---

# RFC 0033: People merge playbooks at runtime, made of the actions shoc has

## Summary

`playbook.merge` keeps a playbook a person wrote, in the shape of
`content/playbooks/`, per tenant in `shoc.merged_playbooks`. It loads with the
shipped playbooks wherever playbooks load: it takes the rules it names from the
playbook that answered them, the crew reads its questions on those rules' cases,
and the runner runs its steps. Its steps use the actions shoc already has, so a
new action is still a code change. `playbook.revert` takes it back, and its
rules return to the playbooks that had them. Amends D93, which left applying
content through the database to an RFC.

## Motivation

Since D48 and RFC 0032 a rule and a hunt pack can be added to a running
deployment, behind a gate. A playbook could only be added by editing
`SHOC_CONTENT_DIR` and deploying it (D93). For the company shoc is written for,
that is its one technical person rebuilding an image to change who is paged, or
what is suspended, when one rule fires. The actions a playbook calls already
exist, are typed, and are checked by the policy whoever proposes them.

The Detection Engineer met the same wall from the other side. Its gate refuses a
new rule unless a playbook can act on the rule's platform, and it could name
only a shipped one.

Binding merged rules also had a fault. A narrowing is a `merged_rules` row with
the shipped rule's id and no playbook, and `playbooks.load` removed every merged
rule id from its shipped playbook before adding it to the playbook its row
named. A narrowed rule was added to none: its cases matched no playbook, and the
crew no longer saw its questions.

## Design

**Shape.** The body is a playbook as `content/playbooks/` holds it, as JSON.
`playbook.list` returns each playbook in that shape, step parameters and worked
example included, so a shipped one can be copied, edited and merged under
another id. `shoc playbook merge --playbook-file ours.yaml` sends a YAML file as
it is. `policy.show` lists each action's required parameters and the platforms
it acts on.

**Binding.** A rule still belongs to one playbook. Playbooks load in three
layers: the shipped ones with their `rules`; a new rule merged here goes to the
playbook it was merged with (`merged_rules.playbook_id`); a merged playbook takes
the rules it names from whichever playbook answered them. A narrowing names no
playbook and keeps its shipped one. A merged playbook that no longer loads, an
action renamed in a release, is skipped with a warning, and its rules go back
where they were.

**The gate.** `playbook.merge` refuses, and names every reason:

1. a body that does not parse, an unknown action, a step with both or neither
   of `action` and `wait_minutes`, a placeholder for a rule it does not answer;
2. an id that is not lower_snake_case, or one that ships in `content/`;
3. a trigger whose verdicts are not `malicious` or `suspicious`, whose severity
   is not one of the five, or whose confidence is outside 0 to 1;
4. fewer than two questions, or two with one id (RFC 0013);
5. a step whose action needs a parameter the step does not give and the action
   cannot find for itself (its `resolve`);
6. a rule or hunt pack that does not exist here, or that another merged
   playbook names;
7. a required step that cannot run on the platform of a rule it answers (D53);
8. a rule taken from a playbook that can act on its platform, by one that
   cannot.

Merging an id merged before replaces it.

**Runs.** A run's steps are rows numbered by the playbook it started on.
Replacing or reverting a merged playbook cancels its open runs with the reason,
and the actions they proposed stay for a person to approve or reject. A run that
has ended answers `playbook.get` and `playbook.resume` without its playbook.

**Undo.** `playbook.revert` takes a merged playbook back. It refuses while a rule
merged here names it as its playbook, since that rule would be left with none:
merge another playbook that names the rule, or revert the rule, first. A shipped
playbook is out of reach.

**Who.** Both capabilities are human-only and audited, and need
`playbooks:merge`, which the `operator` role holds. No crew role is offered
them.

## What does not change

The autonomy policy decides every step, as it does for a shipped playbook. A
merged playbook cannot raise an action's level, lower its confidence or severity
floor, or approve an L2. Research before acting and review before blocking apply
to its steps as they are.

## Not done

The Detection Engineer does not write playbooks. When it does, the questions,
benign conditions and example of a playbook a model wrote reach the next case's
crew, so they will have to be quoted as data (principle 6). A person's are
content, as RFC 0013 treats the shipped ones. The console lists merged playbooks
with the others and has no form to write one.
