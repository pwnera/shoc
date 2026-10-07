---
rfc: 0010
title: The openspace, peer requests and interruptions
status: superseded in part by RFC 0012   # built: the rename, the three kinds, to_agent; replaced: rounds, routing by domain terms, per-round caps
authors: ["@Rettila"]
created: 2026-09-25
requirements: ["AGT-1", "AGT-2", "AGT-9", "SEC-2"]
amends: ["RFC 0003 (case-room protocol): renames the room and adds three message kinds"]
---

# RFC 0010: The openspace, peer requests and interruptions

## Summary

The case room becomes the **openspace**, and two things become possible inside
it. An agent that needs something another role knows asks that role directly, and
gets an answer in the same openspace. An agent that was not scheduled to speak
this round interrupts when what was said reaches its own subject. The round order
of RFC 0003 still runs; these are the moves that happen off it.

## Motivation

RFC 0003 fixed the shape of a case discussion in code, which is what keeps it
debuggable and cheap. It also made every agent's knowledge reachable only by
whoever the script called next. Two costs have shown up in that:

- The Investigator infers what an address is to this company from the attack
  narrative, because Operator is only consulted when an action is already up for
  review (RFC 0006 §2 split Operator out for the same reason, one layer later).
  Asking is one model call; a verdict built on a guess about the office IP is a
  wrong disposition and a suppression in the wrong place.
- CTI reads reports and never hears the case that its report is about. Nothing in
  the loop lets a role say "this is my subject" unless a human notices and posts
  a `request` by hand.

The openspace name follows from that: what the table holds is not a booked room
with an invited list, it is a floor anybody on the crew can speak from.

## Guide-level explanation

```
round 1  Sentinel    observation  Key for deploy-ci used from 203.0.113.55, then a ListBuckets burst [E1]
         Investigator hypothesis  Stolen key, malicious, 0.74 [E1,E2]
         Investigator request →Operator  Is 203.0.113.55 ours?
         Operator    answer →Investigator  It is not. Our egress is 198.51.100.0/24, and nothing deploys from that ASN
         CTI         interject   That address is on the abuse.ch feed as of yesterday [E2]
round 2  Challenger  challenge   A CI runner that moved hosts would look like this
         Investigator evidence   The key is in a public gist, 06:02 [E5]. malicious, 0.93
```

A human does the same thing by hand:

```bash
shoc openspace post CASE-1a2b… "Is 203.0.113.55 ours?" --kind request --to Operator
```

Nothing about the fixed part changes: Sentinel still opens without a model, the
Challenger still runs only on high and critical cases, and the Orchestrator still
closes.

## Reference-level explanation

**Naming.** `shoc/agents/room.py` becomes `shoc/agents/openspace.py`,
`shoc.room_messages` becomes `shoc.openspace_messages`, `room.post` becomes
`openspace.post` (`POST /v1/openspace/post`, MCP `openspace_post`, `shoc
openspace post`), and the `room.message` event type becomes
`openspace.message`. Migration `014` renames the table rather than recreating it,
so policies, indexes and the foreign key to `cases` survive and no message moves.

**Three kinds.** `request`, `answer` and `interject` join the eight in RFC 0003.
`request` and `answer` are addressed: a new `to_agent` column holds the role a
request is for, or the role an answer replies to, and a message of those kinds
without it is refused. `interject` is not addressed; it is for the openspace.
None of the three is in `MUST_CITE`: a question is not a claim, and an answer
about the company's own infrastructure is argued from memory and the graph rather
than from an event. Citations they do carry are validated as any other.

**Who answers.** The role named in a `request` answers it, through the same
`RemarkOutput` schema as an interruption: a body, citations, a confidence and a
`speak` flag. `speak: false` is a valid turn; silence beats padding.
`openspace.pending` finds requests with no answer from the named role, so an
openspace can be resumed and the Orchestrator can see what is still outstanding.

**Who interrupts.** Each `Role` declares a `domain`: the terms that mean the
discussion has reached its subject. `roles.interested(text, exclude)` is a
substring test over those terms, so routing costs nothing and is inspectable: no
model decides who cares, and a term is a one-line change. A role that has already
had the floor in this case is excluded, as are Sentinel and the Orchestrator.

**What it may cost.** Two requests served per round, one interruption per round,
six peer turns per case, and the openspace's existing round, token and wall-clock
budget checked before every peer turn. An exhausted budget stops peer talk first
and the scheduled roles last, so a case cannot talk itself out of a verdict.

**Principles.** Principle 5 (bounded autonomy) is unchanged: peers still only
read and speak, the playbook runner still acts. Principle 6 is unchanged: the
kinds that make claims still cite. Principle 3 is unchanged: no dependency, one
migration, one new column.

## Drawbacks

More model calls per case, and the caps are judgement rather than measurement.
Term matching is blunt: it will invite CTI to a case that says "campaign" about a
marketing campaign, which costs one call and one silent turn. A role can also be
asked something it cannot answer, which is a wasted call, visible as an `answer`
that says so.

## Alternatives

- **Do nothing.** The Investigator keeps guessing about the company's own
  infrastructure, and CTI keeps not hearing the cases its reports are about.
- **Let a model route.** An extra call per message to decide who is interested,
  spent before anybody says anything. Rejected on cost and on debuggability.
- **Every role speaks every round.** Six model calls a round for a medium case
  that needed one.
- **Free-form agent-to-agent messaging with no schedule.** Rejected: the fixed
  round order is what makes a transcript replayable as an eval, and an
  unscheduled chat has no budget that a reader can predict.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: `room.post` → `openspace.post` with a `to` field and
  three more kinds; `room.message` → `openspace.message`; `case.investigate`
  reports `requests` and `interjections`; `case.get` returns `to_agent` on each
  message.

## Security considerations

A request body and an interruption trigger both come from text that quotes logs,
so an attacker who controls a log field can try to have a role summoned. What
that buys is one read-only model call by a role that holds no credentials; the
term list is fixed in code, not learned from content, and the per-round and
per-case caps bound the spend. Peer messages are audited like any other, and
`speak: false` leaves nothing in the transcript. `openspace.post` keeps its
`cases:write` scope and its principals, so an external agent may ask and answer
but still cannot approve or act.

## Unresolved questions

Whether domain terms belong in code or in per-tenant configuration once a company
has taught the crew its own vocabulary. Whether an unanswered request should keep
an openspace open past its round budget. Whether the caps should scale with
severity as the round budget does.

## Adoption and migration

Migration `014` renames the table and adds the column and the kinds; existing
transcripts read unchanged, with an empty `to_agent`. Callers of `room.post` have
to move to `openspace.post`: the contract snapshot changes in the same commit, and
v0.4 has no external installs to deprecate against.
