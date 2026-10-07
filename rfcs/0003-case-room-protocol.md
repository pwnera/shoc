---
rfc: 0003
title: The case-room protocol
status: superseded   # by RFC 0010 (the openspace) and RFC 0012 (no rounds, no Orchestrator)
authors: ["@Rettila"]
created: 2026-09-24
requirements: ["AGT-1", "AGT-2", "SEC-2", "DET-3"]
---

# RFC 0003: The case-room protocol

> **Superseded.** The room is the openspace of RFC 0010: the table is
> `shoc.openspace_messages`, people post with `openspace.post`, and `request`,
> `answer` and `interject` joined the eight kinds below. RFC 0012 removed the
> Orchestrator and the rounds. `shoc/agents/loop.py` runs a fixed order (the
> Investigator, the Challenger, the Investigator again, the IR Commander when
> there is a response), a role calls CTI or the Surveyor directly, and whoever
> held the case last closes it. `round` survives as the turn number on a
> message, and the budget still caps turns, tokens and wall time and ends in a
> decision when it runs out. Agents do not wake on `NOTIFY`; the worker runs
> `case.investigate` as a job.
>
> Still true from this RFC: one table, append-only except that an identical
> re-post is counted on the message it repeats; a kind outside the list is
> refused at the capability boundary; `hypothesis`, `evidence` and `decision`
> need citations that exist in the store; log text reaches a prompt only as
> quoted data; agents only propose, and the playbook runner acts.

## Summary

Each case gets a room: one Postgres table of typed, cited messages that agents
and humans post to in rounds. An Orchestrator opens and closes rounds and stops
the discussion when it converges or hits a budget. Agents wake on
`LISTEN/NOTIFY`. This RFC fixes the message types, the round and budget rules,
the citation requirement and how a human injects a fact, so that v0.2 can build
the crew without renegotiating the protocol.

## Motivation

A single-model verdict on a security incident is confidently wrong too often. A
structured disagreement, where an Investigator proposes, a Challenger is required to
offer a benign explanation, a human able to inject one fact that invalidates
both, produces verdicts we can defend, and a transcript we can audit and replay
as an eval. Putting it in one table rather than a framework keeps it debuggable
and keeps the dependency budget intact.

## Guide-level explanation

A room is a case. Messages look like this:

| Round | Agent | Kind | Body | Cites |
| --- | --- | --- | --- | --- |
| 1 | Sentinel | observation | Access key for deploy-ci used from a new ASN | E1 |
| 1 | Investigator | hypothesis | Stolen key, malicious, 0.80 | E1, E2 |
| 2 | Challenger | challenge | Could this be the CI runner moving hosts? | none |
| 2 | Sam K. (human) | inject | No CI migration is planned this quarter | none |
| 2 | Investigator | evidence | Key found in a public gist at 06:02 | E5 |
| 3 | Orchestrator | decision | Run L1 now, ask for L2 approval | E1–E5 |

Humans join from Slack or any MCP client through `room.post` and `room.inject`,
with the same message types as agents.

## Reference-level explanation

- **One table, `room_messages`:** `(tenant_id, case_id, round, agent, kind,
  body, cited_event_uids[], created_at)`, append-only.
- **Kinds:** `observation`, `hypothesis`, `evidence`, `challenge`, `concede`,
  `proposal`, `decision`, `inject`. Anything else is rejected at the capability
  boundary, so a model cannot invent a message type.
- **Rounds and budgets, per room:** maximum rounds, maximum tokens, maximum wall
  time. Low severity gets one round and no Challenger; critical gets up to five.
  Exhausting a budget is a `decision` of `needs human`, never a silent stop.
- **Citations:** a `hypothesis`, `evidence` or `decision` without
  `cited_event_uids` is downgraded to `needs human` (principle 6). Citations are
  validated against the store, so an event UID that does not exist fails the
  message.
- **Untrusted content:** log text reaches a prompt only inside a quoted data
  block, never as instructions (SEC-2). An agent's output is schema-checked
  before it becomes a message.
- **Wakeups:** `NOTIFY shoc_room_<case_id>`; agents never poll.
- **Actions:** agents may only `propose`. The playbook runner acts, after the
  autonomy policy check, and `L2` requires a human principal.

## Drawbacks

Rounds cost tokens and latency: the debate is the expensive part of a case. The
protocol also assumes agents are honest-but-fallible; it defends against
confusion, not against a compromised model with action credentials, which is
why agents never hold them.

## Alternatives

- **A single investigator prompt.** Cheaper, and measurably worse on ambiguous
  cases; no transcript to audit.
- **LangGraph or CrewAI.** Rejected on principle 3, and because the round and
  budget semantics we need are a few hundred lines we would rather own.
- **A message queue between agents.** Rejected: Postgres `LISTEN/NOTIFY` plus a
  table is enough at our volumes and keeps the required-service count at one.

## Dependency and scope impact

No new dependencies. New tables in a forward-only migration. `room.*`
capabilities join the public contract in v0.2.

## Security considerations

Room content is attacker-influenced by construction, because it quotes logs. It is
therefore treated as data everywhere downstream, agents get read-only database
roles, and every message, tool call and action is written to the hash-chained
audit log.

## Unresolved questions

Token accounting across providers; whether an external agent joining over MCP
needs a distinct message kind; how corrections become eval cases automatically.

## Adoption and migration

v0.2 ships the room, the first five roles and the eval harness. v0.1 has no
rooms, so there is nothing to migrate.
