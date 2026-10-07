---
rfc: 0032
title: The Hunter turns its backlog into packs, behind a gate
status: accepted
authors: ["@Rettila"]
created: 2026-10-06
requirements: ["DET-8", "DET-9", "AGT-3", "AGT-10", "SEC-2"]
supersedes: null
---

# RFC 0032: The Hunter turns its backlog into packs, behind a gate

## Summary

Once a day, before the packs run, the Hunter takes the top three open items of
its hunt backlog, one model turn each. It ends each item as `packed`, `covered`,
`not_worth`, `source_gap` or `later`. To pack an item it writes a pack in the
shape of `content/hunts/` and calls `hunt.merge`. The gate keeps the pack only
when it parses, a connected source sends its product, its own fixtures surface
and silence it, and it returns no more tuples over our data than triage can
read. A merged pack is kept per tenant in `shoc.merged_hunts`, runs with the
shipped packs, and its first concluded run marks the item `done`. Amends RFC
0005's boundary and RFC 0022.

## Motivation

On the main instance on 2026-10-06 the hunt backlog held 28 items, all `open`:
26 suggested by threat reports CTI digested, one from a person and one from a
pack that returned 210 rows. Nothing read the backlog. `hunter.select()` picks
from `content/hunts/` only, and no code moved an item out of `open`, although
the schema has had `packed`, `rejected` and `done` since migration 013. Every
report CTI keeps adds up to ten more.

RFC 0005 drew the line at "a model never writes a query". It kept a model from
choosing what to look at during triage, where the data it reads was written by
whoever we are investigating. A pack written from a backlog item comes from a
report or a person, and it is checked by code before it runs. The risk RFC 0005
guarded against is a query nobody tested. The gate tests every one.

## Design

**Who.** The Hunter, on a second turn with its own tool list: `hunt.merge`,
`events.query`, `events.summarize`, `memory.search`, `hunt.results`,
`rule.list`. Triage keeps its read-only list and never sees `hunt.merge`
(`tools.WRITES["Hunter"]`).

**When.** The worker's `hunt.daily` job calls `hunt.work` first, so a pack
merged in the morning runs in that day's cycle as "never run here". Three items
a day, priority first, under a ceiling of 300,000 tokens a day.

**Outcomes.**

| Outcome | Accepted when | The item |
| --- | --- | --- |
| `packed` | `shoc.merged_hunts` holds a pack for it; the model saying so is not enough | `packed`, then `done` after the pack's first concluded run |
| `covered` | Always; the pack or rule named is kept | `rejected`, `covered_by` |
| `not_worth` | Always | `rejected` |
| `source_gap` | Always; the products named are kept | `rejected`, reopened when a source sends one of them |
| `later` | Always | stays `open`; the third time it is `rejected` as `stuck` |

**The gate (`hunt.merge`).**

1. The pack parses and compiles, its id is lower_snake_case and no pack here
   has it, it names ATT&CK and a product, and it has a baseline.
2. Its readiness is not `not_applicable`.
3. In a scratch tenant, its `surfaced` fixture comes back, and once its
   `baseline` fixture was ingested first (ten days earlier for `first_seen`),
   the surfaced records do not. This is the test every shipped pack passes in
   `tests/conformance/test_hunts.py`.
4. On a ready pack, one window over our own data returns at most 200 tuples.

A refusal names which step failed, and the model can fix the pack and call
again within its turn.

**Undo.** `hunt.revert` takes a merged pack back; it stops running and its item
is `rejected`. A shipped pack is out of reach. A person with the `operator` role
holds `hunts:merge`.

## What does not change

Triage reads tuples with read-only tools and code checks its verdicts. A hunt
raises a low finding, never a case. A pack becomes a rule only through the
Detection Engineer after two confirmed true positives, and that now includes
packs the Hunter wrote.

## Not done

A pack the Hunter wrote is not reviewed by a person before it runs. Its
findings are low and go through the crew like any other, and the weekly
digest names every merge and revert.
