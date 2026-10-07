---
rfc: 0022
title: The Hunter runs reviewed packs on data that can answer them, and triages with read-only tools
status: accepted
authors: ["@Rettila"]
created: 2026-10-02
requirements: ["DET-8", "DET-9", "DET-11", "DET-4", "AGT-3", "AGT-10", "AGT-13", "SEC-2"]
supersedes: null
---

# RFC 0022: The Hunter runs reviewed packs on data that can answer them, and triages with read-only tools

## Summary

Code runs every hunt pack whose data is ready, over what was ingested since its
last window. One Hunter turn a day reads what came back with read-only tools and
each pack's follow-up questions; code accepts an explanation only on a basis it
can check. A suspicious tuple becomes a low finding, never a case. A pack on
data nobody sends is *not applicable*, a pack on a source that started less
than its lookback ago is *learning*, and a zero-row run on a ready pack is
`clear`. Amends RFC 0005, RFC 0006 §1, RFC 0012, the RFC 0020 triage line, D54's
coverage source, and PRD DET-8, DET-9 and DET-11.

## Motivation

The live Hunter, read on 2026-10-02:

- The three packs read AWS CloudTrail and Okta; the company connects Cloudflare,
  GitHub, Google Workspace and Tailscale. `select()` never checked a source, so
  every run queried lab replays that stopped on 09-27, returned 0 rows in under
  50 ms, and recorded `clear`, which the daily summary and the weekly called
  coverage.
- "Once a day" compared a rolling 24 hours with a timestamp written after
  triage, so runs landed every other day, and each window was "now minus one
  day": the skipped days were never hunted.
- It opened cases itself with untyped entities, so it never joined the open
  case on the same key. Four hunt-opened cases cost 3.15M tokens against 10k for
  the hunts' own triage; one re-investigated a leaked key already in a case.
- Triage was one prompt with no tools that said "if you are unsure it is
  suspicious", and the rows left out the event type.
- `roles.HUNTER` described a Hunter that plans, has no `clear` and opens no
  case; `hunter.py` did the opposite, and 4 of its 11 tools did not exist.
- Promotion counted "suspicious" runs: a pack was proposed as a rule seven
  minutes before its case closed benign. `hunt.run` turned any address somebody
  searched for into a "known-bad" finding.
- The "rare" baseline ignored its lookback, and first-seen history ignored the
  pack's product.

How hunters work: a hunt on missing data is failed, not disproven (TaHiTI);
baselines need 30 to 90 days (PEAK); doubt ends as inconclusive, after follow-up
queries that rule out admins, developers and the defenders' own tools (MITRE
TTP-based hunting, 2.4.3.3); hunters hand over to the incident team rather than
becoming it (TaHiTI 4.4.2); a hunt becomes a rule only on confirmed true
positives (PEAK). The model works around a reviewed query rather than writing it
(OTRF agent skills, the PEAK Assistant).

## Guide-level explanation

```
$ shoc hunt results
aws_identity_first_api_call          not applicable  no connected source sends AWS CloudTrail
gws_admin_first_console_operation    learning        until 2026-10-30
tailscale_principal_first_operation  ready           clear
github_identity_first_push_to_repo   ready           inconclusive: who owns deploy-bot
```

A pack declares what to check before an explanation counts, and whether a
second inconclusive is enough to raise a finding:

```yaml
follow_up:
  - Did the same account sign in from a new address or country that day?
sensitive: true
```

For each tuple the Hunter returns `explained`, `inconclusive` or `suspicious`.
`explained` names its basis: a memory fact a person wrote (`human_fact`), shoc's
own credential or the company's automation (`own_credential`), or an event from
before the window that one of its queries returned (`older_event`). Anything
else is inconclusive. `suspicious` cites events. An inconclusive tuple is read
again the next day with what was missing named.

## Reference-level explanation

- **Readiness**, per pack, from `shoc.source_history` joined to configured
  sources: not applicable, learning until first event + lookback, stale when no
  source delivered within the pack's window (a `gap` with the reason), or ready
  with the accounts those sources speak for. Readiness is kept on
  `hunt_packs.readiness`. A ready pack falling back because its source went
  stale is a `coverage_dark` page grouped with that source's coverage page; one
  whose source was removed is a Manager digest. A `gap` is a `hunt.gap` Ops
  alert, not a hunt backlog item.
- **Windows** follow `ingested_at` from `hunt_packs.ingested_through`, capped at
  the lookback; a window advances only when the run concluded. First-seen
  history is what was ingested before the window, from the same products and
  accounts; a failed attempt (`status` Failure) is not history, so a denied
  call does not make the successful one familiar. "Rare" counts principals
  over the whole lookback.
- **Triage**: one `complete_typed` call over every tuple of the day, tools
  `events.query`, `events.summarize`, `memory.search`, `finding.list`,
  `case.list`, `graph.neighbours`. With no model, or a failed one, nothing is
  triaged and the window is read again. Past 200 tuples a pack's first 200 in a
  fixed order are triaged and the rest are recorded as too broad. The turn has
  a daily token ceiling, `hunt_tokens_per_day` in `llm.configure` (200,000 by
  default): packs join it in agenda order while their tuples fit in half of
  what is left, a pack that does not fit is a `gap` read again the next day,
  and the turn stops calling tools once the rest is spent.
- **Routing**: a suspicious tuple is a `low` finding `hunt:<pack>` with `user:`,
  `key:` and `host:` entities only; if an open case from a rule already names
  that actor in the same days, the rows become a note on that case. A case only
  hunt findings opened carries a lifetime ceiling of 150k tokens. The Hunter
  opens no case, writes no memory and pages nobody.
- **Promotion** counts closed cases of a pack's findings that were malicious, or
  suspicious by a person's close.
- **Agenda**: techniques from configured intel feeds (validated, at most 20) and
  from this week's cases that a rule opened. Every due pack runs; the agenda
  orders them.
- `hunt.run` returns its hits and writes no finding.
- Outcomes are `clear`, `explained`, `inconclusive`, `suspicious` and `gap`.
  `not_applicable` and `learning` record no run.

## Drawbacks

- On the day it ships, packs on the company's sources are learning until about
  30 October. Detection rests on rules until then.
- One turn a day reads every pack's tuples, so one bad turn delays all of them
  by a day; the windows do not move, so nothing is lost.

## Alternatives

- **Let the model write the query.** Rejected: unreviewable, and RFC 0005's
  boundary stands.
- **A known-benign tuple table.** Not now: first-seen never resurfaces a tuple,
  and a model-written allowlist is a suppression (D46).
- **A 30-day backfill on connect.** Rejected: it would end learning on day one
  and fire every rule on a month of old admin changes.
- **The CTI peer.** Not now: it would carry `intel.digest` egress into an
  unattended job.
