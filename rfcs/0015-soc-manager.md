---
rfc: 0015
title: Give the operator one contact, the SOC Manager
status: accepted   # as amended by D135
authors: ["@Rettila"]
created: 2026-09-28
requirements: ["AGT-3", "AGT-13", "AGT-14", "API-1", "API-3", "RSP-7"]
supersedes: null
---

# RFC 0015: Give the operator one contact, the SOC Manager

## Summary

The Reporter becomes the SOC Manager, and it is the only role that talks to the
operator. Every page, Slack post, pending decision and report goes through it,
and every question the operator asks is answered by it. Other roles and
playbooks stop reaching the operator directly and hand the Manager a notice
instead. The Manager does not assign work, close cases or approve anything. The
crew stays as RFC 0012 left it, and the operator gets one sender with one paging
budget.

## Motivation

The operator is the company's only technical person and does not open shoc most
days. Their attention is what makes a critical page work. Before this RFC, these
paths spent it or were specified to, each with its own rule:

| Sender | What reaches the operator | Rule it follows |
| --- | --- | --- |
| `worker._notify_slack` | A Slack post for every investigated case, whatever its severity | None: a configured channel gets everything |
| `worker._notify_if_waiting` | The same case message again whenever a playbook step waits on approval | None |
| All 14 playbooks in `content/playbooks/` | A `notify.page` step | `notify.page` is L1 with no confidence floor (`content/policy.yaml`) |
| IR Commander (`page_human`, `page_condition`) | A line in the case note; nothing sent it | Critical severity, or active and uncontainable |
| Ops (`page_human`, `page_reason`) | Specified in `docs/agents.md`; not built | Material coverage dark for long enough |
| `shoc/cases/unattended.py` | A page on a second deadline expiry | At most one per case per `PAGE_AT_MOST_EVERY_HOURS` |
| Reporter | The shift report every 12 hours (D52 replaced it with the exception report, which is not built yet) | None |

Only `unattended.py` checks whether a page already went out, and only for its
own case. The PagerDuty `dedup_key` falls back to the first 120 characters of
the summary, so two senders that describe one incident differently page twice.
On a leaked key, the containment playbook's page step fires, and the Commander's
`page_human` would have fired on the same evidence had anything sent it. The
case also posts to Slack once when
it is investigated and again when its rotation waits on approval. Wiring up the
Commander as specified would have made that two pages and two posts for one
incident, before a second rule adds a second case. A low-severity case that the Investigator closed as benign still posts
to Slack. The operator learns to mute the channel, and after that the critical
page has nobody reading it.

In the other direction, `ask` (`shoc/capabilities/ask.py`) is still the
deterministic v0.1 version. It pulls identifiers out of the question and runs
findings and event queries. It cannot ask the Investigator what a case
concluded, the Surveyor what a host is, or CTI what an address has done
elsewhere, even though AGT-9 made each of those a tool call.

## Guide-level explanation

The operator sees one sender. A night with an incident looks like this:

```text
03:12  [page]  Critical: AWS key AKIA…EXAMPLE used from 203.0.113.7 to read
               prod secrets. Key disabled (L1, 03:11). Rotation of role
               prod-deployer waits on you until 07:11, then the key stays
               disabled and the role's sessions expire.
               Cases C-4f1a, C-4f1b · events E1–E9
```

That is one page for two cases, one Commander proposal and two playbook page
steps. Nothing else posts that night. The low-severity cases closed on their own
appear in the weekly.

The operator types `/shoc <question>` in Slack, or calls `ask` from Claude over
MCP:

```text
> was anything read before the key was disabled?
Yes. Four GetSecretValue calls between 03:04 and 03:10, on
prod/db-password and prod/stripe-key. The Investigator's timeline on C-4f1a
cites them (E3, E4, E6, E7). Nothing was read after 03:11.
```

The Manager answered by calling the Investigator on C-4f1a, and the call is
recorded in that case's openspace.

A quiet week produces no message until the weekly.

## Reference-level explanation

### The role

`REPORTER` in `shoc/agents/roles.py` is renamed `MANAGER` (principal
`manager`, autonomy L0), and `ReporterOutput` becomes `ManagerOutput`. It keeps
the Reporter's tools and its rule that every figure comes from a query, and adds
`case.get`, `events.query` and `finding.list`. It gains the peer tools from AGT-9
(`ask_investigator`, `ask_ir_commander`, `ask_surveyor`, `ask_cti`, `ask_ops`).
Each of those runs with the called role's principal, as RFC 0012 requires. No
role declares the Manager as a peer. The only action it may cause is
`notify.page`.

It does not:

- open, assign, reprioritise or close a case. Closing stays with whoever held
  the case last (D51);
- change a verdict, a severity or a proposal;
- approve or reject an action;
- sit between a human and the registry. Approvals, `openspace.inject` and
  `memory.add_fact` stay direct capabilities, so a broken Manager cannot block a
  human decision.

### Notices replace direct sends

A notice is a row in a new table, `shoc.notices`:

```sql
tenant_id, notice_uid, source, case_uid, group_key, kind, severity, condition,
body, citations, created_at, delivered_at, outcome, delivered_uid
```

`kind` is one of `page`, `decision` or `digest`. `condition` is required for
`page` and takes the three values the specs already name:
`critical_severity`, `uncontainable_and_active` and `coverage_dark`, plus
`deadline_expired` for `unattended.py`. A `page` told without one is stored as a
`digest`. `group_key` is the case's entity, or `source:<name>` for a dark
source. The same notice told twice on one day is one row.

The senders change as follows:

- The Commander's `page_human` writes a `page` notice with its
  `page_condition`.
- Ops' coverage check runs as a query in the hourly `ops.check` job: a source
  failing or stale for `COVERAGE_DARK_HOURS` (24) writes a `coverage_dark`
  notice. The Ops role still runs without its model (the D47 gap), so the query
  does not wait for it.
- `notify.page` from any principal other than the Manager, whether a playbook
  step or a crew proposal, becomes a `page` notice when it executes, instead of
  a call to PagerDuty. The condition is `critical_severity` on a critical case,
  and none otherwise. The step still succeeds, so playbooks need no edit.
- With no model configured, each new case is told to the Manager as a
  `critical_severity` page. Only a critical case passes the gate.
- `unattended.py`'s `_page` writes a `page` notice with `deadline_expired`.
- A pending L2 writes a `decision` notice that carries its fallback and window
  (RSP-7).
- `_notify_slack` and `_notify_if_waiting` are deleted. A case no longer posts
  itself.

Writing a page notice queues `manager.deliver` (the jobs table, `SKIP
LOCKED`). `unattended.py` delivers inline, because whether a page went out
decides whether the action it chased gets a second window.

### Delivery

`manager.deliver` works in two stages.

1. **The gate is a query, not a model.** It groups undelivered `page` notices by
   `group_key`, so notices on one case, or on cases with the same entity, are one
   incident. For each group:
   - `critical_severity` counts only if the case is critical when the gate runs.
     Otherwise the notice becomes a digest.
   - A group pages when nothing with the same key paged in the last
     `PAGE_AT_MOST_EVERY_HOURS` (24). Otherwise its notices are recorded as
     `merged` into the earlier page.

   `decision` notices on a paged group's cases are marked as carried by that
   page, and the Slack mirror shows their Approve buttons. The rest are listed in
   the weekly, and their fallback runs when the window expires either way.
2. **The model writes the text.** Given the group, the Manager writes one
   message with the case, action and event citations. If the model is
   unconfigured, fails, or returns text whose citations do not verify (D25), a
   fixed template goes out instead. A page is never late because of the model.

The message goes to PagerDuty through the existing `notify.page` action, with the
group's `dedup_key`, and is mirrored to the Slack channel when one is set. Every
notice in the group records the `action_uid` in `delivered_uid`, so the audit log
shows which senders one page stood for.

The weekly and monthly reports are built as the Reporter built them, and gain a
`held` section: digests and the decisions no page carried. The 12-hour
`report.shift` job is removed. The exception report (D52) is still not built,
and stays listed as a gap in `docs/prd.md`.

Slack text the Manager writes, and the log-derived fields of a case message, go
through `slack.escape`.

### Questions

`ask` becomes the Manager's inbound path. With a model configured, the question
goes to the Manager with the read capabilities and peer tools listed above. The
answer uses the existing `Answer` shape, with `intent = "manager"` and a
`consulted` list naming the roles it called. When a question names a case
(`CASE-…`), the Manager reads that case's dossier and the peer exchange is
written to its openspace. Peer calls share the per-case ceiling
(`MAX_PEER_CALLS`). An answer about a case, or about a key, address, account
or finding the question names, falls back to the deterministic path when none of
its event citations survive the store; so does a model failure, or no model at
all. An answer about the deployment itself (rules, sources, health, cost) comes
from the Manager's lookups and needs no events (D135).

`/shoc <question>` in Slack already calls `ask`, so Slack questions reach the
Manager with no new handler.

### Principles touched

Principle 1: `ask` stays one capability, and the surfaces are unchanged.
Principle 5: the Manager proposes only `notify.page`, and the gate is not a model.
Principle 6: a message whose citations do not verify falls back to the template.
Principle 7: `shoc.notices` carries `tenant_id` and RLS like every other table.

## Drawbacks

- Every page takes one extra hop, a notice row and a job, before PagerDuty sees
  it. With `LISTEN/NOTIFY` still unbuilt (AGT-1 gap) that hop is one worker poll
  interval. The gate runs in the same job as the send, so there is no second
  poll.
- Anyone who watched the Slack channel to see every case loses that view. The
  cases are still in the console, over REST and over MCP.
- Grouping by shared entity can merge two unrelated incidents on a busy entity,
  such as a CI service account. They get one page instead of two. That is the
  safer error here, and the merged page names both cases.

## Alternatives

- **A twelfth role next to the Reporter.** Two roles would write to the same
  reader, and the Reporter's reports would still need to know what the Manager
  paged. Folding them into one role avoids both problems.
- **Bring back the Orchestrator as the manager.** RFC 0012 deleted it because a
  role that dispatches and converges the crew was the slow path. The operator
  needs one voice, and the crew does not need a dispatcher.
- **Dedupe inside `notify.page` only.** That fixes duplicate pages. It does not
  stop every case posting to Slack, does not route pending decisions, and does
  not give `ask` the crew.
- **Do nothing.** The channel gets muted, and the critical page goes unread.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: role `Reporter` is renamed `Manager`
  (`ReporterOutput` → `ManagerOutput`, which gains the delivered message and its
  citations). `Answer` gains `consulted`. There is a new table `shoc.notices`
  and a new job kind `manager.deliver`, and `report.shift` is removed.
  `slack.notify` is no longer called per case. `contract/v1.json` is updated in
  the same commit. This lands before the v0.4 freeze.

## Security considerations

**The Manager decides what the operator sees, so it can hide things.** For that
reason the page gate is a query over typed conditions and the model has no veto.
An agent that was misled by log content can change the wording of a page, but it
cannot stop the page. A role can still skip writing a notice, as it can skip
setting `page_human` today. `unattended.py`'s second-expiry page stays the
backstop for that.

**Log content reaches a pager and a chat channel.** Notices reach the model only
inside `safety.quote()`. Slack text goes through `slack.escape`, which escapes
`&`, `<` and `>`, so `<!channel>`, `<!here>`, user mentions and link markup
arrive as text. A log line cannot ping the workspace or disguise a link.

**Peer calls from `ask` are a new path into the crew.** They run with the called
role's principal and scopes, never the caller's. Through them an `ask:read`
caller reaches the reads the crew holds, which is wider than the query path
(events, findings, cases). An answer about a case or a named entity is still
cited (D135), the `ask` call is audited, and a question about a case leaves the
exchange in its openspace.

**`notify.page` is the only action the Manager proposes.** A compromised Manager
can page or stay quiet. It cannot contain, rotate or approve anything.

## Resolved questions

- **Notices get their own table.** Treating a notice as a `proposed`
  `notify.page` action would save a table, but "proposed" would then mean two
  things in an approval flow that already has one meaning for it.
- **The grouping window is 24 hours for every severity.** It matches
  `PAGE_AT_MOST_EVERY_HOURS`. A window per severity is more to tune, with no
  case yet showing it would page better.
- **There is no setting that restores one Slack post per case.** Cases are in
  the console, over REST and over MCP, and a channel that gets every case is
  the channel that gets muted.
- **Email is left to a later RFC.** This RFC covers PagerDuty and Slack, the two
  channels that exist today. Email (L7 in `architecture.md`) will go behind the
  same gate once it is built.

## Unresolved questions

None.

## Adoption and migration

Forward-only, in dependency order:

1. Migration for `shoc.notices`. The `Reporter` → `Manager` rename in
   `roles.py`. Nothing outside the file used the old names, so no alias is
   kept.
2. `manager.deliver` with the gate and the template, no model yet. Point
   `unattended.py`, the Commander, Ops and the `notify.page` playbook step at
   notices.
3. Delete `_notify_slack`, `_notify_if_waiting` and `report.shift`.
4. The model-written message and citation check.
5. `ask` through the Manager.

Existing installs keep their delivered pages and past Slack messages as they
are. Notices start with the migration. Nothing already sent is backfilled.
Migration 022 also deletes the `report.shift` schedule and any pending
`report.shift` or `slack.notify` jobs. `docs/agents.md`, `docs/architecture.md`
§5, `docs/decisions.md` (D58) and `docs/prd.md` (AGT-14) change with it.
