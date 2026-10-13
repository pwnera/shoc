# Running it

What shoc tells you about itself, what it costs, and the jobs it runs on its
own.

## The worker's schedule

`shoc worker` claims jobs from Postgres; one worker is also the cron leader.
Every tenant `shoc migrate` has registered gets these schedules, and the leader
adds a newly migrated tenant's on its next pass. Every job runs as a
capability call, scope-checked and audited like a person's. Out of the
box:

| Every | Job | What it does |
| --- | --- | --- |
| Once a cycle, or the source's longer interval | `source.sync` | Pull a connector; what it loaded wakes detection |
| 15 minutes (`SHOC_CYCLE_SECONDS`) | `detect.run` | Rules, IOC matching, open cases |
| 1 minute | `stream.deliver` | Push events to signed webhooks; queued only for a tenant with an enabled webhook |
| 15 minutes | `case.sweep` | Send the crew back to every open case with something new; the retry clock for a failed run |
| 30 minutes | `unattended` | Resolve what nobody approved: page, or abandon with a reason |
| 1 hour | `ops.check` | First the page decisions (dark sources, stopped detection, disk, model outage) and the audit chain, then Ops' alerts and review and the Integrator's wake-up; a heartbeat after ([below](#the-hourly-check)) |
| 6 hours | `intel.refresh` | Pull feeds and retro-hunt what is new |
| Daily | `hunt.daily` | Every due pack on ready data runs; one Hunter turn triages what came back |
| Daily | `detection.backlog` | Sweep every intake, expire suppressions, lapse old narrowings, work the backlog |
| Weekly | `report.weekly` | Build the weekly report and send it to Slack and the stream, with every digest held for it |
| 30 days | `report.exec` | Build the executive report and send it to Slack and the stream |
| Daily | `report.exception` | Build the exception report, sent only when a decision needs a person (D52) |
| Weekly | `case.recheck` | Read again the crew's benign closures, the ones waiting to change a rule first |
| Daily | `posture.survey` | The Surveyor refreshes exposures from 30 days of events |
| Daily | `source.onboard` | The Integrator moves each source towards `done` |
| Daily | `graph.refresh` | Rebuild the world graph from 30 days of events |
| Daily | `retention` | Drop events past the retention window: whole months on Postgres, which keeps up to about 31 days more, and expired rows from its default partition. Create this month's and next month's partitions. Prune the copies of events and finished jobs ([what is kept](deploy.md#retention)) |

`manager.deliver` has no schedule: a page notice queues it, and the Manager
decides whether one page goes out.

The schedules are for what depends on the clock. What happens wakes the agent it
concerns through `engine.WAKES` (RFC 0034), folded into one run per window:

| Event | Wakes | Within |
| --- | --- | --- |
| A case opened or gained a finding; a person's message or an Ops nudge on it; an action on it ran, was undone or was rejected by a person | `case.sweep`, which sends the crew | 10 seconds |
| CTI kept a report from a configured source or one a person handed in | `hunt.daily` and `detection.backlog` | 10 minutes |
| A source loaded rows, pulled or pushed (GitHub's webhook) | `detect.run`, once for the cycle's polls | 1 minute on Postgres; on a warehouse a push waits in `shoc.push_spool` and is read with the next detection cycle |

The sweep leaves a case the crew is already queued or running on, and the
Hunter's and the Detection Engineer's extra runs stop at the same daily token
ceilings as their scheduled ones.

Scale by running more workers: jobs are claimed with `SELECT … FOR UPDATE SKIP
LOCKED`, so they never collide. The cron leader holds a Postgres advisory lock
for as long as its session lives; every other worker asks for the lock on each
pass, so when the leader's pod dies or a rolling update replaces it, another
worker takes the lock on its next pass. When the leader's node is lost or cut
off, nothing closes its session; the lock holder asks Postgres for TCP keepalive
probes, so the server drops the session and the lock within about 90 seconds.
A schedule queues no new job while its last one has not run.

A worker claims one job at a time, most urgent first (D191). Tier 0 is
`manager.deliver`, `action.run`, `action.expire` and `stream.deliver`; tier 1
is `detect.run`, `source.sync`, `playbook.run`, `playbook.resume`, and
`case.investigate` on a high or critical case; tier 2 is everything else.
Within a tier the oldest goes first, and the leader's tick and sweeps run
between any two jobs. `shoc worker --urgent` is the fast lane and claims only
tiers 0 and 1; Compose ships it as the `worker-urgent` service and the chart as
the `-worker-urgent` Deployment (`worker.urgentReplicas`, 1 by default, 0 turns
it off). Add ordinary workers for more model throughput. `shoc worker --once`
runs up to four due jobs and exits.

Each worker process is named `hostname:pid` plus a random suffix, so a
container restarted in place does not inherit its predecessor's jobs (D192).
It renews its running job's lease every 60 seconds on a connection of its own.
The leader takes back a job whose lease is 30 minutes old or whose worker has
no session left, and a job lost five times is parked as failed with
`the worker running it was lost, after N attempt(s)`, which the `jobs.failed`
alert reports. A worker that reconnects to the database takes back its own job
at once. A query error on a live connection (a timeout, a deadlock, a lock
wait) fails the job and counts towards parking; only a lost connection makes
the worker reconnect. A worker whose one job has run for 30 minutes is stuck,
and exits so that its lock frees and its supervisor restarts it. On `SIGTERM`
a worker finishes the job in hand and takes no other; Compose and the chart
give it 90 seconds.

Two of these exist because nobody is watching. `case.sweep` asks which open cases
have something new since the crew last worked them (a detection, a completed
action, a fact somebody posted) and sends the crew back; the events above wake it
at once, and its schedule catches a run that failed. `unattended` gives a deadline to everything whose
resting state was an approval, and it is the reason a running install needs no
clicks. Both are idempotent.

While the model provider is failing, the sweep stands down rather than spend a
case's retries on an outage, and `unattended` still nudges but holds every
stalled case: it neither closes one nor pages for it (D245). A high or critical
case is still paged on its own until the outage page is due. The Manager then
pages once, `coverage_dark` in group `llm`: at once when the provider refuses
the key or the credit (401, 402, 403), and otherwise after 6 hours with no
answer; on a tenant no model has ever answered, the 6 hours count from its
first recorded failure. The provider is failing only while no model has answered since the
latest failure, and a reply that failed its JSON schema still counts as an
answer (D199). The Manager's own 20-second cut-off on a page's wording is not a
provider failure. A case below high that the crew tried and never read is held,
not closed. A deadline is set by the worse of the case's severity and its worst
finding's, since the Investigator may lower the case's own (D165).

No shift report is sent (D52). The Manager pages on six typed conditions, and
what it did not page for is held for the weekly report (RFC 0015).

## Pages

A page counts as delivered when any channel took it: PagerDuty, the Slack
channel, or email (D167). The notify credential holds a PagerDuty Events v2
routing key and an optional `region`, `us` (the default) or `eu`, which posts to
`events.eu.pagerduty.com`; any other value fails the page at once. When the
pager did not take a page (no notify credential, a refusal or a failed post) and
`SHOC_SMTP_URL` is set, the Manager also emails it to every enabled admin and
operator who has signed in at least once, under the subject `shoc needs you`. A
failed PagerDuty post is tried again after 1, 5 and 15 minutes, then recorded as
failed, and `shoc.notices.last_error` says why (D169). A missing notify
credential or a policy refusal is recorded as failed at once. A page is sent for
real while `SHOC_DRY_RUN=1`, because it changes nothing in the company's systems
(D168). Every page opens with a head code writes (severity, conditions, case
ids), and the model words the rest within 20 seconds or the template goes out
(D171).

Two conditions page as `coverage_dark` besides a source dark for 24 hours: a
source that has never succeeded, 24 hours after it was set up, and
`no detection run has finished` when no `detect.run` completed within three
cycles or an hour, whichever is longer (D170). A dark-source page carries the
diagnosis Ops' review wrote in an earlier hour; a source pages only after a day
dark, and the review runs hourly, so nothing is lost.

shoc can reach a person when it holds a notify credential, a Slack app with a
channel, `SHOC_SMTP_URL` and an enabled admin or operator who has signed in, or
an enabled stream webhook that is unfiltered or subscribes to `report.ready`.
With none of them, `health status` is not ok, Ops raises `notify.unreachable`
(high), and the exception report lists it first (D241). Reports travel only
through Slack or a webhook; a pager and mail carry pages alone.

## Health

`health status` is the one to poll. It is `ok: false` whenever a source is
stale or failing, a rule is erroring, a job has given up in the last day, a
schedule is more than an hour overdue (no worker is ticking the scheduler), the
store cannot be read, an intel feed is failing, the database was migrated by a
newer release (`schema_ahead`), no channel reaches a person (`reachable` names
the pager, Slack, mail and webhook), or Postgres fills 90% of
`SHOC_DISK_BUDGET_GB` (`disk`). A source whose last pull read some streams and
had others refused (`partial`) is named in the summary and leaves `ok` alone; a
pull refused whole still makes it false. `heartbeat` says whether `SHOC_HEARTBEAT_URL`
is set; unset is a notice, not a failure. It is the same reading the detailed
commands give, so they cannot disagree. Nobody has to poll for the overdue
schedule: `serve` checks it every five minutes and the Manager pages
(`coverage_dark`), because `ops.check` is itself a schedule and stops with the
rest. `/healthz` is a liveness probe for Docker and Kubernetes: it answers `ok`
whenever the process is up, and says nothing about whether shoc is working.
`/readyz` is the readiness probe: it answers 503 while `serve` cannot reach
Postgres.

```bash
shoc health status        # one line: is anything wrong?
shoc health sources       # which sources are late or failing
shoc health rules         # which rules are noisy, silent or erroring
shoc health audit         # verify the hash-chained audit log
shoc ops alerts           # what the Ops role would raise right now
curl localhost:8080/metrics
```

Once a token exists, `/metrics` needs one that holds `health:read`, and
it shows that token's tenant only. It exports timestamps, not ages (D172):
`shoc_source_last_success_timestamp_seconds{tenant,source}` (0 when the source
never succeeded) and `shoc_detect_last_success_timestamp_seconds{tenant}`, read
from the last finished `detect.run`; `shoc_jobs` carries a `tenant` label. A
sample alert rule:

```
time() - shoc_source_last_success_timestamp_seconds > 3600
```

A source is "late" relative to its own interval (three missed cycles, not a
fixed clock) so a five-minute connector and a daily one are judged fairly. A
source only the vendor pushes to (a GitHub organisation webhook with no
audit-log token, so no sync schedule) is `pushed` and shows `quiet: true` for
up to 7 days of silence instead of going stale, so a quiet weekend neither
turns health red nor pages (D197). It is stale after 7 days, at once when an
open `github_webhook_deleted` finding for its organisation is newer than its
last delivery, or when deliveries have been refused by signature for over an
hour since the last one that loaded (for example after
`source push-key --rotate` while GitHub still signs with the old secret). Its
stale alert reads `no successful delivery in N minutes`.

Source quality names a hole inside the scoring window as
`no events on N working day(s) between X and Y` when it spans at least two
working days (Monday to Friday) and is longer than twice the source's usual gap
(D198). Retention is measured from the source's history start. A source whose
history is shorter than the 30-day hunt baseline is learning, not faulty:
`health quality` and hunt readiness give the date it gets there, and Ops raises
nothing for it (D246).

### The hourly check

`ops.check` makes the decisions that page first: dark sources, stopped
detection, the disk and the model outage, then the audit chain. Ops' alerts,
its review and the Integrator's wake-up come after. When every step ran, the
worker sends a `GET` to `SHOC_HEARTBEAT_URL`, if it is set, for an outside
monitor ([`deploy.md`](deploy.md#an-outside-monitor)). A step that fails fails
the job by name once the other steps have run, and no heartbeat is sent. The
audit chain is walked from the last row a walk found whole
(`shoc.audit_checkpoints`), and in full once a day per worker and at each
worker start (D247).

`shoc ops alerts` lists what Ops raises:

| Alert | Severity | Raised when |
| --- | --- | --- |
| `source.stale`, `source.failing` | high | A source is late or refused |
| `source.partial` | medium | Some of a source's streams were refused and the rest read; the detail names the setting that drops the stream |
| `source.quality` | medium, high when the score is under 0.5 | A source's fields or volume fell off, or a hole as above |
| `notify.unreachable` | high | No pager key, Slack channel, mail to a signed-in admin or operator, or webhook that carries reports |
| `page.failed` | high | Pages were settled as failed in the last 24 hours; the detail has the newest error |
| `store.size` | medium, high at 90% | Postgres has reached 80% of `SHOC_DISK_BUDGET_GB`; checked only when it is set |
| `intel.feed_failing` | medium | An enabled feed has a `last_error` or no good pull in 24 hours, or an abuse.ch feed keeps no unexpired indicator (D248) |
| `intel.list_failing` | medium | The worker failed to load a warninglist or a cloud range |
| `hunt.backlog_stale` | medium | Open hunt backlog items went 48 hours without a model turn: no model configured, the model failing (see `llm.failing`), today's Hunter token ceiling spent, or none on record |
| `hunt.gap` | medium | A hunt pack's last run this week ended as a `gap` |
| `intel.budget_short` | low | Reports that scored well went unread this week, because CTI's daily budget is too small for what the sources publish |
| `llm.failing` | medium, high when none succeeded today | Model calls to one model failed today |
| `rule.failing` | high | A rule errors |
| `rule.noisy` | medium | A rule fires past its budget |
| `action.stuck`, `approval.waiting` | high | An action has run too long, or waits on a person |
| `jobs.failed` | medium | A job gave up |
| `case.stalled` | medium, high for a high or critical case | A case stopped moving |
| `cost.over_budget`, `cost.unpriced` | medium | See [cost](#cost) |

The noisy, failing and silent counts of `health rules` cover every tracked
rule, whatever `--only` filter is set.

## Cost

```bash
shoc health cost --days 30
```

Two numbers matter: events stored (per product) and LLM spend (per model). Spend
is recorded on every model call from the token counts the provider returns, and
priced from a small table you can override with `SHOC_LLM_PRICE_IN` and
`SHOC_LLM_PRICE_OUT`; a model in neither is a `cost.unpriced` alert, since its
spend reads $0. `llm.configure` with `spend_usd_per_day: 5` makes the hourly
check raise `cost.over_budget` when a day goes over what you expected, and
`shoc ops alerts --budget-usd-per-day 5` asks once with another figure. Once
the day's spend reaches it, informational and low cases go to a person
(`needs_human`) without a model call until the next day; medium and above
still run. The default is 0, no cap.

Keeping it cheap: `SHOC_LLM_PROVIDER=none` disables the crew entirely and leaves
detection, cases and reports working. Case budgets are per severity, so a
low-severity case gets one round and no Challenger. Every case also has a
lifetime ceiling of three times its severity's per-run token budget (a hunt
case's own cap still applies when it is lower), and past it the case goes to a
person (D238). Within an hour of a crew run, more findings of rules the case
already holds, and repeated messages from anything but a person, wait for the
hour; a person's message, a new rule, a finished action or the first such
message in the hour still bring the crew back. One model call, retries
included, takes at most 600 seconds, and a read timeout is not retried. A crew
turn stops looking things up once its run's time budget is spent, and answers
from what it has (D239).

## Reports

```bash
shoc report get --kind weekly    # plus hunting, detection, quality and what was held
shoc report get --kind exec      # 30 days, plus posture numbers
```

Every number in a report is computed from the tables. With an LLM configured,
`--narrate` adds a short paragraph over those numbers; without one, the report
is exactly as useful, just drier.

The daily exception report (D52) lists only decisions that need a person, in
this order:

| Item | Reference |
| --- | --- |
| Give shoc a way to reach you, always first while nothing reaches a person | `notify:unreachable` |
| Fix the model provider | `llm:<last answer time>` |
| Make pages reach you, when pages in the last 24 hours were settled as failed | `page:failed:<date>` |
| Decide on an action that waits for a person | the action's uid |
| Act on a malicious case the crew or shoc closed with nothing contained, or acknowledge it | `uncontained:<case_uid>` |
| Give shoc a credential for a source, or replace one it rejected | `credentials:<source>`, `rejected:<source>` |
| Release an indicator held as too common, or leave it held | `intel:held:<type>:<value>` |
| Turn dry run off, naming the switch that holds actions back | `dry_run` |
| Give shoc a response credential for a platform it reads | `response:<provider>` |

A malicious case closed by the crew or by shoc with nothing contained stays
unacknowledged until a person acknowledges it, whether or not an action was
ever proposed, and its `malicious_uncontained` page is settled only by
containment or a person's close (D240). `report send` and the job's summary add
`not delivered: no channel` when neither Slack nor a webhook carries the report.

The weekly report's `body.intel` holds `reports_read`, `reports`, `ioc_match`
and `ioc_retrohunt`. `body.held` groups what the Manager held by source, kind
and group, each row with a count and a body cut to 300 characters. `top_rules`
leaves out findings on shoc's own identities and suppressed ones, and a case
closed with no findings left (they moved to another case) is in neither the
rows nor the counts.

## Tuning

```bash
shoc case close --case-uid CASE-… --disposition false_positive --reason "…"
shoc detection backlog           # every idea for a detection change, ranked
shoc detection work              # the Detection Engineer works the top of it
shoc suppression list            # what is silenced, and until when
shoc health rules --only silent  # silent rules, and why each one is
shoc own list                    # shoc's own credentials, addresses and operators
```

Closing a case with your disposition is how a detection gets fixed. A case you
close `false_positive` hands the Detection Engineer one item; one you close
`benign_expected` writes a week-long suppression for that rule and entity, and
reaches the Detection Engineer only if the same thing comes back (D77).

The Detection Engineer never edits `content/`. It narrows a shipped rule by an
exclusion that names an exact address and id, seen for a week before the case,
and only after the case's events, replayed through today's mapping, stop
matching while the rule's fixture and its past true positives still match. The
narrowing lapses after 90 days. A new rule needs fixtures, a backtest, the ADS
form and a playbook that can act on its platform. `shoc detection revert` takes
one back; reopening the case behind it does the same.

Register the company's break-glass and emergency admin accounts as yours, so
no agent or playbook acts on them without a person (L2, D253):

```bash
shoc own add --kind operator --value breakglass@example.com --note "Entra break-glass admin"
```

A plan that takes away an admin role (`entra.remove_admin_role`,
`github.demote_org_owner`) also says how many others still hold it.

## The world graph

```bash
shoc graph refresh --days 30
shoc graph neighbours --node AKIAIOSFODNN7EXAMPLE --hops 2
```

Nodes are the entities events mention (users, keys, addresses, resources,
accounts) and an edge means they appeared together. Walks stop at three hops.
It is rebuilt from events, so it describes what actually happens rather than an
inventory somebody forgot to update. Each refresh replaces the tenant's graph
in one transaction, so a node's `first_seen` and `last_seen` describe the
window it read, and nothing outside that window survives (D251). A walk reaches
the account a target was seen in, and goes on through an account only when it
starts there.

## Hunting

```bash
shoc hunt daily                         # today's behavioural hunts, as the worker runs them
shoc hunt pack aws_rare_api_operation   # one pack from content/hunts/, now
shoc hunt results --days 7              # what the hunts concluded
shoc hunt backlog                       # hypotheses no pack can run yet
shoc hunt suggest                       # what is worth looking for, and why
shoc hunt run 203.0.113.55 --days 90    # search history for one value
shoc intel refresh                      # pull feeds, retro-hunt new indicators
shoc intel list --type ip
```

A pack runs only on data that can answer it: `hunt results` lists each pack as
not applicable, learning until a date, stale or ready (RFC 0022). A run ends
`clear`, `explained`, `inconclusive`, `suspicious` or `gap`; `suspicious` raises
a low finding, and the Hunter never opens a case itself. Readiness is per
account: a ready pack whose newer accounts are still learning lists them under
`learning_accounts` with the date each is ready, and runs over the others
(D264). A row whose `learning_on` is `selection` has its sources ready and waits
only for the pack's own first match to pass its lookback (`baseline.learns_from:
selection`). A pack's window is at most 7 days and its lookback at most 90, and
`hunt.merge` refuses a lookback past what the deployment keeps. A pack merged
before those bounds that breaks one no longer runs, and the daily run says so
once in a Hunter digest. A `seen_by_at_least` pack counts over one lookback
ending with the window, so "two countries in a day" spans 24 hours.

### Indicator feeds

`intel.refresh` pulls every enabled feed every six hours. Besides the two
abuse.ch feeds, `shoc intel configure --feed <name> --parser otx|misp|list`
adds one of your own:

- OTX takes `pages` (default 20 pages of 50 pulses) and skips pulses marked
  TLP:RED.
- MISP takes `pages` (default 10 pages of `limit` attributes), `days` (how
  long an indicator is matched, default 30), `severity` (informational to
  critical, default high) and `tags`. It pulls only published attributes
  flagged for detection (`to_ids`) that are on no MISP warninglist, and stores
  them at confidence 0.7, below every action's floor on their own. `tags`
  takes one tag or a list; `!tlp:red` is added unless it names `tlp:red`
  itself.
- A pull cut short by its page cap keeps what it read, and the feed shows as
  failing with a `truncated: …` error.
- OTX and MISP follow no redirect, so their key never goes to another host,
  and OTX follows a next page only on the configured host and path.

Every feed's values pass the checks `intel.add` applies (D222). A value that is
the company's own, or on a warninglist this process has loaded, is held, and a
held value already stored from that feed is deleted on its next pull.
`intel.refresh` counts them as `held` per feed. Values are stored the way
events hold them (a compressed IP, a domain with no trailing dot); a CIDR is
dropped (D224).

`intel.add` with a `url` flattens an HTML page to text before it extracts
indicators, and leaves out the page's own host and its subdomains, counted in
`rejected`; a plain list or CSV is read as it is. A report source's pull that
stops at its page cap is reported as that source's error.

## What it can take

Measured on a 4 vCPU / 8 GB VPS with Postgres 16 in a container, 200,000
CloudTrail events, 50 rules:

| | |
| --- | --- |
| Ingest | 4,850 events/second (`COPY`, 20k-event batches) |
| One detection cycle, 50 rules over a 1-hour window of 200k events | 7.7 s |
| Point query (one user, 500 rows) | 18 ms |
| Aggregate over 200k events | 83 ms |
| Storage | 224 MB per 200k events, ≈ 1.1 KB/event with indexes and `raw` |

What that means in practice: a 100-person company on AWS, Okta and GitHub
produces roughly 1–5 million events a day, which is 3–20 minutes of ingest and
about 1–6 GB a day at 90-day retention. Postgres is comfortable there. Set
`SHOC_DISK_BUDGET_GB` to the disk Postgres may fill: at 80% Ops raises
`store.size`, and at 90% the Manager pages once a day and `health status` is not
ok, because on a full disk Postgres refuses every write. Above roughly 50
million events a day, or when the budget cannot hold the retention window,
move the events to a warehouse (see [which are tested](deploy.md#backends)).
The rules, the crew and everything else stay exactly the same.

Detection cost grows with the window, not with total storage: retention only
affects disk and the cost of a retro-hunt.

On a warehouse the bill follows how often the store is woken and how many
statements each cycle sends (D149). A rule whose products were not loaded since
its last cycle sends nothing. One statement asks every other rule whether
anything new matches it, and only the rules with a match send their own, a run
of adjacent buckets per statement. Indicators are compared with the values the
cycle's window holds, in one statement however large the feeds. Counted with
the 182 shipped rules and 5,300 indicators: a cycle after a GitHub push sends 10
statements (198 before), and an 8-hour backlog of GitHub events is caught up in
35 (592 before), with the same findings. No statement binds more than 256 values
on Databricks, which refuses more. On BigQuery, `SHOC_BIGQUERY_MAX_BYTES_BILLED`
caps what one read may bill (off by default; loads and retention never carry
it); a read past it fails without billing, and the rule or read that sent it
shows the error.

A four-minute soak (a worker running its full schedule while 68,000 events
arrived in 4,000-event batches) held flat at 74 MB resident and three Postgres
connections, with no job backlog and nothing failed. A detection cycle over the
76,000 events that ended up there took 4.9 seconds across all 50 rules and
produced 406 findings, which the entity correlation grouped into **one** case.
That last number is the one that matters: a loud day should cost a person one
page, not four hundred.

## Security posture of the deployment

```bash
shoc grant-readonly --role shoc_agent    # outside Compose: prints the SHOC_READONLY_DSN to set
```

`shoc migrate` already grants the role named in `SHOC_READONLY_DSN`, including
after a new tenant's schema is created, so a stock deployment needs nothing
here. Use this command to create the role in the first place, or to rotate its
password. The worker also proves the role can read at startup and says so if it
cannot, rather than leaving every agent read to fail one cycle at a time.

- Run `serve` and `worker` as a role that does **not own the schema**
  (`SHOC_DSN`), and `shoc migrate` as the owner (`SHOC_MIGRATE_DSN`); Compose
  and the chart do (RFC 0024). The owner can disable the audit log's triggers
  and delete its rows; the runtime role can only append and read. `migrate`,
  `serve` and `worker` warn when they run as the owner.
- Run shoc as an **ordinary Postgres role**, never a superuser: superusers
  bypass row-level security, and `shoc migrate` warns when it sees one. As that
  role, a session sees no tenant rows until it sets `shoc.tenant_id`; in psql,
  `SET shoc.tenant_id = 'shoc:all'` for all tenants or a tenant id for one.
  A backup as that role needs the same setting and row security switched on,
  or `pg_dump` stops at the first table with a policy:
  `PGOPTIONS='-c shoc.tenant_id=shoc:all' pg_dump --enable-row-security …`.
  The nightly dump and the restore are in
  [`deploy.md`](deploy.md#backup-and-restore).
- Set `SHOC_READONLY_DSN` so agent principals query through a role that holds
  only `SELECT`. On a warehouse, set `SHOC_DATABRICKS_READONLY_TOKEN` and
  `SHOC_DATABRICKS_READONLY_PRINCIPAL`, `SHOC_SNOWFLAKE_READONLY_ROLE`,
  `SHOC_REDSHIFT_READONLY_DSN` or `SHOC_BIGQUERY_READONLY_CREDENTIALS`.
- Issue a token (`shoc token create`) or invite an account (`shoc user invite`)
  before exposing the API beyond loopback, and put TLS in front of it. Serve
  the console over `https` with `SHOC_PUBLIC_URL` set to its address.
- Keep `SHOC_MASTER_KEY` outside the database and outside the image, and a
  copy in a password manager apart from the dumps, because without it no
  credential in a dump opens.

See [`security-model.md`](security-model.md) for what each of those protects.
