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
| Per source interval | `source.sync` | Pull a connector; what it loaded wakes detection |
| 5 minutes | `detect.run` | Rules, IOC matching, open cases |
| 1 minute | `stream.deliver` | Push events to signed webhooks |
| 15 minutes | `case.sweep` | Send the crew back to every open case with something new; the retry clock for a failed run |
| 30 minutes | `unattended` | Resolve what nobody approved: page, or abandon with a reason |
| 1 hour | `ops.check` | Raise stale sources, noisy rules, stuck approvals |
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
| Daily | `retention` | Drop partitions past the retention window |

`manager.deliver` has no schedule: a page notice queues it, and the Manager
decides whether one page goes out.

The schedules are for what depends on the clock. What happens wakes the agent it
concerns through `engine.WAKES` (RFC 0034), folded into one run per window:

| Event | Wakes | Within |
| --- | --- | --- |
| A case opened or gained a finding; a person's message or an Ops nudge on it; an action on it ran, was undone or was rejected by a person | `case.sweep`, which sends the crew | 10 seconds |
| CTI kept a report from a configured source or one a person handed in | `hunt.daily` and `detection.backlog` | 10 minutes |
| A source loaded rows, pulled or pushed (GitHub's webhook) | `detect.run`, once for the cycle's polls | 1 minute |

The sweep leaves a case the crew is already queued or running on, and the
Hunter's and the Detection Engineer's extra runs stop at the same daily token
ceilings as their scheduled ones.

Scale by running more workers: jobs are claimed with `SELECT … FOR UPDATE SKIP
LOCKED`, so they never collide. The cron leader holds a Postgres advisory lock
for as long as its session lives; every other worker asks for the lock on each
pass, so when the leader's pod dies or a rolling update replaces it, another
worker takes the lock on its next pass. When the leader's node is lost or cut
off, nothing closes its session; the lock holder asks Postgres for TCP keepalive
probes, so the server drops the session and the lock within about 90 seconds. A
worker whose loop has not started a pass in 30 minutes is stuck in a job, and
exits so that its lock frees and its supervisor restarts it. Every session a
worker opens is named after it, so the jobs of a worker that died, or of a
container that was restarted mid-job, go back to the queue on the leader's next
pass. A schedule queues no new job while its last one has not run.

Two of these exist because nobody is watching. `case.sweep` asks which open cases
have something new since the crew last worked them (a detection, a completed
action, a fact somebody posted) and sends the crew back; the events above wake it
at once, and its schedule catches a run that failed. `unattended` gives a deadline to everything whose
resting state was an approval, and it is the reason a running install needs no
clicks. Both are idempotent, and both stand down while the model provider is
failing rather than spending a case's retries on an outage.

There is no shift report (D52). The Manager pages on six typed conditions, and
what it did not page for is held for the weekly report (RFC 0015).

## Health

`health status` is the one to poll. It is `ok: false` whenever a source is
stale or failing, a rule is erroring, a job has given up in the last day, a
schedule is more than an hour overdue (no worker is ticking the scheduler), or
the store cannot be read. It is the same reading the detailed commands give, so
they cannot disagree. Nobody has to poll for the overdue schedule: `serve` checks it
every five minutes and the Manager pages (`coverage_dark`), because `ops.check`
is itself a schedule and stops with the rest. `/healthz` is a liveness probe for
Docker and Kubernetes: it answers `ok` whenever the process is up, and says
nothing about whether shoc is working.

```bash
shoc health status        # one line: is anything wrong?
shoc health sources       # which sources are late or failing
shoc health rules         # which rules are noisy, silent or erroring
shoc health audit         # verify the hash-chained audit log
shoc ops alerts           # what the Ops role would raise right now
curl localhost:8080/metrics
```

Once a token exists, `/metrics` needs one that holds `health:read`, and
it shows that token's tenant only.

A source is "late" relative to its own interval (three missed cycles, not a
fixed clock) so a five-minute connector and a daily one are judged fairly.

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
`shoc ops alerts --budget-usd-per-day 5` asks once with another figure.

Keeping it cheap: `SHOC_LLM_PROVIDER=none` disables the crew entirely and leaves
detection, cases and reports working. Case budgets are per severity, so a
low-severity case gets one round and no Challenger.

## Reports

```bash
shoc report get --kind shift     # last 12 hours, with a handover
shoc report get --kind weekly    # plus hunting, detection, quality and what was held
shoc report get --kind exec      # 30 days, plus posture numbers
```

Every number in a report is computed from the tables. With an LLM configured,
`--narrate` adds a short paragraph over those numbers; without one, the report
is exactly as useful, just drier.

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

## The world graph

```bash
shoc graph refresh --days 30
shoc graph neighbours --node AKIAIOSFODNN7EXAMPLE --hops 2
```

Nodes are the entities events mention (users, keys, addresses, resources,
accounts) and an edge means they appeared together. Walks stop at three hops.
It is rebuilt from events, so it describes what actually happens rather than an
inventory somebody forgot to update.

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
a low finding, and the Hunter never opens a case itself.

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
about 1–6 GB a day at 90-day retention. Postgres is comfortable there. Above
roughly 50 million events a day, or a retention window you cannot afford on one
disk, move the events to Databricks SQL, Snowflake, Redshift or BigQuery. The rules, the crew and
everything else stay exactly the same.

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
on Databricks, which refuses more.

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
- Set `SHOC_READONLY_DSN` so agent principals query through a role that holds
  only `SELECT`. On a warehouse, set `SHOC_DATABRICKS_READONLY_TOKEN` and
  `SHOC_DATABRICKS_READONLY_PRINCIPAL`, `SHOC_SNOWFLAKE_READONLY_ROLE`,
  `SHOC_REDSHIFT_READONLY_DSN` or `SHOC_BIGQUERY_READONLY_CREDENTIALS`.
- Issue a token (`shoc token create`) or invite an account (`shoc user invite`)
  before exposing the API beyond loopback, and put TLS in front of it. Serve
  the console over `https` with `SHOC_PUBLIC_URL` set to its address.
- Keep `SHOC_MASTER_KEY` outside the database and outside the image.

See [`security-model.md`](security-model.md) for what each of those protects.
