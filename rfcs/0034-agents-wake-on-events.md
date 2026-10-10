---
rfc: 0034
title: Agents wake on the events that concern them
status: accepted
authors: ["@Rettila"]
created: 2026-10-08
requirements: ["AGT-1", "AGT-3", "DET-3", "ING-2"]
supersedes: null
---

# RFC 0034: Agents wake on the events that concern them

## Summary

Every event shoc publishes goes through `engine.publish`. A table next to it,
`engine.WAKES`, names the job each event type starts and a window. The job is
queued to fall due at the end of the window, keyed on that window, so the first
event of a burst queues it and the rest of the burst joins it. The crew goes back
to a case within seconds of a new finding, a person's message, an Ops nudge or an
action finishing. A report CTI keeps starts the Hunter and the Detection Engineer
within ten minutes. A GitHub push is read for detections within a minute. The
schedules keep the work that depends on the clock.

## Motivation

On 2026-10-07 a finding on a repository made public waited for a 15-minute
sweep, and the hunts CTI filed from a report waited for the Hunter's next daily
run. Nothing was wrong with either agent; they had not been told. A few paths
woke an agent when something happened (a person's message, a source configured,
a case opened by the worker's own detection cycle), each written where it
happened. Every other path waited for a timer:

| What happened | Who should act | How long it waited |
| --- | --- | --- |
| A finding joined an open case | the crew | up to 15 minutes (`case.sweep`) |
| An action ran, was undone, or a person rejected it | the crew | up to 15 minutes |
| Ops nudged a case nobody answered | the crew | up to 15 minutes |
| A case opened outside the worker (a hunt, a retro-hunt, `detect.run` by hand) | the crew | up to 15 minutes |
| CTI kept a report and filed its hunts | the Hunter | up to a day (`hunt.daily`) |
| CTI kept a report naming techniques no rule maps to | the Detection Engineer | up to a day (`detection.backlog`) |
| GitHub pushed a webhook | detection | up to 15 minutes on a warehouse (`detect.run`) |

Detection had the opposite problem. Every `source.sync` job ran the whole rule set
when its pull ended, whether it loaded anything or not. On the Databricks instance
that was 182 queries and about two minutes per sync against six seconds of
pulling, three sources every five minutes: more work than the one worker could
finish, so the crew's jobs waited up to 18 minutes behind syncs.

## Design

`engine.publish` calls `engine.wake` after it writes the event. `wake` looks the
type up in `WAKES`:

| Event | Job | Window |
| --- | --- | --- |
| `case.opened`, `case.updated` | `case.sweep` | 10 s |
| `openspace.message` from a person, or an `inject` | `case.sweep` | 10 s |
| `action.executed`, `action.rolled_back`, `action.rejected` by a person | `case.sweep` | 10 s |
| `intel.report` | `hunt.daily`, `detection.backlog` | 600 s |

D159 later moved the Hunter's wake to `hunt.item`, published for each item put on
its backlog, at 60 s; `intel.report` wakes only the Detection Engineer.
| `events.loaded` | `detect.run` | 60 s |

The job's `run_at` is the end of the window and its idempotency key names the
window, so every event is followed by a run within the window and a burst costs
one run. A window cannot swallow an event: the job it would join has not run yet.

Two new event types carry what had no event before. `intel.report` is published
when CTI keeps a report from a configured source or one a person handed in (the
reports D79 lets steer the agendas). `events.loaded` is published when a pull
(`source.sync`) or a vendor push loads rows; a sync no longer runs detection
itself, so the polls of one cycle, which the scheduler starts together (D71), are
read by one detection run. `openspace.message` now says who spoke (`principal`),
so the crew's own messages during a run wake nothing; the run sweeps when it ends.

Waking more often must not double the work:

- The sweep leaves a case that already has a `case.investigate` job pending or
  running. Before, the worker's own queueing and a sweep could both send the
  crew to a new case.
- `hunt.daily` runs only the packs that are due, and the Hunter's backlog work and
  the Detection Engineer's stop at their daily token ceilings, so a second run in
  a day spends what is left of the day's budget and no more.
- The sweep keeps its back-off for a case whose last run failed, and stands down
  while the model provider is failing.

An idle worker used to wake for a job queued to run later only at its next poll
(30 s), since the NOTIFY went out when the job was queued. It now waits until the
next pending job falls due (`jobs.seconds_to_next`), with the poll as the longest
wait. Timed jobs that were already there (an action's expiry, a playbook's timer,
a held page) are on time too.

The queue stops growing when work outlasts its interval:

- A schedule queues no job while its last one is pending or running. Every tick
  used to add another sync of a source whose previous sync had not started.
- Every session a process opens carries its name (`application_name`), and a
  running job whose worker has no session left goes back to the queue on the
  next pass. A job held by a container that was restarted waited 30 minutes.
- A page a connector read again and that added no row is no longer recorded as
  a load, so the rules over an idle source stay idle (D71).

## What does not change

The schedules stay, for what depends on the clock: the sweep at 15 minutes is
the retry clock for a failed run, `unattended` chases deadlines, `hunt.daily`
runs packs on their cadence, `intel.refresh` polls feeds that cannot push, the
nightly backlog sweep lapses and reopens items, and the reports go out on their
days. Postgres is still the queue (D6); `WAKES` adds no service and no
dependency.

## Not done

- Webhook delivery (`stream.deliver`) still runs every minute. It is not an
  agent, and with no webhook configured a run is one query.
- A finding Sentinel attaches to another open case publishes no event; the
  receiving case's next event or sweep picks it up.
- The worker runs the jobs it claims one after another, so a long job still
  holds up a crew run queued behind it. Running more workers is the scaling knob
  (D6); a priority between job kinds is a separate change.
- Source schedules set before a deployment moved to a warehouse keep their
  interval; `source.configure` applies the warehouse's 900-second floor only when
  it runs.
