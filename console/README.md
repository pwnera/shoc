# shoc console

An optional console for [shoc](../README.md), the headless agentic SOC. It is a
separate project inside this repository: its own Node toolchain, its own tests,
its own image, and no Python.

shoc does not need it. Everything on these screens is reachable from the CLI,
from an MCP client, from Slack and from `curl`. The console is here for teams who
would rather look at a screen, and it keeps the API sufficient: when a screen
needs something new, shoc grows a capability and every client gets it.

## What it shows

Each screen answers one question, and each fact has one home; other screens
link to it with the filter that reproduces it. The rail has three groups:
Operate is what is happening, Program is what shoc knows and does about it,
and Platform is shoc itself. A list row opens a page (a case, a finding, a
rule, a playbook) or a popup for anything else; rows never expand in place.
Filters, tabs and open popups live in the URL, so any count can link to the
slice behind it and Back undoes a step.

| Screen | What it answers | Capabilities behind it |
| --- | --- | --- |
| Overview | Does anything need me, and what happened while I was away? | `action.list`, `case.list`, `source.list`, `finding.list`, `ops.alerts`, `health.status`, `health.sources`, `policy.show`; approvals through the approval card |
| Cases | Which cases are open, how far along is each, and is the crew on it? | `case.list`, `action.list`, `ops.alerts` |
| Case | What happened, what did the crew conclude on which events, is it contained, and what waits on me? | `case.get`, `timeline.build`, `case.history`, `case.set_state`, `case.close`, `case.investigate`, `action.list`, `action.propose`, `playbook.list`, `playbook.runs`, `playbook.run`, `openspace.post`, `slack.notify`, `policy.show`, `ops.alerts`; approvals through the approval card |
| Findings | What fired, and which of it is not handled yet? | `finding.list` |
| Finding | Why did it fire, on what, and is it handled? | `finding.get`, `finding.list`, `finding.set_status` |
| Explore | What exactly happened in the events: who did what, from where, and when? | `events.query`, `events.summarize` |
| Detection | Can the rules see an attack today, and what has the crew changed or muted? | `rule.list`, `health.rules`, `detection.backlog`, `detection.work`, `detection.decide`, `detection.merge`, `detection.revert`, `suppression.list`, `detect.run`, `hunt.results`, `playbook.list`, `intel.reports` |
| Rule | Does it work here, what does it match, and what answers it when it fires? | `rule.list`, `health.rules`, `rule.backtest`, `rule.test`, `detect.run`, `suppression.list`, `detection.backlog`, `playbook.list`, `policy.show`, `detection.revert` |
| Response | What did shoc do or try, whom did it page, and what may it do without me? | `action.list`, `policy.show`, `playbook.list`, `playbook.runs`, `playbook.merge`, `rule.list`, `case.list`, `ops.alerts` |
| Playbook | When does it run, what does it do alone, and what waits for a person? | `playbook.list`, `playbook.runs`, `policy.show`, `rule.list`, `health.rules`, `hunt.results`, `case.list`, `playbook.revert` |
| Hunts | Is the crew hunting, what does each pack look for, and did a hunt turn up something it cannot explain? | `hunt.results` (with each pack's logic), `hunt.backlog`, `hunt.merge`, `hunt.decide`, `hunt.revert`, `hunt.daily`, `hunt.pack`, `intel.reports`, `ops.alerts` |
| Intel | Does anything the feeds carry show up in our logs, and what has CTI read? | `intel.list`, `intel.add`, `intel.remove`, `intel.reports` (read and unread), `intel.digest`, `hunt.suggest`, `hunt.run`, `hunt.propose`, `hunt.backlog` |
| Posture | What is reachable from outside or privileged, and how is it connected? | `posture.get`, `surface.list`, `snapshot.list`, `graph.refresh` |
| Coverage | Can the live rules and ready hunts see each ATT&CK tactic in the data that arrives? | `health.quality`, `rule.list`, `health.rules`, `hunt.results` |
| Memory | What has the crew been told or learned about this company, and is any of it wrong? | `memory.search`, `memory.add_fact` |
| Connections | Is every product delivering good data and can shoc act on it, which intel sources and services does shoc reach, and what else should we connect? | `source.list`, `source.configure`, `source.sync`, `source.remove`, `source.onboard`, `source.push_key`, `source.sample`, `mapping.test`, `credential.list`, `credential.configure`, `credential.check`, `credential.remove`, `intel.list`, `intel.refresh`, `intel.configure` (feeds, report sources by name, keyed lookups), `llm.show`, `llm.configure`, `slack.show`, `slack.configure`, `health.sources`, `ops.alerts`, `health.quality`, `health.cost`, `events.summarize`, `rule.list`, `own.list`, `own.add`, `own.remove` |
| Health | Is shoc itself working, and what does it cost? | `health.status`, `ops.alerts`, `llm.show` (spend, hunt and intel budgets), `health.jobs`, `health.cost`, `health.sources`, `source.list`, `playbook.runs`, `action.list`, `stream.tail`, `health.audit` |
| Measurement | How fast and how accurate is shoc, per incident type, over time? | `metrics.get`, `case.list`, `ops.alerts`, `report.get` and `report.send` (Export only) |
| Access | Who signs in or holds a key, what may each call, and who called what? | `capability.list`, `user.list`, `user.invite`, `user.reset`, `user.update`, `sso.show`, `sso.configure`, `token.list`, `token.create`, `token.revoke`, `health.audit` |

Four dialogs open over any screen from the URL: an event (`?event=`,
`events.query`), an action (`?action=`, with `action.undo` and `action.run`; a
playbook run inside it uses `playbook.get` and `playbook.resume`), an approval
(`?decide=`), and an entity (`?entity=`,
`posture.exposure`, `asset.identify`, `identity.resolve`, `graph.neighbours`,
`platform.lookups`, `platform.lookup`, `intel.lookup`, `timeline.extend`).
The approval card (`components/ui/approval.tsx`) is the one call site of
`action.approve` and `action.reject`; the Overview inbox, the case and the
approval dialog all render it.

The shell is the same on every screen. The top bar holds the palette, the
crew's state and a health pill fed by `health.status`, `ops.alerts` and the
event stream (`stream.tail`). The palette (⌘K) jumps to screens and records,
runs the screen's commands, searches with `search` (which never calls a
model) and lists the keys (`?`). "Ask the crew" (⌘J) opens a chat window
bottom right that runs `ask`: the SOC Manager answers with cited events, keeps
the conversation across screens, and on a record's page takes that record as
the subject. Pages to the on-call human have their own tab on Response.

Every agent statement shows the events it cited as E-chips, because in shoc
an uncited verdict does not count; pointing at a chip lights the same event on
the rest of the page. Approving an action here calls the same `action.approve`
capability Slack does, and only a human principal may call it. Approvals live
in the Overview inbox and on the case; each takes one confirm that restates
what the action does.

A product's dialog on Connections has two sides laid out alike, Logs and
Response, each with its own Review, Settings and Onboarding. Connections
connects a source through `source.configure` and a response credential through
`credential.configure`: credentials go to shoc, which makes
one read with them, stores them and says what the read returned, and the console
shows a stored one as stored without reading it back. A lookup's key, the
model's key and the Slack app's secrets go the same way, through
`intel.configure`, `llm.configure` and `slack.configure`. A push source gets a
push key shown once. Access › People invites people, changes their role, sends
a reset link, disables them, and sets up the company's SSO provider; an
invitation or reset link that was not emailed is shown once. Access › Tokens
creates and revokes bearer tokens; a new token is shown once. Both leave the
page when you say they are stored.

## Running it

Against a shoc you are already running:

```bash
cd console/deploy
CONSOLE_BIND=127.0.0.1 CONSOLE_PORT=8089 docker compose up -d --build
```

nginx serves the build and proxies `/v1`, `/auth`, `/healthz`, `/metrics`,
`/mcp` and `/ingest` to shoc, so the browser sees one origin: no CORS, and the
session cookie goes nowhere else. Set `SHOC_PUBLIC_URL` on shoc to the address
people open, ideally `https` (`tailscale serve` will do): sign-in accepts no
other `Origin`, and builds emailed links and the SSO redirect from it. The first
admin comes from the host:

```bash
shoc user invite you@example.com --role admin
```

In development, with `SHOC_PUBLIC_URL=http://localhost:5173` on shoc:

```bash
cd console
npm install
SHOC_URL=http://127.0.0.1:8080 npm run dev
```

## How it talks to shoc

There is no backend here, and the page keeps no credential. People sign
in through the kernel's `/auth/*` routes (RFC 0028): email, then a password
and a code from an authenticator app, or the company's SSO provider; "Use a
token" turns a person's bearer token into a session. Each sets an HttpOnly
session cookie that no script can read and the browser sends with every
call. `/welcome` takes invitation and reset links. The console asks `user.me`
whether it is signed in, shows the front page when it is not, and raises a
"Signed out" banner when a session ends.

The console can do exactly what the person's role allows. A `reader` gets a
read-only console because the API refuses the rest, not because the console
hides the buttons.

Every call is `POST /v1/<area>/<name>` and every answer is
`{ data, summary, citations }`. Live updates come from the event stream over
SSE, which refreshes exactly the queries each event changes. `health.status`
refetches every 30 seconds while the tab is visible; the shared logs and the
alerts do so only while the stream is down, and sources only on Connections and
Health.

## Working on it

```bash
npm run check   # eslint, tsc, the build and vitest
npm run dev
```

Fetching lives in `src/lib/queries.ts`, one hook per capability, so the whole
dependency on shoc is readable in one place; the shell's own reads sit in
`src/lib/reads.ts` and `queries.ts` re-exports them, which keeps them in the
main chunk while each screen loads as its own. A screen that wants something
which is not there gets a new capability in the kernel, not a workaround here. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

Apache 2.0, the same as the rest of the repository: [`../LICENSE`](../LICENSE).
The name and logo follow shoc's [trademark policy](../TRADEMARKS.md).
