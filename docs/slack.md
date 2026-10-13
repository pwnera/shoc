# Slack

Slack is where most small teams will actually meet shoc: a case arrives with its
evidence, and the one thing that needs a person has a button next to it.

## What it does

- Posts the SOC Manager's pages to the channel. A case does not post itself
  (D58).
- Posts the weekly, executive and exception reports.
- With each page, posts the cases behind it that have an action waiting for a
  human, with findings and verdict, and **Approve** and **Reject** buttons on
  those actions. If nobody presses one, the action waits four hours and is then
  paged or rejected ([`response.md`](response.md)).
- Answers `/shoc` for the people you list: ask a question, list open cases, or
  see what is waiting. Each answer is shown to the asker only.

## Setting it up

1. Create a Slack app for your workspace. Add the bot scopes `chat:write` and
   `commands`, install it, and invite it to the channel you want.
2. Point the slash command and the interactivity request URL at your shoc:
    - Slash command `/shoc` → `https://shoc.example.com/slack/commands`
    - Interactivity → `https://shoc.example.com/slack/interactions`
3. Put the bot token and the signing secret in `SHOC_SECRET_SLACK_BOT_TOKEN`
   and `SHOC_SECRET_SLACK_SIGNING_SECRET` (on Docker, in `deploy/secrets.env`),
   so neither is typed on a command line, and name them in `shoc.yaml`:

```yaml
slack:
  channel: C0123456789
  bot_token_env: SHOC_SECRET_SLACK_BOT_TOKEN
  signing_secret_env: SHOC_SECRET_SLACK_SIGNING_SECRET
  team_id: T0123456789
  approvers: { U0123ALICE: alice, U0456SAM: sam }
  readers: { U0789RITA: rita }   # everyone else who may use /shoc; leave out to keep the stored list
```

4. Apply it with `shoc plan -f shoc.yaml` and `shoc apply -f shoc.yaml -y`
   (the Docker form is in [`deploy.md`](deploy.md#config-as-code)).

The token and signing secret are encrypted with your master key before they are
stored. `shoc slack configure --channel … --approvers …` changes the rest later
and keeps the stored token and secret when they are left out.

## Reaching shoc from Slack

Posts go out from shoc, so they work from a loopback or VPN-only install. The
slash command and the buttons are Slack calling in, so `/slack/commands` and
`/slack/interactions` must be reachable over public HTTPS. Expose those two
paths, and `/ingest/github` if a GitHub webhook pushes to it, through a TLS
reverse proxy, and keep `/v1`, `/mcp`, `/metrics` and the console private.
Those two paths check Slack's signature (below) and need no token. Without that
route, a button press shows an error in Slack and the action keeps waiting on
the four-hour path above.

## Who may approve

**Approvers are named explicitly.** Being in the channel is not authority: a
button press from anyone not in the `approvers` map is refused, with a message
saying so. A listed approver becomes a human principal with the `operator` role
(RFC 0018): a human is the only kind the registry lets approve an L2 action, the
same rule the CLI and the API follow.

That mapping is the security boundary of the Slack integration, so treat it like
one: keep it short, and remove people when they leave.

## Who may read

`/shoc` answers only the Slack users named in `readers` or `approvers`;
approvers are readers already. Anyone else in the workspace, guests included,
gets `/shoc help` and a refusal that names `shoc slack configure`. A listed
reader asks as an external agent with read access to events, findings, cases,
health and `ask`. The crew answers with its own read access, so a reader can
learn more than their own role would show. Keep the list as short as the
approver list.

```bash
shoc slack configure --readers '{"U0789RITA": "rita"}' --team-id T0123456789
```

`--readers` replaces the list (`'{}'` empties it), and leaving it out keeps the
stored one. An install set up before readers existed answers only its
approvers until you add the others. With `--team-id` set, a request from any
other workspace is refused. Answers to `/shoc cases`, `/shoc waiting` and questions are shown to the asker
only; the Approve and Reject confirmations still post in the channel. Each
person may ask 20 questions an hour of each `serve` process.

## What the commands do

Every row but help needs the asker to be a reader or an approver.

| Command | What you get |
| --- | --- |
| `/shoc` or `/shoc help` | The three things it can do |
| `/shoc cases` | The five most recent cases, with verdicts |
| `/shoc waiting` | Actions waiting for a human |
| `/shoc what happened with AKIA…?` | A cited answer, the same `ask` every other client calls |

## How requests are verified

Every request carries Slack's `v0` signature over the raw body and a timestamp.
shoc checks both, and refuses anything older than five minutes, so a captured
body cannot be replayed. A request with no signature, a wrong secret or a
tampered body is rejected before any capability runs.
