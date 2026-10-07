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
- Answers `/shoc`: ask a question, list open cases, or see what is waiting.

## Setting it up

1. Create a Slack app for your workspace. Add the bot scopes `chat:write` and
   `commands`, install it, and invite it to the channel you want.
2. Point the slash command and the interactivity request URL at your shoc:
    - Slash command `/shoc` → `https://shoc.example.com/slack/commands`
    - Interactivity → `https://shoc.example.com/slack/interactions`
3. Configure shoc:

```bash
shoc slack configure \
  --bot-token 'xoxb-…' \
  --signing-secret '…' \
  --channel C0123456789 \
  --approvers '{"U0123ALICE": "alice", "U0456SAM": "sam"}'
```

The token and signing secret are encrypted with your master key before they are
stored.

## Who may approve

**Approvers are named explicitly.** Being in the channel is not authority: a
button press from anyone not in the `approvers` map is refused, with a message
saying so. A listed approver becomes a human principal with the `operator` role
(RFC 0018): a human is the only kind the registry lets approve an L2 action, the
same rule the CLI and the API follow.

That mapping is the security boundary of the Slack integration, so treat it like
one: keep it short, and remove people when they leave.

## What the commands do

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
