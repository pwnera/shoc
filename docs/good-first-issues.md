# Twenty good first issues

Each one is small, has a clear place to put the code, and has a test that tells
you when it is done. Pick one and open a pull request; no need to ask first.

## Connectors (`shoc/ingest/`)

A platform shoc reads also ships a response action and a lookup of its own
(D56), so each of these includes `shoc/actions/<name>.py`. `shoc new connector
<name>` writes the connector, its mapping and a fixture, and prints the rest of
the checklist and the tests that judge it.

1. **Dropbox team events connector.** The team activity log
   (`team_log/get_events`), with an action that suspends a member.
   *Done when:* the tests `shoc new connector dropbox` prints pass.
2. **Slack audit log connector** (`/api/v1/logs` on Enterprise Grid), with an
   action that signs a user out (`admin.users.session.reset`).
3. **1Password events connector.** Sign-ins and item usage. The Events API is
   read-only and on the Business plan only, not Teams Starter, so the action
   that suspends the user goes through the company's own SCIM bridge, a SCIM
   user deactivation (`active: false`) whose bridge URL and bearer token are
   the action credential.
4. **Bitwarden events connector.** The Public API's event log, on Teams and
   Enterprise organizations, with an action that revokes the member.
5. **Atlassian organization audit log connector**, with an action that
   deactivates a managed account.

## Detection content (`content/rules/`)

6. **AWS: `sts:AssumeRole` from a source that has never used the role before.**
7. **GitHub: workflow file changed on the default branch by a non-maintainer.**
8. **M365: mail forwarded outside the tenant.** `m365_mailbox_forwarding_set`
   fires on any `ForwardingSmtpAddress`; checking the address against the
   tenant's own domains would say when mail actually leaves.
9. **Google Workspace: a shared drive made link-accessible.**
10. **GitLab: a CI/CD variable created or changed.** The GitLab counterpart of
    `github_secret_changed`; take the event names from GitLab's audit event types.
11. **GitLab: a project or group webhook removed.** The counterpart of
    `github_webhook_deleted`.
12. **Narrow a noisy rule.** Close a case `false_positive`, let
    `shoc detection work` merge the narrowing, and turn it into a pull request
    against the shipped rule.

## Kernel (`shoc/`)

13. **A `--since` shorthand for the CLI** (`today`, `yesterday`, `this-week`)
    in `shoc/capabilities/events.py:parse_since`, with unit tests.
14. **`shoc events export`**: stream a query to NDJSON on stdout, for people who
    want the data in their own tools.
15. **Prometheus histogram for detection-cycle duration** in
    `metrics.export` in `shoc/capabilities/ops.py`: handwritten text format, no client library.
16. **A `sigma import` command** that converts a subset of upstream Sigma rules
    into our format and says what it could not translate.
17. **Retry with backoff for connectors** that return HTTP 429, in
    `shoc/ingest/connectors/base.py`, with a test using a mock transport.

## Docs and evals

18. **A scenario for a source you run.** Record the events (sanitised, using the
    documentation IP ranges), write `expected.yaml`, and add it to `evals/`.
19. **A quick-start for your own stack**: Entra + M365, or Google Workspace,
    following `docs/quickstart.md`.
20. **Translate the README** into another language under `docs/i18n/`.

## Before you start

Read [`CONTRIBUTING.md`](https://github.com/pwnera/shoc/blob/main/CONTRIBUTING.md) for setup (about ten minutes), and
sign off your commits with `git commit -s`. Ask anything in Discussions. A
question is never an imposition.
