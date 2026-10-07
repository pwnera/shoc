# Eighteen good first issues

Each one is small, has a clear place to put the code, and has a test that tells
you when it is done. Pick one and open a pull request; no need to ask first.

## Connectors (`shoc/ingest/`)

1. **npm registry watch for the company's own packages.** `shoc new connector
   npm_registry`, poll `https://registry.npmjs.org/<package>` for new versions
   and maintainers; it needs no credential. Map them to OCSF.
   *Done when:* `pytest tests/unit/test_mappings_all.py -k npm_registry` passes.
2. **Slack audit log connector** (`/api/v1/logs` on Enterprise Grid). Same shape.
3. **1Password events connector.** Sign-ins and item usage. The Events API is
   on the Business plan only, not Teams Starter.
4. **Bitwarden events connector.** The Public API's event log, on Teams and
   Enterprise organizations.
5. **Snyk alert push source.** A mapping plus a fixture; no pull connector
   needed. Dependabot alerts already arrive with GitHub's organisation webhook.

## Detection content (`content/rules/`)

6. **AWS: `sts:AssumeRole` from a source that has never used the role before.**
7. **GitHub: workflow file changed on the default branch by a non-maintainer.**
8. **M365: mail forwarded outside the tenant.** `m365_mailbox_forwarding_set`
   fires on any `ForwardingSmtpAddress`; checking the address against the
   tenant's own domains would say when mail actually leaves.
9. **Google Workspace: a shared drive made link-accessible.**
10. **Narrow a noisy rule.** Close a case `false_positive`, let
    `shoc detection work` merge the narrowing, and turn it into a pull request
    against the shipped rule.

## Kernel (`shoc/`)

11. **A `--since` shorthand for the CLI** (`today`, `yesterday`, `this-week`)
    in `shoc/capabilities/events.py:parse_since`, with unit tests.
12. **`shoc events export`**: stream a query to NDJSON on stdout, for people who
    want the data in their own tools.
13. **Prometheus histogram for detection-cycle duration** in
    `metrics.export` in `shoc/capabilities/ops.py`: handwritten text format, no client library.
14. **A `sigma import` command** that converts a subset of upstream Sigma rules
    into our format and says what it could not translate.
15. **Retry with backoff for connectors** that return HTTP 429, in
    `shoc/ingest/connectors/base.py`, with a test using a mock transport.

## Docs and evals

16. **A scenario for a source you run.** Record the events (sanitised, using the
    documentation IP ranges), write `expected.yaml`, and add it to `evals/`.
17. **A quick-start for your own stack**: Entra + M365, or Google Workspace,
    following `docs/quickstart.md`.
18. **Translate the README** into another language under `docs/i18n/`.

## Before you start

Read [`CONTRIBUTING.md`](https://github.com/pwnera/shoc/blob/main/CONTRIBUTING.md) for setup (about ten minutes), and
sign off your commits with `git commit -s`. Ask anything in Discussions. A
question is never an imposition.
