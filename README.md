# shoc (Security Headless Operation Center)

An open-source, headless, AI-first 24/7 SOC for companies of 20 to 500 people with
no security team. shoc pulls your cloud, identity and code-hosting audit logs,
maps them to OCSF, detects attacks against them, and answers questions with
cited evidence, from your terminal, from your REST client, or from whatever AI
assistant you already use.

One container image plus Postgres. No required UI. Apache 2.0.

**Status:** unreleased (`0.0.1`). The code covers most of the v0.4 scope; what
is still open is listed in the [roadmap](docs/prd.md#roadmap).

## What it does today

```bash
shoc replay --scenario leaked_aws_key
shoc detect run --lookback 1h
shoc finding list --since=-1h
```

```
5 finding(s); severities: critical, high, medium.
finding uid                 rule id                  title                           severity
--------------------------  -----------------------  ------------------------------  --------
F-abefdf1fdb44383b3be2e871  aws_discovery_burst      Cloud infrastructure discover…  high
F-5baa052110f7ac8ecae65016  aws_s3_mass_object_read  Mass S3 object reads by one c…  critical
…
```

```bash
shoc ask "what happened with AKIAIOSFODNN7EXAMPLE?"
```

```
5 finding(s) since -1h; 129 event(s) for AKIAIOSFODNN7EXAMPLE (contains).
citations: leak-ListBuckets-203.0.113.55-10, leak-GetObject-203.0.113.55-73, … (+98 more)
```

In that scenario a leaked CI access key is used from an unknown address to
enumerate the account, copy an S3 bucket, plant a second key and stop CloudTrail
logging. It runs in CI on every pull request, and every finding cites the events
behind it.

- **Sources:** pull connectors, with cursors that survive restarts, for the
  identity providers (Okta, Entra ID, Google Workspace), the productivity suites
  where business email compromise actually shows (Microsoft 365, Google
  Workspace), the EDRs (Defender, CrowdStrike, SentinelOne), the cloud control
  planes (AWS CloudTrail and GuardDuty, Azure Activity Log, GCP Cloud Audit) and
  source control (GitHub, GitLab). For teams whose plans have no enterprise
  audit API, there are Cloudflare, Tailscale and Stripe, hourly usage per
  OpenAI and Claude API key, Wazuh from its indexer, and GitHub's organisation
  webhook. Each source is read the way its vendor documents for a SIEM.
- **Store:** Postgres (schema per tenant, monthly partitions, `COPY` loading,
  retention by partition drop) and Databricks SQL (catalog per tenant, UC volume
  staging, insert-only `MERGE`), Snowflake, Amazon Redshift and Google BigQuery,
  behind one `EventStore` interface and one conformance suite.
- **Detection:** our own Sigma-subset compiler to canonical SQL, translated per
  dialect with SQLGlot; 182 rules mapped to ATT&CK across AWS, Azure, GCP,
  Okta, Entra ID, Google Workspace, Microsoft 365, GitHub, GitLab, EDR,
  Cloudflare, Tailscale, Stripe, OpenAI and Anthropic, each with a positive and
  a negative fixture test; threat-intel feeds with IOC matching and a 90-day
  retro-hunt; a five-minute scheduler on Postgres. The two feeds a new install
  pulls are named in the quick start, and `SHOC_INTEL_FEEDS=off` stops shoc
  contacting anything you did not configure.
- **Surfaces:** REST + OpenAPI, MCP, and a CLI, all generated from one
  capability registry, so they cannot drift apart.
- **Cases and crew:** Sentinel decides what a case is (by shared entity, by the
  graph path between them, or by the campaign they match), and the Investigator
  works it, building the timeline from the source that alerted outward and
  calling CTI and the Surveyor while it thinks. The Challenger argues whichever
  side the verdict did not take, and the IR Commander owns the response until
  the activity has stopped. Every claim cites events that exist, and no verdict
  may be "a person will look at this". The Manager is the only role that
  talks to the operator, and it pages on six typed conditions and nothing else.
- **Response:** an autonomy policy in YAML (L0/L1/L2), typed reversible actions
  for AWS, Azure, GCP, Okta/Entra, Google Workspace, Microsoft 365, GitHub,
  GitLab, the EDRs, Wazuh, Cloudflare, Tailscale, Stripe, OpenAI and
  Anthropic, a playbook for every rule (38 ship, and an operator can merge more
  at runtime from those actions), and a playbook runner whose state lives in
  Postgres. Dry run is the default; an L2 action can only
  be approved by a human.
- **Slack:** cases arrive with their evidence, and the one thing that needs a
  person has a button; approvers are named explicitly, so being in the channel
  is not authority.
- **Operations:** source and rule health, LLM spend, shift, weekly and
  executive reports, daily behavioural hunts, a Detection Engineer that merges
  its own rules behind fixtures and a backtest, and a world graph built from
  events.
- **Config as code:** `shoc plan` and `shoc apply` over one YAML file that names
  `SHOC_SECRET_*` environment variables instead of holding secrets.
- **Stream:** every state change is an event, over SSE or a signed webhook.
- **Audit:** every audited call is appended to a hash-chained, append-only log
  that `shoc health audit` verifies.

## What has been tested

Nothing is released yet, so each backend and connector below says how far it
has been run.

| Event store | How it is tested |
| --- | --- |
| Postgres 16 | Every unit and conformance test, the 29 replayed attack and benign scenarios in `evals/`, and a deployment that runs around the clock |
| Databricks SQL, Snowflake, Amazon Redshift, Google BigQuery | Unit tests translate all 182 rules and the query capabilities to each dialect. The conformance suite runs against a live warehouse only where CI holds that warehouse's credentials |

| Connector | How it is tested |
| --- | --- |
| GitHub, Google Workspace, Cloudflare, Tailscale | Pulling from real tenants on a running deployment |
| AWS CloudTrail, Azure Activity Log, GCP Cloud Audit, Google Workspace, Microsoft 365, Okta, Entra ID, Wazuh | Replayed from [public raw logs](docs/datasets.md), from 20 Entra sign-ins to 1.94M CloudTrail events from flaws.cloud |
| AWS GuardDuty, Defender, Defender Advanced Hunting, CrowdStrike, CrowdStrike FDR, SentinelOne, SentinelOne Cloud Funnel, GitLab, Cloudflare Logpush, Stripe, OpenAI, Anthropic | Mapping fixtures only, written to each vendor's documented format. No public raw logs for them are in the manifest yet |

Every connector has a mapping fixture test, and every rule has a positive and a
negative fixture. If you run a fixture-only connector against a real tenant,
open an issue with whatever it got wrong.

## Quick start

See [`docs/quickstart.md`](docs/quickstart.md). The short version:

```bash
cd deploy && cp .env.example .env
docker compose run --rm --no-deps shoc keygen   # put the value in .env
docker compose up -d
```

On Kubernetes:

```bash
helm install shoc deploy/helm/shoc --set secrets.existingSecret=shoc-secrets
```

The secret holds `SHOC_DSN`, `SHOC_MIGRATE_DSN`, `SHOC_MASTER_KEY` and
`SHOC_TOKENS`; see [`docs/deploy.md`](docs/deploy.md#kubernetes).

Then point Claude, or any MCP client, at it:

```json
{ "mcpServers": { "shoc": { "command": "shoc", "args": ["mcp"] } } }
```

It runs as an external agent: it reads, asks, and adds facts and indicators,
and cannot propose or approve an action. Set `SHOC_MCP_ROLE` in its `env` to
the role of the person driving it: `admin`, `operator` (works cases, approves
actions), `deployer` (connects sources, credentials and Slack) or `reader`. An
approval or any other L2 call made through the assistant still waits for that
person to confirm it in the client. Remote clients use the same server over
HTTP at `/mcp`, with a bearer token from `shoc token create`.

People sign in to the [console](console/README.md) with an email, a password
and an authenticator code, or through the company's OIDC provider. Set
`SHOC_PUBLIC_URL` and invite the first admin with
`shoc user invite you@example.com --role admin`.

## How it is built

| Principle | What it means here |
| --- | --- |
| Headless first | Every feature is a capability in the registry; REST, MCP and CLI are generated from it, and Slack calls it |
| AI-first | Agents use the same capabilities as people; every answer is JSON plus a summary plus citations |
| Minimal dependencies | Postgres is the only required service; core stays at 8 Python packages or fewer |
| Composable event store | Canonical SQL over OCSF, one adapter interface, one conformance suite |
| Bounded autonomy | Agents read; only the playbook runner acts, and L2 needs a human |
| Evidence or nothing | A verdict without cited event IDs becomes "needs human" |
| SaaS-ready, not SaaS-shaped | `tenant_id` everywhere from day one; no control-plane code in this repo |

Full design: [`docs/architecture.md`](docs/architecture.md). Decisions and their
reasons: [`docs/decisions.md`](docs/decisions.md). Foundation RFCs:
[`rfcs/`](rfcs/).

## Documentation

- [Quick start](docs/quickstart.md)
- [The crew](docs/agents.md): openspaces, roles, budgets, evidence rules
- [Sources](docs/connectors.md): every connector, how each is read, writing your own
- [Public datasets](docs/datasets.md): raw logs per source, and where none exist
- [Response](docs/response.md): autonomy policy, actions, playbooks, approvals
- [Slack](docs/slack.md): alerts, `/shoc`, one-click approvals
- [Running it](docs/operations.md): health, cost, reports, tuning, hunting
- [Deploying it](docs/deploy.md): Docker Compose, Helm, config as code
- [The console](console/README.md): the optional web client, an independent
  project under `console/` that the kernel never needs
- [The public contract](docs/contract.md): what will not break without a major release
- [Capability reference](docs/reference.md): generated from the registry
- [Security model](docs/security-model.md)
- [Ontology](docs/ontology.md): every entity, its table, states and relations
- [Product requirements and roadmap](docs/prd.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md) · [Governance](GOVERNANCE.md) · [Support](SUPPORT.md)

## Contributing

Good first contributions are a detection rule, a connector or a backend adapter.
Each has a template and a test harness, and there are
[twenty concrete ones](docs/good-first-issues.md) waiting. See
[`CONTRIBUTING.md`](CONTRIBUTING.md). Sign off your commits (`git commit -s`);
there is no CLA.

## Our promise

No feature will ever move from the open-source project to a paid offer. A
managed service may sell operations (hosting, scale, support), never features
taken out of this repository.

## Licence

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
