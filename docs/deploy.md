# Deploying it

One image, two roles: `shoc serve` (REST, MCP, ingest, Slack callbacks) and
`shoc worker` (connectors, detections, agents, playbooks, housekeeping). Scale
by adding workers: jobs are claimed with `SKIP LOCKED`, and one worker becomes
the cron leader through a Postgres advisory lock.

## Docker Compose

```bash
cd deploy
cp .env.example .env
docker compose run --rm --no-deps shoc keygen   # put the value in .env as SHOC_MASTER_KEY
docker compose up -d
```

That brings up Postgres, a one-shot `migrate` service, `shoc` (which runs
`serve`) and `worker`; both start once `migrate` has finished, on every `up`. Postgres creates three ordinary roles: `shoc` owns the database and only
`migrate` uses it, `shoc` and `worker` connect as `shoc_app`, and `shoc_agent`
only reads. None is the superuser, because a superuser bypasses row-level
security.

### Where it listens, and who may talk to it

```bash
SHOC_BIND=127.0.0.1     # the address to publish on; see the warning below
SHOC_PORT=8080
```

**Docker's port publishing bypasses ufw and most host firewalls.** On a normal
VPS, `SHOC_BIND=0.0.0.0` means the public internet, whatever your firewall says.
Bind to loopback, or to a private interface (a VPN address), unless there is TLS
and authentication in front.

Then issue yourself a token, because until one exists anyone who reaches the
port is a full human principal. This talks to Postgres directly, so it works
before `serve` is reachable:

```bash
docker compose run --rm shoc token create --who you@example.com --role admin
```

The answer carries the token once. Everyone else gets theirs from you, from the
CLI, from your assistant over MCP or from the console's Access screen:

```bash
docker compose run --rm shoc token create --who alice@example.com --role operator
docker compose run --rm shoc token create --who ci --kind service --scopes events:write
```

A person's token names a role (`admin`, `operator`, `deployer` or `reader`); a
machine's names a kind and the scopes it uses. `token.revoke` ends one on the
next request. `SHOC_TOKENS`, a JSON map in the environment, works too and needs
a restart to change. Roles, tenants and what single-user mode refuses are in
[`security-model.md`](security-model.md#tokens-and-single-user-mode). The
Compose file passes `SHOC_BIND` through, so a loopback publish starts without
tokens and a VPN address does not. Caddy, Traefik and the console's nginx add a
forwarding header, which single-user mode refuses; issue a token before you put
anything in front.

People sign in to the console with an account. Set `SHOC_PUBLIC_URL` in `.env`
to the address they open it at, recreate `shoc` and `worker` so they read it,
then invite the first admin from the host:

```bash
docker compose up -d
docker compose run --rm shoc user invite you@example.com --role admin
```

The answer carries a link once, or says it was emailed when `SHOC_SMTP_URL` is
set and the mail went out. The link opens the console, which shows a QR code
for an authenticator app and asks for a password and the first code. The first
account ends single-user mode as the first token does. Invite everyone else
from the People tab of the console's Access screen or from your assistant. Signing
in through the company's identity provider, and the rules every sign-in
follows, are in
[`security-model.md`](security-model.md#people-sign-in).

## Kubernetes

```bash
kubectl create secret generic shoc-secrets \
  --from-literal=SHOC_DSN='postgresql://shoc_app:…@postgres:5432/shoc' \
  --from-literal=SHOC_MIGRATE_DSN='postgresql://shoc:…@postgres:5432/shoc' \
  --from-literal=SHOC_MASTER_KEY="$(shoc keygen)" \
  --from-literal=SHOC_READONLY_DSN='postgresql://shoc_agent:…@postgres:5432/shoc' \
  --from-literal=SHOC_TOKENS='{"<a long random token>":{"role":"admin","id":"you"}}'

helm install shoc deploy/helm/shoc \
  --set secrets.existingSecret=shoc-secrets \
  --set worker.replicas=3
```

The chart does not run Postgres for you: point it at one you manage and back up.
`SHOC_TOKENS` is required when the chart creates the secret: `serve` listens
on `0.0.0.0` in the pod and will not start until `SHOC_TOKENS` is set or a token
or account exists. For people to sign in to the console, add
`SHOC_PUBLIC_URL`, and `SHOC_SMTP_URL` for mail, to the same secret.
`shoc migrate` runs as a pre-install and pre-upgrade hook, because migrations are
forward-only and safe to re-run. It connects with `SHOC_MIGRATE_DSN`, the role
that owns the schema; `serve` and `worker` never see that DSN and run as
`SHOC_DSN`, a role that must not own the schema (RFC 0024). Create that role
once, as an administrator of your Postgres, and the migrate hook grants it the
rest:

```sql
CREATE ROLE shoc_app LOGIN PASSWORD '…';
GRANT shoc_app TO shoc;   -- so migrate can grant on the tenant schemas shoc_app creates
```

Defaults worth knowing: `dryRun: true` (actions are planned, never executed) and
`llm.provider: none` (cases are handed to a human with their evidence). Turn
each on when you are ready.

## Configuration

Everything is environment variables, so one image works everywhere. Compose
passes on only the variables in `x-shoc-env` at the top of `docker-compose.yml`,
which covers Postgres and Databricks; add any other variable to that block, not
only to `.env`.

| Variable | What it does |
| --- | --- |
| `SHOC_DSN` | Postgres connection string of the role shoc runs as. Required. It should not own the schema, so it cannot disable the audit log's triggers |
| `SHOC_MIGRATE_DSN` | The role that owns the schema, used only by `shoc migrate`, `shoc grant-readonly` and `shoc rotate-key`. Unset, they use `SHOC_DSN`, and `migrate`, `serve` and `worker` warn that the runtime role owns the audit log |
| `SHOC_MASTER_KEY` | Encrypts connector and action secrets and people's authenticator seeds, and keys the audit chain. Required, and the same in every process: `shoc migrate` records its fingerprint, and a process with an empty or different key cannot write the audit log. Keep it out of the database, and change it only with `shoc rotate-key`. |
| `SHOC_READONLY_DSN` | The SELECT-only role agents query through (`shoc grant-readonly` prints it) |
| `SHOC_TENANT` | Tenant id, default `default` |
| `SHOC_BACKEND` | `postgres`, `databricks`, `snowflake`, `redshift` or `bigquery` |
| `SHOC_DRY_RUN` | `1` (default) plans actions without executing them |
| `SHOC_TOKENS` | JSON map of API tokens to a role (people) or a kind and scopes (machines), an id and a tenant; checked by REST, ingest, the stream, `/metrics` and `/mcp` alongside the tokens `token.create` issues |
| `SHOC_BIND` | The address the port is published on. Compose publishes on it; `serve` checks it before `--host` |
| `SHOC_PUBLIC_URL` | The console's origin as people reach it, e.g. `https://shoc.example.com`. Required for any sign-in: emailed links and the SSO redirect URI are built from it, it is the only `Origin` a sign-in or a cookie request is accepted from, and `https` makes the session cookie `Secure` |
| `SHOC_SMTP_URL` | The mail server for invitations, resets and lock notices: `smtps://user:pass@host:465` (TLS) or `smtp://user:pass@host:587` (STARTTLS, required). Certificates are verified. Unset, or when a mail cannot be sent, `user.invite` and `user.reset` return their link once |
| `SHOC_MAIL_FROM` | The `From` address of that mail. Defaults to the SMTP user when that is an address |
| `SHOC_TRUSTED_PROXIES` | Comma-separated networks whose `X-Forwarded-For` is believed when sign-in attempts are counted per client address; the client is the first entry, read from the right, outside them. Default `127.0.0.0/8,::1/128,172.16.0.0/12`: loopback and the networks Docker usually assigns. Add a TLS terminator that runs on another host, and have it append `X-Forwarded-For`, or everyone shares its address |
| `SHOC_LLM_PROVIDER` | `none` (default), `anthropic`, `openai` (`/chat/completions`) or `openai-responses` (`/responses`) |
| `SHOC_LLM_API_KEY`, `SHOC_LLM_MODEL`, `SHOC_LLM_MODEL_CHEAP`, `SHOC_LLM_BASE_URL` | The crew's model at startup. `llm.configure` overrides any of them per tenant without a restart |
| `SHOC_LLM_BASE_URL_ALLOWLIST` | Comma-separated hosts a base URL set through `llm.configure` may name. Default: the host of `SHOC_LLM_BASE_URL`, `api.anthropic.com` and `api.openai.com` |
| `SHOC_LLM_MAX_TOKENS` | The most tokens one model reply may use |
| `SHOC_LLM_PRICE_IN`, `SHOC_LLM_PRICE_OUT` | Override the price table used to record LLM spend |
| `SHOC_CREW_SAMPLES` | Independent reads behind a confidence (default 2) |
| `SHOC_CONTENT_DIR` | Where rules, hunts, playbooks and the policy are read from (default: the copy shipped with the package) |
| `SHOC_DB_PASSWORD`, `SHOC_APP_DB_PASSWORD`, `SHOC_AGENT_DB_PASSWORD`, `POSTGRES_SUPERUSER_PASSWORD` | Compose only: the database passwords of the owner, the runtime role, the agents' role and the superuser, which default to `shoc`, `shoc_app`, `shoc_agent` and `postgres`. Set all four before Postgres first starts on anything but your own machine |
| `SHOC_VERSION` | Compose only: the image tag (default `edge`) |
| `SHOC_RETENTION_DAYS` | Days of events kept (default 90) |
| `SHOC_INTEL_FEEDS` | `off` stops the two default abuse.ch feeds and the worker's daily download of the lookup lists, which then load on the first lookup |
| `SHOC_MCP_ROLE` | The role of the person driving the `shoc mcp` stdio client: `admin`, `operator`, `deployer` or `reader`. Unset, the client is an external agent. An HTTP client is whoever its token names |
| `SHOC_MCP_USER` | The id a stdio client with a role is audited under |
| `SHOC_DATABRICKS_*`, `SHOC_SNOWFLAKE_*` | Warehouse backends |
| `SHOC_DATABRICKS_READONLY_TOKEN`, `SHOC_DATABRICKS_READONLY_PRINCIPAL` | The token agents read Databricks with, and the principal or group it belongs to, which `shoc migrate` grants `USE` and `SELECT` on each tenant's catalog |
| `SHOC_SNOWFLAKE_READONLY_ROLE` | The role agents read Snowflake with. The shoc user must hold it; `shoc migrate` grants it `USAGE` and `SELECT` on each tenant's database |
| `SHOC_REDSHIFT_DSN` | The Redshift cluster or workgroup as a Postgres connection string, e.g. `postgresql://shoc:…@cluster.abc.eu-west-1.redshift.amazonaws.com:5439/dev?sslmode=require` |
| `SHOC_REDSHIFT_STAGE`, `SHOC_REDSHIFT_REGION` | The S3 prefix batches are staged under (`s3://bucket/prefix`) and its region |
| `SHOC_REDSHIFT_AWS_ACCESS_KEY_ID`, `SHOC_REDSHIFT_AWS_SECRET_ACCESS_KEY` | The key shoc writes and deletes staged batches with: `s3:PutObject` and `s3:DeleteObject` on the prefix and nothing else |
| `SHOC_REDSHIFT_IAM_ROLE` | The role `COPY` reads the prefix as: `default` (the cluster's default role, the default) or an ARN |
| `SHOC_REDSHIFT_READONLY_DSN` | The DSN agents read Redshift with; `shoc migrate` grants its user `USAGE` and `SELECT` on each tenant's schema |
| `SHOC_BIGQUERY_PROJECT`, `SHOC_BIGQUERY_LOCATION` | The Google Cloud project that holds the datasets, and their location (default `US`) |
| `SHOC_BIGQUERY_CREDENTIALS` | A service-account key, as its JSON or the path of the file. The account needs BigQuery Data Editor and Job User on the project |
| `SHOC_BIGQUERY_READONLY_CREDENTIALS` | The service account agents read BigQuery as. Give it Job User on the project; `shoc migrate` grants it Data Viewer on each tenant's dataset |
| `SHOC_CYCLE_SECONDS` | How often detection runs, and on a warehouse the shortest interval a source polls at (default 300 on Postgres, 900 on a warehouse) |
| `SHOC_STATEMENT_TIMEOUT` | Seconds before a query is cancelled (default 120) |
| `SHOC_MAX_REQUEST_BYTES` | Largest accepted request body (default 32 MB) |
| `SHOC_MAX_INGEST_RECORDS` | Records per ingest call (default 50,000) |

## Config as code

The deployment's shape belongs in git; its secrets do not.

```bash
shoc init-config              # writes a starter shoc.yaml
shoc plan -f shoc.yaml        # what would change
shoc apply -f shoc.yaml -y    # make it so
```

`SHOC_RETENTION_DAYS` (default 90) is how many days of events survive the
nightly partition drop. A `retention_days` in the file overrides it once applied,
and stays through restarts. An instance loaded with historical data, such as a
replayed public dataset or a backfill older than 90 days, must raise one of them
or lose that data at the next nightly run.

```yaml
version: 1
sources:
  - source: okta
    settings: { org_url: https://acme.okta.com }
    secret_env: { api_token: SHOC_SECRET_OKTA_API_TOKEN }   # the variable, never the value
intel_feeds:
  - feed: abuse_ch_urlhaus
slack:
  channel: C0123456789
  bot_token_env: SHOC_SECRET_SLACK_BOT_TOKEN
  signing_secret_env: SHOC_SECRET_SLACK_SIGNING_SECRET
  approvers: { U0123ALICE: alice }
```

The file may only name variables that start with `SHOC_SECRET_`, so a config
sent to `config.apply` over REST or MCP cannot read `SHOC_MASTER_KEY`, the DSN
or any other server setting. The CLI reads the file and sends its content; the
server reads no path a caller gives it.

Rules, playbooks and the autonomy policy are read from `SHOC_CONTENT_DIR` by
every process, so deploying that directory is what applies them. `plan`
validates all of them before it compares anything, and `apply` refuses to run
if any of them is invalid or a named variable is missing. Both are idempotent.
Rules, hunt packs and playbooks merged at runtime (`detection.merge`,
`hunt.merge`, `playbook.merge`) are kept per tenant in the database and loaded
over the directory's. Each takes `dry_run`, which runs its gate (fixtures,
backtest, actions) and writes nothing, so a change can be checked before it
lands:

```bash
shoc detection merge --rule-file rule.yaml --ads-file ads.yaml --fixtures-file fixtures.yaml --playbook-id contain_admin_account_misuse --dry-run
shoc hunt merge --pack-file pack.yaml --fixtures-file fixtures.yaml --dry-run
shoc playbook merge --playbook-file playbook.yaml --dry-run
```

A person's merge of a new rule or pack records a backlog item of its own, and a
dry run of one needs none. An agent's merge answers an open item, which
`detection.propose` and `hunt.propose` open by hand. Narrowing a shipped rule
always answers an item, dry run included.

`apply` makes each change through its own capability as the caller:
`source.configure` needs `sources:write`, `intel.configure` needs
`intel:configure`, `slack.configure` needs `slack:write`. The `deployer` role
holds all of them. A caller short of one is refused before anything changes,
and the audit log names the caller for every step.

## Backends

| Backend | Tenancy | Load path | Good for |
| --- | --- | --- | --- |
| Postgres | schema per tenant | `COPY` from NDJSON | the default; 30–90 days hot |
| Databricks SQL | catalog per tenant | `PUT` to a UC volume, insert-only `MERGE` | volume and long retention |
| Snowflake | database per tenant | `PUT` to a stage, `COPY INTO` a temporary table, insert-only `MERGE` | teams already on Snowflake |
| Amazon Redshift | schema per tenant | `PUT` to an S3 prefix, `COPY` into a temporary table, insert what the table lacks | teams already on Redshift |
| Google BigQuery | dataset per tenant, partitioned by day | load job into a staging table, insert-only `MERGE` | teams already on BigQuery |

Postgres stays required with a warehouse: findings, cases, jobs, cursors,
indicators and memory live there, and only `ocsf_events` moves. Databricks and
Snowflake need the `shoc[databricks]` or `shoc[snowflake]` extra. The image
installs it when built with `SHOC_EXTRAS=databricks` (or `snowflake`) in
`.env`; Redshift and BigQuery need none (D131).

A warehouse bills for the minutes it is awake. Every schedule starts on a clock
multiple of its interval, so the source polls and the detection cycle wake it
together, once every `SHOC_CYCLE_SECONDS`. A cycle with nothing loaded since the
last one skips the warehouse. Set the warehouse to stop after a minute or two
of idle time; left at its default, it can stay up between cycles.

BigQuery bills by bytes read instead, with a 10 MB minimum per query, so the
cost follows the number of rules and cycles: each rule reads only the partitions
of its window. A provisioned Redshift cluster bills by the hour whether shoc
uses it or not; Redshift Serverless bills by the second with a 60-second
minimum and suits the 15-minute cycle better.

Redshift's widest text column is 64 KB. `COPY` cuts a longer value there, and a
`raw` or `unmapped` field read from an event cut short is NULL, so a rule on a
source-specific field of such an event does not match. The flattened columns
are unaffected.

The same conformance suite runs against whichever backends your environment can
reach, so a rule behaves identically on all of them. Postgres handles roughly
5,000 events a second and about 1.1 KB per event on modest hardware; see
[what it can take](operations.md#what-it-can-take) for where the line is.

## Upgrading

```bash
docker compose pull && docker compose up -d    # migrate runs first
# or: helm upgrade shoc deploy/helm/shoc
```

Migrations are forward-only. The public contract (capability names and schemas,
REST paths, MCP tool names, event types, the OCSF layout) does not break
outside a major release; see [`contract.md`](contract.md).

### Upgrading to the runtime role

A Compose install whose database was created before `shoc_app` existed has no
such role, because Postgres runs its init script only once. Create it before
pulling, then upgrade as usual; `shoc migrate` grants it what it needs and hands
it the tenant event schemas it will load into:

```bash
docker compose exec postgres psql -U postgres -c \
  "CREATE ROLE shoc_app LOGIN PASSWORD 'shoc_app'; GRANT shoc_app TO shoc;"
docker compose pull && docker compose up -d
```

Use the password you put in `SHOC_APP_DB_PASSWORD`, if you set one.

### Rotating the master key

```bash
docker compose stop shoc worker
docker compose run --rm migrate rotate-key     # prints the new key once
# put the new key in .env as SHOC_MASTER_KEY, then
docker compose up -d
```

`shoc rotate-key` runs as the schema owner in one transaction. It seals every
stored secret again under the new key, bound to its row as before, and moves the
audit chain to the new key: the old chain key is kept in `shoc.audit_epochs`,
sealed with the new master key, so every older row still verifies. Set
`SHOC_NEW_MASTER_KEY` to choose the new key instead of having one generated.
`serve` and `worker` must be stopped first: once it commits, a process still
holding the old key can neither open a secret nor append to the audit log.
