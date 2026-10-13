# Quick start

From nothing to a detected attack in about ten minutes. You need Docker, or
Python 3.12 and a Postgres you can write to.

## 1. Start it

```bash
git clone https://github.com/pwnera/shoc && cd shoc/deploy
cp .env.example .env
for v in SHOC_DB_PASSWORD SHOC_APP_DB_PASSWORD SHOC_AGENT_DB_PASSWORD POSTGRES_SUPERUSER_PASSWORD
do
  sed -i.bak "s/^$v=\$/$v=$(openssl rand -hex 24)/" .env
done && rm .env.bak
docker compose run --rm --no-deps shoc keygen   # paste the value into .env as SHOC_MASTER_KEY
docker compose up -d
```

The loop fills the four database passwords `.env.example` leaves empty, each
with its own random value. Compose runs nothing while one is empty, `keygen`
included. Postgres reads them only when its volume is first created, so keep
`.env` once `up` has run.

Migrations run as their own service, so `up` is the only command: the API and
the workers wait for the schema before they start. They refuse the
`replace-me` placeholder `.env.example` ships as the master key, which is why
`keygen` runs with `--no-deps`; the key it prints has 44 characters.

A command that cannot reach Postgres prints one line naming the host, the port
and libpq's reason, ending `check SHOC_DSN`, and exits 1.

Or without Docker, against an existing Postgres, from a checkout (shoc is not
on PyPI yet):

```bash
pip install .
export SHOC_DSN="postgresql://user:pass@localhost:5432/shoc"
export SHOC_MASTER_KEY="$(shoc keygen)"
shoc migrate
```

`shoc migrate` is forward-only and safe to re-run.

## 2. See it detect something

Before connecting real sources, replay the attack scenario that ships with the
project: a leaked AWS access key used from an unknown address. Replay it into a
demo tenant, which keeps the scenario's case, findings and baselines out of the
tenant your real sources feed:

```bash
docker compose run --rm migrate --tenant demo migrate
docker compose run --rm shoc --tenant demo replay --scenario leaked_aws_key
docker compose run --rm shoc --tenant demo detect run --lookback 1h
docker compose run --rm shoc --tenant demo finding list --since=-1h
```

The first line creates the tenant through the `migrate` service, which holds
the schema owner's DSN. The scenarios ship inside the image, so the same
commands work in a checkout without the `docker compose run --rm` prefix
(`shoc --tenant demo migrate` first).

Once a source is connected, `shoc replay` refuses its tenant, because replayed
events there open real cases. Replay into a tenant of its own, as above, or
pass `--force`.

You should see five findings: a discovery burst, a wall of AccessDenied errors,
64 S3 object reads, a second access key created, and CloudTrail logging stopped.
Every one of them cites the event IDs behind it.

```bash
docker compose run --rm shoc --tenant demo ask "what happened with AKIAIOSFODNN7EXAMPLE?"
```

Every command prints a sentence and a table. `--json` gives the full envelope,
which is what a script should read. `--json` and `--tenant` work before or
after the command (`shoc finding list --json --tenant demo`).

## 3. Connect a real source

Each source needs settings and a secret. The secret is encrypted with your
master key before it touches the database.

Describe them in one file, which names environment variables instead of holding
secrets, so nothing sensitive is committed or typed on a command line. Every
variable the file names starts with `SHOC_SECRET_`. On Docker, write them one per
line in `deploy/secrets.env`, which Compose (2.24 or later) passes to `shoc` and
`worker` only. Keep them out of `.env`, which can hold the database passwords.
Then, from `deploy/`:

```bash
# a starter shoc.yaml, written next to docker-compose.yml
docker compose run --rm -T --no-deps --entrypoint sh shoc \
  -c 'shoc init-config -f /tmp/shoc.yaml >/dev/null && cat /tmp/shoc.yaml' > shoc.yaml
# what would change, then make it so
docker compose run --rm -v "$PWD/shoc.yaml:/home/shoc/shoc.yaml:ro" shoc plan -f shoc.yaml
docker compose run --rm -v "$PWD/shoc.yaml:/home/shoc/shoc.yaml:ro" shoc apply -f shoc.yaml -y
```

From a checkout, export the variables in your shell and run
`shoc init-config`, `shoc plan -f shoc.yaml` and `shoc apply -f shoc.yaml -y`.
The file format is in [`deploy.md`](deploy.md#config-as-code).

One source at a time works too. Read the secret from stdin rather than putting
it in the command, where it lands in shell history. The container cannot read a
path on the host, so on Docker the file goes in through `-T` and `<`:

```bash
docker compose run --rm -T shoc source configure --source okta \
  --settings '{"org_url": "https://acme.okta.com"}' \
  --secret-file - < okta.json

docker compose run --rm shoc source sync --source okta     # pull once, now
docker compose run --rm shoc health status                 # is anything stale?
```

From a checkout, drop the `docker compose run --rm -T` prefix, and
`--secret-file ./okta.json` reads the file directly.

`source configure` tries the credential before it answers, so a token that is
wrong or missing a permission says so immediately rather than on the next
polling cycle. Pass `--no-verify` to write one down before the permission has
been granted.

Entra ID, Google Workspace, Microsoft 365, GuardDuty, Azure, GCP, GitLab and
the EDRs (Defender, CrowdStrike, SentinelOne) and Wazuh work the same way; see
[`connectors.md`](connectors.md) for every source and the permissions to grant.

`shoc worker` polls every configured source and runs a detection cycle every 15
minutes. In Docker it is already running.

## 4. Connect Claude (or any MCP client)

shoc speaks MCP over stdio and over HTTP. On the Docker host, the client starts
`shoc mcp` inside the running `shoc` container, which reads the container's
environment, so no key or DSN goes into the client's config:

```json
{
  "mcpServers": {
    "shoc": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/shoc/deploy/docker-compose.yml",
               "exec", "-T", "shoc", "shoc", "mcp"]
    }
  }
}
```

From a checkout, the client runs `shoc` itself and needs the DSN and the master
key:

```json
{
  "mcpServers": {
    "shoc": {
      "command": "shoc",
      "args": ["mcp"],
      "env": {
        "SHOC_DSN": "postgresql://user:pass@localhost:5432/shoc",
        "SHOC_MASTER_KEY": "…"
      }
    }
  }
}
```

That master key opens every credential shoc stores and keys the audit log.
Protect the client's config file as you protect `.env`, or use the Docker or
HTTP form instead.

Then ask your assistant: *"Use shoc to list the high-severity findings from the
last day and explain the first one."* By default the client is an external
agent: it gets read, ask and search tools, and can add a fact, post to a case's
openspace, hand in indicators and run a hunt. It can never approve an action or
change a source.

To work through the assistant as yourself, add two variables to its `env`:

```json
"SHOC_MCP_ROLE": "admin",
"SHOC_MCP_USER": "you@example.com"
```

On Docker, pass them to `exec` instead: `"exec", "-T", "-e",
"SHOC_MCP_ROLE=admin", "-e", "SHOC_MCP_USER=you@example.com", "shoc", "shoc",
"mcp"`.

The role is yours: `admin`, `operator` (works cases, approves actions),
`deployer` (connects sources, credentials and Slack) or `reader`. As `deployer`
or `admin`, "connect Okta, here is the token" is one call. An approval, or any
other L2 call, waits for you: your client shows a prompt from shoc naming the
action and its target, and nothing runs until you say yes. A client that cannot
show that prompt is told to use Slack or the CLI. Every call is audited under
`SHOC_MCP_USER`. Credentials you hand the assistant pass through its context
and its provider's logs.

A client on another machine connects over HTTP instead, to the same server
(`http://127.0.0.1:8080/mcp` on the shoc host itself):

```
https://shoc.example.com/mcp
```

`/mcp` checks the same bearer token as the REST API, and the client gets the
role or scopes and the tenant that token names. Issue the client a token of its
own as in step 5, with the smallest role it needs (`--role reader` reads and
asks), and send it as `Authorization: Bearer <token>`. `SHOC_MCP_ROLE` applies
to stdio only. With no tokens configured, an HTTP client is the external agent.
Put TLS in front.

## 5. Use the REST API

```bash
curl -s localhost:8080/v1/finding/list -d '{"since": "-24h"}' | jq .summary
curl -s localhost:8080/v1/openapi.json | jq '.paths | keys | length'
```

Every capability is a `POST /v1/<area>/<name>`; the OpenAPI document is generated
from the same registry the CLI and MCP tools come from.

Until a token or an account exists, shoc runs in single-user mode: every caller
is a human with every scope, and `shoc serve` answers only on loopback. To
reach the API or `/mcp` from anywhere else, issue yourself a token first:

```bash
docker compose run --rm -e SHOC_CLI_USER=you@example.com shoc token create --who you@example.com --role admin
```

The token is shown once. Give each other person their own with `--role
operator`, `deployer` or `reader`, and revoke one with `shoc token revoke`. See
[`security-model.md`](security-model.md#tokens-and-single-user-mode).

The console signs people in with an account. Set `SHOC_PUBLIC_URL` in `.env`
to the address you open the console at, recreate `shoc` and `worker` so they
read it, then invite yourself:

```bash
docker compose up -d
docker compose run --rm -e SHOC_CLI_USER=you@example.com shoc user invite you@example.com --role admin
```

The link it prints, once, opens the console, where you scan a QR code with an
authenticator app and choose a password. Invite everyone else from the
console's Access screen. See
[`console/README.md`](https://github.com/pwnera/shoc/blob/main/console/README.md)
to run the console, and
[`security-model.md`](security-model.md#people-sign-in) for how sign-in works.

## 6. Let the crew investigate

Findings that share an entity are grouped into a case. With an LLM configured,
the crew discusses it and records a cited verdict:

```bash
export SHOC_LLM_PROVIDER=anthropic
export SHOC_LLM_API_KEY=…

shoc case list
shoc case investigate CASE-1a2b…
shoc case get CASE-1a2b…
```

`openai` is the other provider, and it means any endpoint that speaks
`/v1/chat/completions`: Ollama, vLLM, or a gateway in front of several
providers:

```bash
export SHOC_LLM_PROVIDER=openai
export SHOC_LLM_BASE_URL=https://llm-gateway.example.com/v1   # a local model: http://ollama:11434/v1
export SHOC_LLM_API_KEY=…
export SHOC_LLM_MODEL=…
```

A gateway that serves a model on `/v1/responses` only takes
`openai-responses`, with the same variables:

```bash
export SHOC_LLM_PROVIDER=openai-responses
export SHOC_LLM_BASE_URL=https://llm-gateway.example.com/v1
export SHOC_LLM_MODEL=…
```

Whichever endpoint you name receives case evidence; see
[what shoc contacts on its own](#what-shoc-contacts-on-its-own).

Without an LLM (`SHOC_LLM_PROVIDER=none`, the default) shoc stays fully
deterministic: detections, findings and cases work, and every case is handed to
a human with its evidence attached. See [`agents.md`](agents.md).

## 7. Make sure shoc can reach you

shoc pages the on-call person only on a few typed conditions, and a page
reaches nobody until shoc has a channel you read. Set up at least one:

- PagerDuty: an Events v2 integration key, with `region` set to `eu` for an
  account in PagerDuty's EU region.

  ```bash
  docker compose run --rm -T shoc credential configure --provider notify \
    --settings '{"region": "eu"}' --secret-file - < pagerduty.json   # {"routing_key": "…"}
  ```

- Slack, which also carries the reports: see [`slack.md`](slack.md).
- Mail: `SHOC_SMTP_URL` and `SHOC_MAIL_FROM` in `.env`. A page no pager took
  is mailed to every enabled admin and operator who has signed in.

`health status` is not ok while none of them is set, and the daily exception
report puts it first. Then point `SHOC_HEARTBEAT_URL` at an outside dead-man
monitor (healthchecks.io, Cronitor, Uptime Kuma) with a period of about an hour
plus some grace. The worker pings it after each hourly check, so a dead host,
database or worker shows as missing pings
([`deploy.md`](deploy.md#an-outside-monitor)).

## What shoc contacts on its own

Two public threat-intel feeds, every six hours, with no account and no key:
`feodotracker.abuse.ch` and `urlhaus.abuse.ch`. With them, the worker downloads
the lists indicator research answers from, once a day each (the Tor exit list
every six hours, DB-IP Lite once a week): `check.torproject.org`,
`ip-ranges.amazonaws.com`, `www.gstatic.com`, `www.cloudflare.com`,
`www.microsoft.com`, `download.microsoft.com`, `docs.oracle.com`,
`api.fastly.com`, `api.github.com`, `digitalocean.com`,
`raw.githubusercontent.com` (MISP warninglists, X4BNet VPN ranges, disposable
mail domains), `www.spamhaus.org`, `download.db-ip.com` and `data.iana.org`. The
worker names the feeds and the list hosts in a log line the first time it
pulls them. `shoc serve` and `shoc mcp` also load the warninglists (`raw.githubusercontent.com`)
and IANA's RDAP bootstrap (`data.iana.org`) when they start and on the first
report read or `intel.add`, so their indicator checks hold the same lists.

`SHOC_INTEL_FEEDS=off` turns off the two feeds and that download. Set
`SHOC_INTEL_FEEDS=off` in `.env` and run `docker compose up -d`, or outside
Compose:

```bash
export SHOC_INTEL_FEEDS=off
```

Detection, cases, the crew and reporting are unaffected; you lose indicator
matching and the retro-hunt. The setting does not make shoc silent. The lists
then load on the first lookup instead, with no log line, and lookups reach the
hosts in the next paragraph. An indicator feed you configure yourself (OTX,
MISP, a list) loads the warninglists when it pulls, even with the setting off.

Indicator research (`intel.lookup`, which the crew calls during an
investigation and the policy can require before an action) answers from those
lists without sending the value anywhere, and asks rdap.org or the registry
IANA names, FIRST EPSS and NVD. It never sends a private or internal address to
them, nor the company's own domains and egress addresses, nor a value a source
marked TLP:AMBER, AMBER+STRICT or RED; a URL goes out as its scheme, host and
path only. `SHOC_INTEL_FEEDS=off` does not turn it off. Sources that need an
account (abuse.ch, ipapi.is, AbuseIPDB, GreyNoise, Shodan, Netlas, VirusTotal,
urlscan.io) are off until you set a key with `shoc intel configure --lookup`,
and each keeps under a daily quota.

Report sources are off until you add one. `shoc intel list` names the free ones
shoc knows (`--preset microsoft_ti`, `--preset the_dfir_report`, …); CTI reads
at most five reports and 100,000 tokens a day, best first (`shoc llm configure
--intel-reports-per-day`, `--intel-tokens-per-day`).

An LLM provider is contacted only once you configure one. Each crew turn sends
it the case: the findings, up to 40 of the events they cite with their OCSF
columns and up to 60 fields of each raw record, memory facts and lookup answers,
all quoted as data. That includes the user names, email and IP addresses and
anything else those records hold. shoc's own credentials and sealed secrets are
never in a prompt. With `SHOC_LLM_PROVIDER=none` none of it leaves, and with a
model you host (Ollama, vLLM) it stays on your network. The provider's region
and how long it keeps prompts are set on your account with it, not in shoc.
With `openai-responses` pointed at `api.openai.com`, shoc sends `store: false`,
so OpenAI keeps no response for later retrieval; its abuse-monitoring
retention still applies. A gateway gets no such field, and what it keeps
follows its own terms.
`SHOC_LLM_BASE_URL_ALLOWLIST` limits the endpoints `llm.configure` may set at
runtime, not `SHOC_LLM_BASE_URL`. See
[what reaches the model](security-model.md#what-reaches-the-model) and
[who else receives what](security-model.md#who-else-receives-what).

Connectors only reach the sources you have configured. A mail server is
contacted only once you set `SHOC_SMTP_URL`, an identity provider only once you
run `sso.configure`, PagerDuty only once it has a notify credential, and an
outside monitor only once you set `SHOC_HEARTBEAT_URL`, whose host the worker
logs when it starts.
