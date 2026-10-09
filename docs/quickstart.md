# Quick start

From nothing to a detected attack in about ten minutes. You need Docker, or
Python 3.12 and a Postgres you can write to.

## 1. Start it

```bash
git clone https://github.com/pwnera/shoc && cd shoc/deploy
cp .env.example .env
docker compose run --rm --no-deps shoc keygen   # paste the value into .env as SHOC_MASTER_KEY
docker compose up -d
```

Migrations run as their own service, so `up` is the only command: the API and
the worker wait for the schema before they start.

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
project: a leaked AWS access key used from an unknown address.

```bash
docker compose run --rm shoc replay --scenario leaked_aws_key
docker compose run --rm shoc detect run --lookback 1h
docker compose run --rm shoc finding list --since=-1h
```

The scenarios ship inside the image, so those three commands work as written
whether you are in Docker or in a checkout (drop the `docker compose run --rm`
prefix for the latter).

Once a source is connected, `shoc replay` refuses its tenant, because replayed
events there open real cases. Replay into a tenant of its own (`shoc --tenant
lab migrate`, then `shoc --tenant lab replay …`), or pass `--force`.

You should see five findings: a discovery burst, a wall of AccessDenied errors,
64 S3 object reads, a second access key created, and CloudTrail logging stopped.
Every one of them cites the event IDs behind it.

```bash
shoc ask "what happened with AKIAIOSFODNN7EXAMPLE?"
```

Every command prints a sentence and a table. `--json` gives the full envelope,
which is what a script should read.

## 3. Connect a real source

Each source needs settings and a secret. The secret is encrypted with your
master key before it touches the database.

Describe them in one file, which names environment variables instead of holding
secrets, so nothing sensitive is committed or typed on a command line:

```bash
shoc init-config                   # writes a starter shoc.yaml
shoc plan -f shoc.yaml             # what would change
shoc apply -f shoc.yaml -y         # make it so
```

The file format is in [`deploy.md`](deploy.md#config-as-code).

One source at a time works too. Read the secret from a file or from stdin
rather than putting it in the command, where it lands in shell history:

```bash
shoc source configure --source okta \
  --settings '{"org_url": "https://acme.okta.com"}' \
  --secret-file ./okta.json          # or --secret-file - to read stdin

shoc source sync --source okta     # pull once, now
shoc health status                 # is anything stale?
```

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

shoc speaks MCP over stdio. Add it to your client's config:

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

The role is yours: `admin`, `operator` (works cases, approves actions),
`deployer` (connects sources, credentials and Slack) or `reader`. As `deployer`
or `admin`, "connect Okta, here is the token" is one call. An approval, or any
other L2 call, waits for you: your client shows a prompt from shoc naming the
action and its target, and nothing runs until you say yes. A client that cannot
show that prompt is told to use Slack or the CLI. Every call is audited under
`SHOC_MCP_USER`. Credentials you hand the assistant pass through its context
and its provider's logs.

A remote client connects over HTTP instead, to the same server:

```
https://shoc.example.com/mcp
```

`/mcp` checks the same bearer token as the REST API, and the client gets the
role or scopes and the tenant that token names. `SHOC_MCP_ROLE` applies to
stdio only. With no tokens configured, an HTTP client is the external agent. Put
TLS in front.

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
docker compose run --rm shoc token create --who you@example.com --role admin
```

The token is shown once. Give each other person their own with `--role
operator`, `deployer` or `reader`, and revoke one with `shoc token revoke`. See
[`security-model.md`](security-model.md#tokens-and-single-user-mode).

The console signs people in with an account. Set `SHOC_PUBLIC_URL` in `.env`
to the address you open the console at, recreate `shoc` and `worker` so they
read it, then invite yourself:

```bash
docker compose up -d
docker compose run --rm shoc user invite you@example.com --role admin
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
export SHOC_LLM_BASE_URL=https://api.kie.ai/v1
export SHOC_LLM_API_KEY=…
export SHOC_LLM_MODEL=gemini-3-pro
```

A gateway that serves a model on `/v1/responses` only takes
`openai-responses`, with the same variables:

```bash
export SHOC_LLM_PROVIDER=openai-responses
export SHOC_LLM_BASE_URL=https://api.kie.ai/openai/v1
export SHOC_LLM_MODEL=deepseek-v4-1-flash
```

Without an LLM (`SHOC_LLM_PROVIDER=none`, the default) shoc stays fully
deterministic: detections, findings and cases work, and every case is handed to
a human with its evidence attached. See [`agents.md`](agents.md).

## What shoc contacts on its own

Two public threat-intel feeds, every six hours, with no account and no key:
`feodotracker.abuse.ch` and `urlhaus.abuse.ch`. With them, the worker downloads
the lists indicator research answers from, at most once a day each (DB-IP Lite
monthly): `check.torproject.org`, `ip-ranges.amazonaws.com`, `www.gstatic.com`,
`www.cloudflare.com`, `www.microsoft.com`, `download.microsoft.com`,
`docs.oracle.com`, `api.fastly.com`, `api.github.com`, `digitalocean.com`,
`raw.githubusercontent.com` (MISP warninglists, X4BNet VPN ranges, disposable
mail domains), `www.spamhaus.org`, `download.db-ip.com` and `data.iana.org`. The
worker names the feeds and the list hosts in a log line the first time. If shoc
should make no outbound connection you did not configure, set
`SHOC_INTEL_FEEDS: "off"` in the `x-shoc-env` block of `docker-compose.yml`
(Compose passes on only the variables listed there), or outside Compose:

```bash
export SHOC_INTEL_FEEDS=off
```

Detection, cases, the crew and reporting are unaffected; you lose indicator
matching and the retro-hunt, and the lists load on the first lookup instead.

Indicator research (`intel.lookup`, which the crew calls during an
investigation and the policy can require before an action) answers from those
lists without sending the value anywhere, and asks rdap.org or the registry
IANA names, FIRST EPSS and NVD. It never sends a private or internal address to
them, and `SHOC_INTEL_FEEDS=off` does not turn it off. Sources that need an
account (abuse.ch, ipapi.is, AbuseIPDB, GreyNoise, Shodan, Netlas, VirusTotal,
urlscan.io) are off until you set a key with `shoc intel configure --lookup`,
and each keeps under a daily quota.

Report sources are off until you add one. `shoc intel list` names the free ones
shoc knows (`--preset microsoft_ti`, `--preset the_dfir_report`, …); CTI reads
at most five reports and 100,000 tokens a day, best first (`shoc llm configure
--intel-reports-per-day`, `--intel-tokens-per-day`).

An LLM provider is contacted only once you configure one, and connectors only
reach the sources you have configured. A mail server is contacted only once you
set `SHOC_SMTP_URL`, and an identity provider only once you run
`sso.configure`.
