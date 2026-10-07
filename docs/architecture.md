# shoc architecture

shoc is a headless kernel with no front end of its own. Every capability is a typed tool, exposed the same way to its own agents, to the customer's AI assistants over MCP, to scripts over REST and the CLI, and to people in Slack. Agents talk in shared openspaces, and remember the company they protect. It runs as **one container image plus Postgres**, with a composable event store (Postgres, Databricks SQL, Snowflake, Redshift or BigQuery).

At a glance:

- 1 capability registry → REST, MCP, CLI, Slack callbacks, agent tools
- 0 required UI: Slack and MCP clients are the front ends
- 1 required service: Postgres 15+
- ≤ 8 core Python packages, all libraries
- 0 queues, workflow engines, graph DBs or vector DBs

This page is the design. Where the code does not do what it says yet is listed
under "Where the code is against this plan" in [`prd.md`](prd.md).

---

## 1. Headless, AI-first

```
Clients (all optional, all equal)
  Slack bot · MCP clients (Claude, ChatGPT, Cursor, customer agents) · CLI · services (SIEM, SOAR, ticketing, CI) · MSSP/partner · optional console
        │  scoped bearer tokens (token.create, SHOC_TOKENS), or a person's session cookie (/auth/*, RFC 0028)
        ▼
Interfaces (generated, in `shoc serve`)
  REST + OpenAPI (/v1/…) · MCP server (streamable HTTP or stdio: one tool per capability) · event stream (SSE + signed webhooks) · POST /v1/ask
        │  one call path
        ▼
Capability registry (the product surface, 128 capabilities)
  events.query · finding.list · case.get · openspace.post · action.propose · action.approve · hunt.run · detection.merge · memory.add_fact · health.sources · report.get · ask …
  → auth + scope check → autonomy check (L0/L1/L2 by principal + action) → audit → dual output (JSON + summary + citations)
        │
        ▼
Kernel (section 2)
```

Declared once, exposed everywhere:

```python
# shoc/capabilities/response.py
@capability(
    name="action.approve",
    summary="Approve a response action the crew proposed",
    input=ApprovalInput, output=ActionRecord,
    scope="actions:approve",
    principals=("human",),        # never an agent
    autonomy="L2",
    audit=True,
)
def approve(ctx, inp: ApprovalInput) -> Result: ...

# generated:
#   POST /v1/action/approve
#   MCP tool  action_approve
#   CLI       shoc action approve <id>
#   Slack     "Approve" button callback
#   crew tool only if the role's scopes allow it
```

Principals:

| Principal | Comes in through | Default rights |
| --- | --- | --- |
| Human | Slack, CLI, the console with a session (RFC 0028), an assistant over MCP | Per role: `admin`, `operator`, `deployer` or `reader` (RFC 0018). An L2 call made through an assistant waits for the person's confirmation |
| Crew agent | Internal tool calls | Per role; L1 actions only where policy allows |
| External agent | MCP (customer's AI, partner bots) | Read, ask, post to openspaces, add facts and indicators, run hunts. Never propose or approve an action |
| Service | REST, webhooks | Scoped: ingest, read findings, sync tickets |

Principles:

- **Ask instead of navigate.** `ask` goes to the SOC Manager, which calls the crew as peers and returns a cited answer (RFC 0015), and takes the earlier turns of a conversation. `search` answers the same question from typed queries without a model. Same from Slack, Claude, CLI or a script.
- **Push, don't poll.** Every state change is an event (finding, openspace message, proposal, approval, source health). Clients subscribe over SSE or webhooks, filtered by scope. Slack, paging and ticketing are just subscribers.
- **Config is code.** Rules, playbooks, hunts, policies and mappings are YAML in git. `shoc plan` / `shoc apply`. The Detection Engineer merges its own rules per tenant in `shoc.merged_rules`, behind fixtures and a backtest (D48, D55), and the Hunter its own packs in `shoc.merged_hunts`, behind fixtures and a run over the tenant's data (RFC 0032). A person merges playbooks made of existing actions in `shoc.merged_playbooks`, behind a gate on each rule's platform (RFC 0033).

---

## 2. Kernel: everything inside one process, around one database

```
L1 Sources      AWS CloudTrail/GuardDuty · Azure Activity · GCP Cloud Audit · Okta/Entra · Google/M365 · GitHub (audit log or org webhook)/GitLab · Cloudflare · Tailscale · Stripe · OpenAI/Anthropic (usage per key) · EDR (Defender, CrowdStrike, S1, Wazuh) · webhook · TI feeds (abuse.ch, OTX, MISP)
      │ httpx
L2 Ingest       pull connectors (one module per source, cursor in Postgres) · POST /ingest/{source} · OCSF mapper (YAML) · batch writer (NDJSON.gz, no object store)
      │ load_batch()
L3 Event store  adapter per tenant: Postgres (COPY) | Databricks SQL (PUT to UC Volume → MERGE) | Snowflake (PUT to stage → COPY INTO temp → MERGE)
                | Redshift (PUT to S3 → COPY into temp → insert-only) | BigQuery (load job to staging table → MERGE)
                OCSF table, identical everywhere: ocsf_events (findings, indicators and hunt runs live in Postgres)
      │ canonical SQL → SQLGlot
L4 Detection    own Sigma-subset compiler (pyyaml) · SQLGlot per dialect · scheduler = Postgres jobs table + advisory-lock cron · correlation (entity key + window) · IOC matcher (new IOC → 90-day retro-hunt)
      │ finding → openspace
L5 Agents       openspace (record) · world graph · memory · 10 crew roles and the Integrator · tools = the registry filtered by role scopes · LLM client (Anthropic or OpenAI-compatible) · guardrails (citations, schema-checked outputs, replay evals)
      │ proposal → policy → action
L6 Cases        case engine (NIST 800-61 states) · playbook runner (step state machine on jobs table: timers, approvals, idempotency keys) · autonomy policy (YAML) · action connectors, one per vendor (AWS, Azure, GCP, GitHub, GitLab, Google, M365, Entra, Okta, CrowdStrike, Defender, SentinelOne, Wazuh, Cloudflare, Tailscale, Stripe, OpenAI, Anthropic, PagerDuty)
      │ notify / escalate / inject
L7 Out          event stream · ask · openspace.post (inject) / memory.add_fact · Slack (subscriber + approval callback) · paging (PagerDuty Events API)
```

**Postgres holds everything** except events in warehouse mode: tenants, users, config, connector secrets (encrypted with a master key; KMS in SaaS), cursors, jobs, schedules, locks, openspaces, cases, playbook runs, world graph and memory (full-text search), health metrics, the audit log, when the store last took a batch, and events in Postgres mode.

**Process roles, same image:**

- `shoc serve`: REST, MCP, event stream, ingest endpoint, Slack callbacks
- `shoc worker`: connectors, detections, agents, playbooks, MCO. Scale by running more workers; jobs are claimed with `SELECT … FOR UPDATE SKIP LOCKED`, wakeups via `LISTEN/NOTIFY`, cron leadership via advisory locks.

**MCO built in:** source freshness and volume drift, rule health, backend cost, agent eval drift, LLM spend, exposed as `health.*` capabilities and events, plus a `/metrics` text endpoint.

---

## 3. Agent interaction: the openspace

Agents with their own roles and memory work over a shared world (the tenant), and a human can inject facts from above. The output of an openspace is a decision.

Each case gets an openspace, and agents post typed, cited messages into it. **It is the record of a case, not the mechanism that drives one** (RFC 0012): a role that needs something a colleague knows calls that role directly and gets the answer inside its own turn, and the exchange is written here afterwards. There is no scheduler granting turns and no round order to converge; **the case is closed by whoever held it last**, the Investigator when nothing needed doing and the IR Commander when something did, against a severity-derived deadline the scheduler enforces.

Example (CASE-1042, leaked AWS key):

| Agent | Kind | Message |
| --- | --- | --- |
| None | observation | Access key for deploy-ci used from a new ASN, then a ListBuckets burst [E1] |
| Investigator → Surveyor | request | Is 203.0.113.55 one of ours? |
| Surveyor | answer | Not ours; our egress is 198.51.100.0/24, 1 principal behind it (observed) |
| Investigator → CTI | request | Anything published on 203.0.113.55? |
| CTI | answer | On the abuse.ch blocklist since June [store]. Usually followed by bulk object reads |
| Investigator | hypothesis | Stolen key, malicious, 0.80, severity high. 214 object reads in 2 minutes [E2] |
| Challenger | challenge | Arguing benign, grounded in checklist: the CI runner moving to a new VPS |
| Sam K. (human) | inject | No CI migration is planned this quarter |
| Investigator | evidence | Key found in a public gist at 06:02 [E5]; no change record in 30 days (checked, absent). Revised: malicious, 0.93 |
| Challenger | concede | No benign explanation left that fits E1–E5 |
| IR Commander | proposal | Collect the session list (L1), disable the key (L1, 1 principal behind it), then rotate role prod-deployer (L2, production; fallback: expire after 4h) |
| IR Commander | decision | Ask the Manager to page (uncontainable_and_active). Verified by: key disabled, no further reads for 60 minutes |

**Blackboard mechanics**

- One table, `openspace_messages`: case, round, agent, kind, body, addressee, cited event IDs.
- Kinds: observation, hypothesis, evidence, challenge, proposal, decision, inject (+ concede), request, answer.
- Agents talk to each other, not only to the case. Asking is a **tool call** (`ask_cti`, `ask_surveyor`) that runs with the peer's own principal and capability list, never the caller's, and the `request` and `answer` pair is written here as the record. Nothing routes by keyword, and no role interrupts, because nothing has to guess who might want to speak.
- Workers wake on `LISTEN/NOTIFY` (`shoc_jobs`, sent with every queued job); a 30-second poll stays as the fallback for jobs that fall due later.
- Budgets per run: max tokens and max wall time, plus six peer calls per case. What the case turns out to contain raises the floor severity set, and the Investigator's own severity change recomputes it. A spent budget stops the run with a `needs_human` decision. **Every case hears the Challenger**, whatever its severity, and an objection is always answered.

**Memory (all Postgres rows, full-text search; no graph DB, no vector DB)**

- World graph: users, groups, roles, assets, repos, SaaS apps and their edges; built at onboarding, refreshed nightly. Graph walks capped at 3–4 hops in SQL.
- Episodic: past cases, verdicts and human corrections.
- Semantic: tenant facts with an expiry ("VPN pool is 10.8.0.0/16").

**Human in the openspace**

- Inject a fact into an openspace or tenant memory; agents replan next round.
- Talk to any agent about a case or hunt, from Slack or any MCP client; it answers from its messages and trace.
- Bring your own agent: an external agent can join an openspace over MCP as a member with its own scoped identity.
- Correct a verdict; the correction becomes episodic memory and an eval case.

---

## 5. The crew

Ten roles and the Integrator. Every role uses a model, and the Integrator is code (D74); where an answer must be identical each time it is asked, that answer stays a query and the model sits above it (RFC 0012, superseding D29 and D32).

| Agent | Trigger | Posts / produces | Autonomy |
| --- | --- | --- | --- |
| Sentinel | Every finding, and again on new findings for an open case | Cases: opened, attached, split, re-scoped or deferred | L0 |
| Investigator | Every case | The timeline, the scope, the severity, a cited disposition, the case record | L0 (+ evidence preservation) |
| Challenger | Every case, once | The side the verdict did not take, and a suppression draft when it wins | L0 |
| IR Commander | Malicious, suspicious, or anything still happening | Forensic collection, proposals with a cited blast radius, L2 fallbacks, verification | L0 |
| CTI | Scheduled for reading; called for cases, hunts and detections | Digests, the indicator store, answers with a provenance per claim | L0 |
| Hunter | Its own planned cycle | Hunts, baseline facts, findings through Sentinel, detection proposals | L0 |
| Surveyor | Daily, and on every call about an address, host or identity | Posture, asset identity, resolved identities, coverage gaps | L0 |
| Detection Engineer | Daily backlog run | Rules it authors, merges, narrows and reverts | merges into `shoc.merged_rules` (D55) |
| Ops | Continuously | Retries, the exact fix, what the SOC cannot see, the budget | L0 |
| Integrator (code, D74) | Daily per source, until that source produces a finding | Scopes and click paths, proof a source works, and field paths moved when a vendor changes shape | L0 (+ `mapping.write`) |
| Manager | On every notice, on every `ask`, weekly, monthly | The only page and the only Slack message the operator gets, answers to `ask`, the weekly, the founder's page (RFC 0015) | L0 (+ `notify.page`) |

L0 = reads and proposes · L1 = the playbook runner, the only thing that acts · L2 = a human approves in Slack or another client. Evidence preservation and forensic collection are the two L1 action classes an agent may cause without approval; both only read, and both are typed, catalogued and audited.

---

## 6. Dependency budget

Rule: a new dependency must be a library, not a service, and must replace code we would otherwise own.

Core: `sqlglot`, `psycopg`, `httpx`, `starlette` + `uvicorn`, `pyyaml`, `cryptography`, `pyjwt`, `mcp`. Extras: `[databricks]`, `[snowflake]`, `[pdf]`.

CI counts what the core pulls in as well. `scripts/check_dependency_budget.py` fails on any transitive package missing from its reviewed list, lets `pydantic` in only through `mcp`, and fails if a `shoc/` module imports a denied package. `scripts/check_licenses.py` fails any runtime package whose licence is not permissive, unless it was reviewed and recorded with the exact licence accepted (psycopg under LGPL-3.0, certifi under MPL-2.0).

| Instead of | We use | Trade-off we accept |
| --- | --- | --- |
| Temporal | Jobs table + SKIP LOCKED + step state machine | Steps must be idempotent; no replay debugger |
| Kafka, Redis, SQS | Postgres jobs + LISTEN/NOTIFY | Fine up to thousands of jobs/min per pool |
| Vector, Fluent Bit | Built-in pull connectors + HTTP ingest | No syslog in the MVP |
| S3 / MinIO landing | Warehouse-native staging; direct COPY for Postgres | No raw replay beyond warehouse retention |
| Zep, Neo4j, GraphRAG | Entity/edge/memory tables + full-text search | Graph walks capped at 3–4 hops |
| Vector DB / pgvector | Postgres full-text first; pgvector only if evals show it helps | Weaker fuzzy recall at the start |
| LangGraph, CAMEL, CrewAI | Own agent loop and openspace protocol (a few hundred lines) | We maintain it, but it stays readable |
| LiteLLM, per-tool MCP servers | Two thin LLM clients; one MCP server generated from the registry | New providers need a small client or an OpenAI-compatible proxy |
| OPA | YAML autonomy policy evaluated in code | Less expressive, easier to audit |
| pySigma | Own compiler for the Sigma subset our rules use | Not every Sigma modifier on day one |
| Prometheus, Grafana, Vault | `health.*` capabilities, `/metrics`, encrypted secrets column | Bring your own dashboards |
| A built-in web app | Slack, MCP clients, CLI; the console in `console/` is an optional client | Less visual onboarding until the console ships |

---

## 7. Composable backend

```python
# shoc/store/base.py
class EventStore(Protocol):
    dialect: str  # "postgres" | "databricks" | "snowflake" | "redshift" | "bigquery"
    tenant_id: str

    def create_tenant(self) -> None: ...
    def migrate(self, ocsf_version) -> None: ...
    def load_batch(self, path, table) -> LoadStats: ...
    def query(self, canonical_sql, params, limit) -> QueryResult: ...
    def apply_retention(self, policy) -> int: ...
    def reset(self) -> None: ...
    def health(self) -> StoreHealth: ...
    def close(self) -> None: ...

# tests/conformance: same rules + same fixtures must give the same findings on every backend
```

| Backend | Best for | Tenancy | Load path |
| --- | --- | --- | --- |
| Postgres | OSS, small tenants, 30–90 days hot | Schema per tenant | COPY from NDJSON |
| Databricks SQL | SaaS default, volume, long retention | Catalog per tenant | PUT to UC Volume, insert-only MERGE |
| Snowflake | Customers already on Snowflake | Database per tenant | PUT to stage, COPY INTO a temporary table, insert-only MERGE |
| Amazon Redshift | Customers already on Redshift | Schema per tenant | PUT to an S3 prefix, COPY into a temporary table, insert what the table lacks |
| Google BigQuery | Customers already on BigQuery | Dataset per tenant | Load job into a staging table, insert-only MERGE |

Redshift and BigQuery need no extra: Redshift speaks the Postgres protocol, so `psycopg` connects to it and S3 is one SigV4-signed request; BigQuery is its REST API over `httpx`, signed in as a service account with `pyjwt` (D131).

---

## 8. Deployment

- **OSS self-host:** `docker compose up` = `shoc` + `postgres`; or `pip install shoc` against an existing Postgres. Connect Claude or another MCP client to `/mcp`. Any LLM: Anthropic, OpenAI-compatible, or local (vLLM, Ollama).
- **Managed SaaS (later, AWS):** ECS Fargate (`serve`, `worker`), RDS Postgres, Databricks SQL Serverless (catalog per tenant; model serving as LLM endpoint if used), KMS + Secrets Manager.
- **Bring your own warehouse (later):** our `serve` + `worker` + Postgres; events stay in the customer's Snowflake, Databricks, Redshift or BigQuery via a scoped service principal.

---

## 9. Safety

Isolation:

- Tenant ID enforced in the adapter and Postgres row-level security, never in prompts.
- Agents query with a read-only role (a reader principal or role on a warehouse), and the store's read path runs a single `SELECT` and nothing else; only the playbook runner holds action credentials.
- Connector secrets encrypted per tenant.
- Append-only, hash-chained audit of every message, tool call and action.

Agent safety:

- A verdict without cited event IDs becomes "needs human".
- Log content is untrusted: quoted into prompts as data, never as instructions.
- Actions only through typed playbook steps checked against policy.
