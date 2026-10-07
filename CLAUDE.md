# CLAUDE.md for shoc

You are working on **shoc** (Security Headless Operation Center), an open-source, headless, AI-first, 24/7 agentic SOC for companies of 20–500 people with no security team. This file is the source of truth for how to work in this repo. Read it fully before any change, then read `docs/`.

## Read first

1. `docs/prd.md`: product requirements, requirement IDs (ING-1, STO-2, …), roadmap and release rules. **The roadmap decides what to build next.**
2. `docs/architecture.md`: the v0.3 architecture (headless kernel, capability registry, openspace, memory, composable event store).
3. `docs/decisions.md`: every decision already made and why. Don't reopen these without an RFC.
4. `docs/ui-prototype.md`: the optional console prototype (not part of the kernel).

## What we are building right now

Current phase: **Phase 0: Foundations** (target 2026-10-31), then **v0.1: Kernel** (target 2026-12-15). The code already covers most of the v0.4 scope and nothing is released (version `0.0.1`); the scope still open is listed under "Where the code is against this plan" in `docs/prd.md`. Close those gaps before building anything past v0.4.

Phase 0 checklist (from `docs/prd.md`):
- [ ] Monorepo layout (see below) with all community files: README, LICENSE (Apache 2.0), NOTICE, CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1), SECURITY, SUPPORT, GOVERNANCE, MAINTAINERS, CODEOWNERS, `rfcs/0000-template.md`
- [ ] Issue forms (bug, feature, connector request, rule request) and a PR template
- [ ] CI: ruff, pyright, pytest, DCO check, dependency-budget check, license check, docs build
- [ ] release-please config, PyPI Trusted Publishing and GHCR publishing workflows (dry run `0.0.1`)
- [ ] Three foundation RFCs in `rfcs/`: capability registry, `EventStore` adapter, openspace protocol

v0.1 scope: API-1, STO-1, STO-2, ING-1 (AWS CloudTrail, Okta, GitHub), ING-3, DET-1, DET-2 (20 rules), DET-3, SEC-1 (audit log).
v0.1 exit: the leaked-AWS-key scenario is detected end to end on Postgres, and findings can be queried from Claude over MCP.

Always reference requirement IDs in commits, PRs and code comments where relevant.

## Architecture principles (binding; changing one needs an RFC)

1. **Headless first.** Every feature starts as a capability in the registry (typed input/output, scope, autonomy level, allowed principals). REST + OpenAPI, MCP tools, CLI commands and Slack callbacks are *generated* from it. A UI is always an optional client.
2. **AI-first.** Agents use the same capabilities as people. Every answer is JSON + short summary + citations. `ask` is a first-class capability.
3. **Minimal dependencies.** Postgres is the only required service. A new dependency must be a library (never a service) and must replace code we'd otherwise maintain. **Core stays at ≤ 8 Python packages.**
4. **Composable event store.** No warehouse-specific feature in the core. Canonical SQL over OCSF, translated per dialect with SQLGlot. Every adapter passes the same conformance suite.
5. **Bounded autonomy.** Agents read; only the playbook runner acts. Every action is typed, policy-checked (L0/L1/L2), reversible or human-approved, and audited. L2 approval requires a *human* principal.
6. **Evidence or nothing.** A verdict without cited event IDs becomes "needs human". Log content is untrusted data. Quote it into prompts as data, never as instructions.
7. **SaaS-ready, not SaaS-shaped.** `tenant_id` in every table and every call from day one. No multi-tenant control plane, billing or hosting code in this repo.

## Dependency budget

Core (hard limit 8):
`sqlglot`, `psycopg[binary]`, `httpx`, `starlette`, `uvicorn`, `pyyaml`, `cryptography`, `pyjwt`, `mcp`
(`starlette` + `uvicorn` count as one "web" slot.)

Optional extras: `[databricks]` → `databricks-sql-connector`, `[snowflake]` → `snowflake-connector-python`. Redshift and BigQuery need none (D131).
Dev only: `pytest`, `ruff`, `pyright`, `pytest-postgresql` or a Postgres service container. Docs only (`[docs]`): `zensical`, which builds the site from `docs/` (D68).

**Do not add:** Temporal, Celery, Redis, Kafka, SQS, Vector/Fluent Bit, MinIO/S3 SDKs, Neo4j, Zep, GraphRAG, pgvector (until evals justify it), LangChain/LangGraph/CrewAI/CAMEL, LiteLLM, OPA, pySigma, pydantic (use dataclasses + JSON Schema), SQLAlchemy/ORMs, Prometheus client libs. Postgres replaces the queue, scheduler, locks, graph and memory stores. If you think one is needed, stop and write an RFC.

## Repo layout (target)

```
shoc/
├─ shoc/
│  ├─ cli.py                # shoc serve | shoc worker | shoc migrate | shoc ask …
│  ├─ capabilities/         # THE REGISTRY: every operation, typed and scoped
│  ├─ api/                  # generated surfaces: rest.py, mcp.py, stream.py, slack.py
│  ├─ db/                   # schema, migrations (forward-only), jobs queue (SKIP LOCKED), locks, RLS
│  ├─ store/                # base.py (EventStore protocol), postgres.py, databricks.py, snowflake.py, redshift.py, bigquery.py
│  ├─ ingest/               # connectors/, ocsf mappings (YAML), batch writer (NDJSON.gz)
│  ├─ detect/               # sigma-subset compiler, scheduler, correlation, IOC matcher
│  ├─ agents/               # loop.py, openspace.py, memory.py, roles/, llm clients
│  ├─ cases/                # case engine, playbook runner, autonomy policy
│  └─ actions/              # one module per vendor: aws, okta, entra, crowdstrike, github, … (RFC 0031)
├─ content/                 # rules/, hunts/, playbooks/ (YAML, each with tests)
├─ evals/                   # replayed attack sims + expected verdicts
├─ tests/                   # unit/, conformance/ (same fixtures → same findings on every backend)
├─ rfcs/
├─ docs/
├─ deploy/                  # Dockerfile, docker-compose.yml, terraform (SaaS later)
└─ console/                 # optional React + shadcn client: independent project, own Node CI
```

One image, two roles: `shoc serve` (REST, MCP, SSE, ingest endpoint, Slack callbacks) and `shoc worker` (connectors, detections, agents, playbooks, MCO). Scale by adding workers.

## Conventions

- Python 3.12, type hints everywhere, `ruff` + `pyright` clean. Dataclasses for types; JSON Schema derived from them for the registry.
- Trunk-based on `main`, short-lived branches, squash merge. **PR titles and commits use Conventional Commits** (`feat(store): add postgres adapter (STO-2)`); release-please builds the changelog from them.
- DCO sign-off on every commit (`git commit -s`). No CLA.
- Every rule has a positive and a negative fixture test. Every connector has a mapping fixture test. Every adapter passes `tests/conformance`.
- Database migrations are forward-only and run with `shoc migrate`.
- Security-sensitive paths (`shoc/agents/`, `shoc/cases/`, `shoc/actions/`, auth) need two reviewers once the project has them. Flag changes there clearly in PR descriptions.
- Never commit secrets, real customer logs or real IOCs from private sources. Test data uses documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and fake account IDs.

## How to work

- Before building a feature, check which requirement ID and release it belongs to in `docs/prd.md`. Don't build ahead of the roadmap without asking.
- Start every new capability in `shoc/capabilities/`, then let the surfaces be generated. Never hand-write a REST route or MCP tool that bypasses the registry.
- Keep modules small and readable; we prefer a few hundred lines we own over a framework.
- When a decision isn't covered here or in `docs/decisions.md`, propose it as a short RFC in `rfcs/` instead of deciding silently.
- Two external skills are always on in this repo, whether or not a request names them:
  - **ponytail** (`github.com/DietrichGebert/ponytail`) for code: the YAGNI ladder reuse → stdlib → native → existing dependency → one line, and its review mode (`delete:` / `stdlib:` / `native:` / `yagni:` / `shrink:` findings, ending `net: -N lines possible`).
  - **no-ai-slop** (`github.com/petergyang/no-ai-slop`) for prose: README, `docs/`, RFCs, community files, commit messages and PR descriptions. No inflation vocabulary, no binary contrasts, no colon reveals, no puffery or metadiscourse, no recap endings, no decorative bold or emoji. A sentence that would fit any other product is filler.
- Open questions still pending (don't assume otherwise): trademark registration for the name, design partners, default LLM for the quick start, whether the console ships in 2027, foundation timing.
