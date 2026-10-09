# Contributing to shoc

Thanks for helping. shoc is a security product, so we keep the bar high on
evidence, tests and review, but the setup below should take under ten minutes.

## Development setup

You need Python 3.12 and a Postgres 15+ you can write to. Docker gives you one:

```bash
docker run -d --name shoc-pg -e POSTGRES_PASSWORD=shoc -e POSTGRES_USER=shoc \
  -e POSTGRES_DB=shoc -p 5432:5432 postgres:16
```

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export SHOC_DSN="postgresql://shoc:shoc@127.0.0.1:5432/shoc"
export SHOC_MASTER_KEY="$(shoc keygen)"
shoc migrate
pytest            # unit tests, conformance suite and the replay scenarios
ruff check . && ruff format --check . && pyright
python -m scripts.check_dependency_budget && python -m scripts.check_licenses
```

`pytest` skips the Postgres-backed tests when `SHOC_DSN` is unset, so a quick
`pytest tests/unit` works with no database at all.

## How the project is laid out

| Directory | What lives there |
| --- | --- |
| `shoc/capabilities/` | The registry: every operation, typed and scoped |
| `shoc/api/` | Generated surfaces: REST + OpenAPI, MCP, Slack, push ingest, metrics |
| `shoc/store/` | `EventStore` protocol and one module per backend |
| `shoc/ingest/` | Connectors and OCSF mappings (YAML) |
| `shoc/detect/` | Sigma-subset compiler and the detection engine |
| `content/` | Rules, hunt packs, playbooks and the autonomy policy |
| `evals/` | Replayed attack scenarios with expected outcomes |

**Never hand-write a REST route or an MCP tool.** Add a capability in
`shoc/capabilities/`; the surfaces are generated from it.

## Adding a detection rule

1. Write `content/rules/<rule_id>.yaml`. Keep to the Sigma subset the compiler
   supports (`shoc/detect/compiler.py` documents it) and map it to ATT&CK.
   Beyond plain matches a rule can count distinct values (`count_distinct`),
   fire on a second event after a first by the same key (`sequence`), compare
   two fields (`|fieldref`), test a network (`|cidr`), fire on a tuple first
   seen in a lookback (`baseline.first_seen`; add `while_learning: fire` when
   the rule must keep firing on every match until it has that much history)
   and key its finding on the first
   of several fields (`entity: [a, b]`); RFC 0023 shows each in YAML. Write
   values as the vendor logs them: `contains` matches a backslash, `%` or `_`
   literally, and `true` on a `raw.` path needs no quotes. To read one item of
   a list of named items, declare the list under `keyed` in the source's
   mapping and read `unmapped.<alias>.<name>`.
   Set Sigma's `date` to the day you add it and `modified` to the day you
   last change it; the console lists rules by both.
   A rule or hunt taken from someone else's names them under `sources`, each
   with `name`, `title`, `url`, `relation`, the source's `license` where it
   has one and, for Sigma, `author` and `license: DRL-1.1` (that licence
   requires both). The finding and the rule page link to it.
   `relation: adapted` means the rule's logic or text came from the source,
   and is allowed only under Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause or
   DRL-1.1. Any other source, Elastic's rules (Elastic-2.0) and GPL code
   included, is `relation: inspired`: take the idea, write the logic and the
   prose yourself, and still cite it. The project an `adapted` source comes
   from is listed in `NOTICE` under the same `name`, with its licence and
   copyright line; add it there the first time you adapt from it.
   `tests/unit/test_content_licences.py` fails on an `adapted` source under
   any other licence, on a DRL-1.1 source without an author and on an
   `adapted` source NOTICE does not list.
2. Add `tests/fixtures/rules/<rule_id>/positive.json` and `negative.json` with
   raw source records. `_repeat: 40` expands a record, and timestamps are
   stamped by the test harness, so do not hard-code them.
3. `pytest tests/conformance/test_rules.py -k <rule_id>`. The rule must fire on
   the positive fixture and stay silent on the negative one.
4. Add the rule id to the `rules` list of the one playbook in
   `content/playbooks/` that answers it. `tests/unit/test_rules_content.py`
   fails on a rule that no playbook, or more than one, claims.

Test data uses the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and fake account IDs. Never commit real logs or IOCs from a
private source.

## Adding a connector

One module in `shoc/ingest/connectors/` implementing `fetch()`, plus one mapping
in `shoc/ingest/mappings/<source>.yaml` and a mapping fixture test. Cursors,
batching, dedup and health accounting are handled for you in
`shoc/ingest/connectors/base.py`.

## Adding a backend adapter

Implement the `EventStore` protocol in `shoc/store/`. `tests/conformance` must
pass unchanged: same fixtures, same findings, on every backend.

An adapter can also live in its own package. It names a factory
`(config, tenant_id, readonly) -> EventStore` under the `shoc.stores` entry point
group, and `SHOC_BACKEND=<that name>` selects it. `shoc.store.conformance.run(store)`
runs the adapter checks that ship with shoc against a store opened for a
throwaway tenant, and returns the failures.

## Changing the docs

Pages live in `docs/`, and the site's nav in `zensical.toml`, so a new page
needs an entry there. To preview the site at http://localhost:8000:

```bash
pip install -e ".[docs]"
zensical serve
```

CI builds it with `zensical build --strict`, which fails on a broken link or
anchor. Leave a blank line before a list and indent a nested list by four
spaces; GitHub renders both without, the site does not. Link to a file outside
`docs/` with its `https://github.com/pwnera/shoc/blob/main/…` URL.

## Commits and pull requests

- Sign off every commit: `git commit -s` (DCO, no CLA).
- Conventional Commits for PR titles and commits, with the requirement ID:
  `feat(store): add postgres adapter (STO-2)`.
- Trunk-based: short-lived branches off `main`, squash merge.
- Changes under `shoc/agents/`, `shoc/cases/`, `shoc/actions/` or auth need two
  reviewers. Say so in the PR description.
- Anything that changes an architecture principle, the public contract or the
  security model needs an RFC in `rfcs/` first, open at least 7 days.

## What a good PR looks like

- Tests for the behaviour, not just for the happy path.
- `ruff check .` and `pyright` clean.
- Docs updated when behaviour changes.
- The requirement ID (`ING-1`, `DET-2`, …) in the title or description.
