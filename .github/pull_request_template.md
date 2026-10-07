<!-- Title must follow Conventional Commits, e.g. feat(detect): add okta rule pack (DET-2) -->

## What this changes

<!-- One or two sentences. Link the issue and the requirement ID from docs/prd.md. -->

Requirement: <!-- e.g. DET-2 --> · Closes #

## Why

<!-- The problem this solves. If it changes behaviour, say what a user will notice. -->

## Checklist

- [ ] Commits signed off (`git commit -s`) for the DCO
- [ ] `ruff check .` and `pyright` are clean
- [ ] Tests added or updated; `pytest` passes locally
- [ ] New rule? positive **and** negative fixtures added
- [ ] New connector? mapping fixture test added
- [ ] New backend adapter? `tests/conformance` passes unchanged
- [ ] New capability declared in `shoc/capabilities/` (no hand-written route or MCP tool)
- [ ] Docs updated; `python scripts/generate_reference.py` re-run if capabilities changed
- [ ] No real logs, customer data, credentials or private IOCs in this PR

## Security-sensitive paths

- [ ] This touches `shoc/agents/`, `shoc/cases/`, `shoc/actions/`, auth, audit or secrets: **two reviewers required**
- [ ] It changes an architecture principle, the public contract or the dependency budget: **an accepted RFC is linked above**
