---
rfc: 0000
title: <short, imperative title>
status: draft          # draft | open | accepted | rejected | superseded
authors: ["@you"]
created: YYYY-MM-DD
requirements: []       # e.g. ["STO-1", "API-1"]
supersedes: null
---

# RFC 0000: <title>

## Summary

One paragraph. What changes, in the words a user would use.

## Motivation

The problem, who has it, and what happens if we do nothing. Prefer evidence over
argument: a failing scenario, a support thread, a benchmark.

## Guide-level explanation

How a user or contributor experiences this once it exists. Show the YAML, the
capability call or the CLI session. Write it as if the change had already
shipped.

## Reference-level explanation

The design. Data model, interfaces, migrations, failure modes, and what happens
on upgrade. Say which architecture principles it touches.

## Drawbacks

Why we might not do this.

## Alternatives

What else was considered and why it was rejected. Include "do nothing".

## Dependency and scope impact

- New dependencies (and how they fit the budget of 8 core packages):
- New required services: (must be none, or this RFC must argue for changing principle 3)
- Public contract changes (REST, MCP names, capability schemas, event types,
  `EventStore`, OCSF layout, rule/playbook/policy YAML):

## Security considerations

Principals, scopes, autonomy level, audit, and what an attacker gains if this
component is compromised or fed malicious log content.

## Unresolved questions

What must be settled before this is accepted, and what can be settled later.

## Adoption and migration

Feature flag, default, deprecation window, and how existing installs move over.
