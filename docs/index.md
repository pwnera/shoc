# shoc

shoc (Security Headless Operation Center) is an open-source SOC for companies
of 20–500 people with no security team. It pulls cloud, identity and
code-hosting audit logs, maps them to OCSF, detects attacks against them, and
answers questions with cited evidence from the CLI, over REST, or from an MCP
client such as Claude. It runs as one container image plus Postgres, under
Apache 2.0.

It is unreleased (`0.0.1`). The code covers most of the v0.4 scope, and what is
still open is listed in the [roadmap](prd.md#roadmap).

```bash
shoc replay --scenario leaked_aws_key
shoc detect run --lookback 1h
shoc ask "what happened with AKIAIOSFODNN7EXAMPLE?"
```

In that scenario a leaked CI access key is used from an unknown address to
enumerate the account, copy an S3 bucket, plant a second key and stop
CloudTrail logging. The [quick start](quickstart.md) runs it in about ten
minutes, then connects a real source and an MCP client.

| To | Read |
| --- | --- |
| Connect a source, or write a connector | [Sources](connectors.md) |
| Check a mapping against public raw logs | [Public datasets](datasets.md) |
| Decide what shoc may do without asking | [Response](response.md) |
| Get cases and approvals in Slack | [Slack](slack.md) |
| Watch health, cost, reports, tuning and hunts | [Running it](operations.md) |
| Deploy with Compose or Helm, and keep config in git | [Deploying it](deploy.md) |
| See how the kernel, the store and the crew fit together | [Architecture](architecture.md) |
| Know what each agent does and may not do | [The crew](agents.md), [Agent specifications](agent-specs.md) |
| Review principals, autonomy, audit and secrets | [Security model](security-model.md) |
| Look up an entity, its table and its states | [Ontology](ontology.md) |
| Call a capability over REST, MCP or the CLI | [Capabilities](reference.md) |
| Know what will not break before a major release | [Public contract](contract.md) |
| Pick a first contribution | [Good first issues](good-first-issues.md) |
