---
rfc: 0025
title: An action acts on the platform and in the tenant its target was seen in
status: accepted
authors: ["@Rettila"]
created: 2026-10-04
requirements: ["RSP-2", "RSP-4", "ING-1", "API-1"]
supersedes: null
---

# RFC 0025: An action acts on the platform and in the tenant its target was seen in

## Summary

A provider can hold several credentials, named like sources (D76): `aws` and
`aws:staging`, `idp:okta` and `idp:entra`. Each one acts on the platforms of its
flavour and, if its settings list `accounts`, only in those accounts. When an
action is proposed, shoc looks at the case's findings that name the target,
reads the platform of each finding's rule and the account its events carried,
and picks the credential that serves that platform and account. A target seen
in two tenants is acted on in both. If a tenant has no credential, or two
credentials could both claim it, shoc says so in the action's reason. It does
not guess. Events whose records never name their account (Okta, GitLab) get
the account of the source that read them.

## Motivation

Read on 2026-10-04:

- `action_credentials` was keyed by provider, so a tenant had one `aws`, one
  `idp` and one `edr` credential. A company with a production and a staging
  AWS account could contain a leaked key in only one of them. In the other,
  the call failed as if the key did not exist.
- `idp` covers Okta and Entra with one row and a `flavour`.
  `contain_account_takeover` answers Okta, Entra and M365 rules. An Entra case
  passed the platform check, because `entra` is in the action's platforms, and
  then called Okta's API with an Entra UPN.
- Every EDR answers the rule product `edr`. A CrowdStrike credential would be
  used to isolate a host that SentinelOne reported.
- The Okta, GitLab, CrowdStrike and SentinelOne mappings left
  `cloud_account_uid` empty. Their events, findings and cases did not say
  which org or console they came from. D76 assumed that "their events already
  carry" it.
- Ingest already supported two accounts of one vendor (D76). Response, the
  half that changes things, did not.

## Guide-level explanation

One credential per provider keeps working with no change: every action of that
provider uses it.

A second tenant gets a label and the accounts it acts in:

```bash
shoc action configure --provider aws:staging \
  --settings '{"accounts": ["222222222222"]}' \
  --secret '{"access_key_id": "…", "secret_access_key": "…"}'
```

An account is written the way the platform's events write `cloud_account_uid`:
an AWS account ID, an Entra tenant ID, a GCP project, a GitHub organisation, an
Okta org host (`acme.okta.com`), a CrowdStrike CID or a SentinelOne account ID.
`source.list` shows the accounts each source's events have named.

Okta and Entra side by side need no accounts, because their flavours already
split the platforms:

```bash
shoc action configure --provider idp --settings '{"flavour": "okta", "org_url": "https://acme.okta.com"}' …
shoc action configure --provider idp:entra --settings '{"flavour": "entra"}' …
```

`action.configure` refuses a credential that could claim a target another one
already claims: two with no accounts on the same platform, or one account named
twice.

A proposal shows where it will act:

```text
Disable access key AKIA… of deploy-ci in aws:staging, will run automatically (L1, dry run).
```

`action.propose` and `platform.lookup` take an optional `credential`. Naming one
only narrows the choice. A name pointing to a tenant the target was never seen
in blocks the action, so a credential name an attacker writes into a log line
that the crew repeats sends nothing to another tenant.

## Reference-level explanation

**Credentials.** No table change. `action_credentials.provider` holds the
credential's name, `aws` or `aws:staging`. The part before the colon is the
provider. Settings may carry `accounts` (a string or a list). An instance's
platforms come from its flavour: `okta` → okta, `entra` → entra, m365 and azure (an Azure caller is an Entra principal). Any
other flavour, or none, means every platform its actions name. An `idp` row
without a flavour is read the way `shoc.actions.idp` reads it: `org_url` means
Okta.

**Where a target was seen** (`credentials.where_seen`). The case's findings
whose rule product is one of the action's platforms, narrowed to the findings
whose entities name the target when any do. Each one gives a (platform,
account) pair: the rule's `logsource.product` and the finding's `account:`
entity, or '' when its events had none. Without a case, the last 30 days of
findings that name the target are used.

**Choosing** (`credentials.choose`, a pure function). For each pair:

1. Keep the credentials that serve the platform (and the named one, if a name
   was given).
2. With an account, the credentials that list it. If none lists it, the ones
   that list no account.
3. With no account, all of them. A pair with no account is dropped when the
   same platform also has a known account.
4. Exactly one left: act with it. None: "no aws credentials act in aws account
   333…". Several: "aws, aws:b could each act in …".

**Proposing.** `actions.propose` routes before it resolves parameters, so a
lookup that fills a missing parameter reads the same tenant. If nothing can be
chosen while credentials exist, the action is `blocked` with that reason, and a
required playbook step that is blocked fails the run, as any policy block
does. If only some places have a credential, shoc acts where it can and adds
the rest to the reason. The chosen names are stored in the new column
`shoc.actions.acts_in` (migration 038).

**Running and undoing.** `execute` acts with each name in `acts_in`. With one
name, the result and undo keep the shape the action returns. With several, each
name's result and undo are kept under `acts_in`, and a name that succeeded on
an earlier attempt is not called again. Suspending an Okta user twice is an
error. `undo` runs each name's part separately, so a failure in one tenant
does not stop the others. An action proposed before any credential existed is
routed when it runs. An older row with no `acts_in` uses the provider's own
name.

**Ingest.** Before loading, `connectors.base.run` fills an empty
`cloud_account_uid` with the source's `account` setting or, failing that, the
connector's `account(settings)`. Okta returns its org host. GitLab returns its
group, or the instance host. The CrowdStrike, Falcon Data Replicator,
SentinelOne and Cloud Funnel mappings now read the CID or account ID their
records carry. `account:` entities never link cases (engine `NOT_LINKING`), so
this changes routing and labels, not grouping.

**Baselines.** A first-seen rule or hunt compared accounts with
`COALESCE(account, '')`. An Okta tuple stamped `acme.okta.com` after the
upgrade would then miss its own 30 days of history, which has no account, and
every Okta tuple would look new for a month. A Falcon DNS lookup with a CID
would also look new next to the same name in a Cloudflare Gateway log with
none. An event that names no account is now compared with every account. Two
events that both name an account are still compared only within it, so a user
familiar in one AWS account is still new in the next.

Principles touched: 5 (bounded autonomy: no action runs in a tenant nobody
connected), 7 (`tenant_id` is unchanged. This is about the customer's own
tenants of a vendor, not shoc's).

## Drawbacks

- An operator with two credentials on one platform has to type account IDs.
  The configure error names the problem and the source history shows the IDs.
- Events loaded before this change have no account for Okta, GitLab and the
  EDRs. Until new events arrive, a second credential on those platforms leaves
  their old cases ambiguous, and the action is blocked with that reason.
- A rule product shared by several vendors (`edr`) is told apart only by
  account. Wazuh records name no account, so Wazuh and a second EDR on the same
  `edr` provider need the source's `account` setting.

## Alternatives

- **Stamp the source name on every event and route by source.** One AWS
  organisation trail is one source covering many accounts, and response
  credentials are per account. The account is the tenant, and OCSF already has
  a column for it.
- **Act with every credential of the provider.** Signing a user out of two
  unrelated Okta orgs because a name matched is the wrong-tenant mistake this
  RFC exists to prevent.
- **Split `idp` into `okta` and `entra` providers.** That renames actions in
  29 playbooks, the policy and the contract, and still leaves two AWS accounts
  unsolved.
- **Do nothing.** A second tenant stays uncontainable, and an Entra case keeps
  reaching the Okta API.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: optional inputs `action.propose.credential`,
  `platform.lookup.case_uid` and `platform.lookup.credential`. Outputs
  `ActionRecord.acts_in` and `LookupAnswer.read_from`. `action.configure`
  validates the provider name. `source.list` rows gain `accounts`. Column
  `shoc.actions.acts_in`. Four mappings fill `cloud_account_uid`, an existing
  column. A first-seen baseline compares an event with no account against
  every account. A hunt finding's platform is its pack's `logsource.product`.

## Security considerations

Only a human configures credentials (`action.configure`, L2, unchanged). The
crew and log content can name a credential, but a name only narrows the
choice, so they cannot move an action to a tenant the target was not seen in.
When there is any doubt the decision is `blocked` with a reason, never a
guess. Accounts come from the platform's own events, which an attacker inside
the platform can shape only within that platform.

## Unresolved questions

- One AWS role assumed into many accounts (an organisation-wide responder) is
  one credential listing many accounts. Assuming a role per account is left
  for when a design partner runs it.
- The console does not show `acts_in` yet. That belongs to the console's own
  work.

## Adoption and migration

`shoc migrate` adds the column. Existing single credentials keep working with
no change. A second credential on a platform needs `accounts`, and configure
says so.
