---
rfc: 0014
title: Give every Tier 0 platform its response actions and live lookups
status: draft
authors: ["@Rettila"]
created: 2026-09-27
requirements: ["RSP-4", "AGT-1", "ING-1"]
supersedes: null
---

# RFC 0014: Give every Tier 0 platform its response actions and live lookups

## Summary

Every platform shoc ingests from (the ING-1 list) gets response actions of its
own, and the crew gets a way to read the live state of those platforms during an
investigation. The set of actions comes from the Splunk SOAR connectors for the
same products (`github.com/splunk-soar-connectors`), which document each
vendor's containment and investigation calls. We keep the ones that answer a
rule we ship and drop the rest. Where a rule needs a response the SOAR connector
lacks (Google sign-out, GitLab block, consent revocation), the call comes from
the vendor's own API, and the table says so. Reads go through one new capability,
`platform.lookup`, which uses the credentials the actions already use and never
writes.

## Motivation

Before this change, 8 actions covered 5 platforms.

- Google Workspace, GitLab, Azure and GCP had connectors and no action. A
  malicious Google case could only page, and `contain_google_workspace_compromise`
  said so in its description.
- Several playbooks ended in "needs actions shoc does not have yet": removing an
  inbox rule that forwards mail (the BEC case), revoking an app consent, taking
  back an admin role, detaching an admin policy, demoting a GitHub owner. With an
  absent operator, each of those ended in a page or in nothing.
- The crew could query events but not the platform. "Which admin roles does this
  user hold now", "which inbox rules forward mail", "who owns AKIA…", "which
  laptops ran this hash" have no answer in the logs, or only an old one. The
  Commander also had no way to learn the ids that removal actions need, such as
  a role assignment id or a rule id.

## Guide-level explanation

An operator configures one credential per provider, as today:

```bash
shoc action configure --provider m365 \
  --secret '{"tenant_id": "…", "client_id": "…", "client_secret": "…"}'
shoc action configure --provider google \
  --settings '{"admin_email": "secops-bot@example.com"}' \
  --secret '{"client_email": "…", "private_key": "…"}'
```

The Investigator, while working a BEC case, calls:

```json
{"lookup": "m365.list_inbox_rules", "params": {"user": "alice@example.com"}}
```

and cites the rule that forwards invoices outside the company. The IR Commander
proposes `m365.delete_inbox_rule` with that `rule_id`. The policy allows it at
L1: the rule is kept in the action record and recreated on undo. The same lookup
afterwards is the `verify` step.

`platform.lookups` lists every read, its parameters, and whether its provider is
configured.

### Actions added

| Action | Platform | From SOAR connector | Autonomy | Undo |
| --- | --- | --- | --- | --- |
| `idp.remove_admin_role` | okta, entra | okta `unassign role` | L1 | re-assigns the recorded role |
| `m365.delete_inbox_rule` | m365 | msgraphforoffice365 reads rules; the delete is Graph's | L1 | recreates the recorded rule |
| `m365.revoke_app_consent` | entra, m365 | none; Graph `oauth2PermissionGrants` | L1 | restores the recorded grant |
| `google.revoke_sessions` | google | none; Directory API `signOut` | L1 | none needed |
| `google.suspend_user` | google | none; Directory API `users.update` | L2 | unsuspends |
| `google.revoke_app_token` | google | none; Directory API `tokens.delete` | L2 | none: not reversible |
| `edr.block_hash` | edr | crowdstrikeoauth `upload indicator`, sentinelone `block hash`, microsoftdefenderforendpoint `submit indicator` | L1, reviewed | deletes the indicator |
| `aws.detach_user_policy` | aws | awsiam `detach policy` | L1 | re-attaches |
| `aws.detach_role_policy` | aws | awsiam `detach policy` | L2 | re-attaches |
| `github.demote_org_owner` | github | none; GitHub org memberships API | L2 | restores the recorded role |
| `github.remove_collaborator` | github | github `remove collaborator` | L2 | re-invites with the recorded permission |
| `gitlab.block_user` | gitlab | none; GitLab admin API | L2 | unblocks |
| `azure.stop_vm` | azure | microsoftazurecompute `stop vm` | L2 | starts |
| `gcp.disable_service_account_key` | gcp | googlecloudiam, disable instead of `delete serviceaccountkey` | L1 | enables |
| `gcp.disable_service_account` | gcp | googlecloudiam `disable serviceaccount` | L2 | enables |

### Lookups added

`idp.get_user`, `m365.list_inbox_rules`, `m365.list_app_consents`,
`google.get_user`, `google.list_app_tokens`, `edr.get_host`, `edr.find_hash`,
`aws.get_access_key`, `aws.get_user`, `github.get_repo_access`,
`gitlab.get_user`, `azure.get_vm`, `gcp.list_service_account_keys`.

### What was left out, and why

The SOAR connectors expose several hundred actions. Most of them are left out:

- **Destructive and irreversible calls** (`delete vm`, `delete user`,
  `delete serviceaccountkey`, `shutdown endpoint`, `delete email`). Where a
  reversible version exists we use it: disable a key or a service account,
  power off a VM.
- **Live response and scripts** (`run command`, `run script`, `put file`,
  RTR sessions). These give an agent a shell on an endpoint, which conflicts
  with principle 5. A human does this from the vendor console.
- **Anything that answers no rule we ship** (EC2 security-group isolation, S3
  public access block, Gmail trash and untrash, Teams). Each should come with
  the rule that needs it.
- **Generic `make request` and `run query`**. A typed action is what the policy
  can reason about.

## Reference-level explanation

- `shoc/actions/base.py` gains `BaseLookup`, `seg()` and `send()`. `BaseAction`
  and `BaseLookup` share the parameter check and HTTP client. `seg()`
  percent-encodes one path segment, so a user name taken from a log (`../roles`)
  cannot turn into another endpoint. Repository names, VM resource ids, service
  account emails, key ids and hashes are validated against patterns instead.
- Each platform module exports `ACTIONS` and `LOOKUPS`. `shoc.actions.lookups()`
  and `get_lookup()` load them the same way actions are loaded.
- `shoc/capabilities/platforms.py` adds `platform.lookups` (L0, every principal)
  and `platform.lookup` (L0, audited, human, agent and service only). It loads
  the provider's credentials with `credentials.load`, runs the lookup and returns
  the data. Lookups run under `SHOC_DRY_RUN`, since dry run is about changing
  things and a lookup changes nothing.
- The Investigator, the IR Commander and the Surveyor are offered both
  capabilities. Results are quoted to the model as untrusted data by
  `agents/tools.py`, and the existing per-turn lookup budget bounds them.
- A lookup made of several calls reports a section it lacked permission for as
  `unavailable` instead of failing the whole answer.
- The EDR actions now mint tokens with the connectors' OAuth helpers
  (CrowdStrike client credentials per cloud, the Defender for Endpoint scope). A
  static `access_token` in the secret still works.
- An action whose target can be a user or a role is two actions
  (`aws.detach_user_policy`, `aws.detach_role_policy`), because protected
  targets match on `<kind>:<target>` and `role:prod-*` must stay protected.
- `tests/unit/test_actions.py` fails when any product in `store.ocsf.PRODUCTS`
  has no action whose `platforms` covers it.

## Drawbacks

- Lookups use the same credentials as actions, so a credential with write
  permission is used for reads. A compromised lookup path could only issue the
  fixed GET calls written in these modules. It cannot reach the write endpoints.
- More actions in the catalogue make the Commander's prompt longer. It is
  already filtered to the case's platforms (D53).
- Each vendor API version is pinned in code. When a vendor changes an endpoint,
  the action fails loudly as a `StoreError`, and it does not act wrongly.

## Alternatives

- **Run the SOAR connectors themselves.** They depend on the SOAR platform
  runtime (`phantom.app`) and on vendor SDKs, which breaks principle 3 and the
  dependency budget. We read them as documentation of which calls matter.
- **One capability per lookup.** That adds 13 MCP tools and 13 entries in every
  role's tool list. One capability with a catalogue keeps the tool count flat.
- **Separate read-only credentials per provider.** Better least privilege, and a
  second credential for every platform to set up. Left as an unresolved
  question.
- **Do nothing.** Google, GitLab, Azure and GCP cases stay page-only, and BEC
  stays uncontained.

## Dependency and scope impact

- New dependencies: none. `xml.etree` (stdlib) parses IAM responses.
- New required services: none.
- Public contract changes: two new capabilities (`platform.lookups`,
  `platform.lookup`) and 15 new action names. Additive only.

## Security considerations

- `shoc/actions/` and `shoc/agents/` are security-sensitive paths and need two
  reviewers.
- `platform.lookup` excludes `external_agent`. The MCP gate keeps `intel:read`
  out for the same reason: a model reading attacker-written log content should
  not choose what shoc asks a vendor with shoc's credentials. The crew is
  allowed, because every call is audited, quoted as data and budgeted.
- Only the runner holds credentials for writes. A lookup reads them inside the
  capability and returns data, never the secret.
- New L1 actions are each reversible, each record what they removed, and each
  sit behind confidence and severity floors. `edr.block_hash` also requires
  peer review, because a wrong hash stops a real tool on every laptop.

## Unresolved questions

- Should a provider accept an optional read-only credential that lookups prefer?
- Should `platform.lookup` refuse a lookup whose platform is not on the case,
  as actions do? It takes no case today.
- Which of the omitted actions (EC2 isolation, S3 public access block, Gmail
  trash) come in with the rules that need them.

## Adoption and migration

No migration. Existing credentials keep working. A platform without configured
credentials shows `configured: false` in `platform.lookups`, and its actions
fail with the existing "set them with action.configure" error. New installs stay
in dry run.
