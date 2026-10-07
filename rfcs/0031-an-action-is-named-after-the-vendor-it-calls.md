---
rfc: 0031
title: An action is named after the vendor it calls
status: accepted
authors: ["@Rettila"]
created: 2026-10-06
requirements: ["RSP-4", "RSP-2", "AGT-4"]
supersedes: null
---

# RFC 0031: An action is named after the vendor it calls

## Summary

The `idp`, `edr` and `waf` providers become `okta`, `entra`, `crowdstrike`,
`sentinelone`, `defender` and `cloudflare`, and the action types follow:
`idp.suspend_user` is now `okta.suspend_user` and `entra.suspend_user`,
`edr.isolate_host` is `crowdstrike.isolate_host`, `sentinelone.isolate_host` and
`defender.isolate_host`, and `waf.block_ip` is `cloudflare.block_ip`. A response
credential no longer has a flavour: its provider is the vendor. A playbook lists
one step per vendor, and the runner skips the steps for a vendor the case did
not come from. `notify.page` keeps its name.

## Motivation

Fourteen action modules are named after the API they call (`aws`, `google`,
`m365`, `tailscale`, …). Three are named after a category. They came from the
first response commit (`5d57a12`, 2026-09-24), which followed the layout in
CLAUDE.md (`actions/ # idp, aws, edr, github, waf`). Four days later D56 added
one module per platform, and the first three were never renamed.

The categories do not hold:

- Google Workspace is an identity provider with its own `google.*`, so
  `google.reset_password` sits beside `idp.reset_password`. Wazuh answers `edr`
  cases as `wazuh.*`. Cloudflare has `waf.block_ip` and
  `cloudflare.disable_api_token`, under two credentials for one account.
- One name covers different behaviour. `idp.reset_password` emails Okta's
  recovery link, and on Entra sets a password nobody holds. `edr.block_hash`
  takes a SHA-1 on SentinelOne and Defender, and sent one to CrowdStrike, which
  prevents on SHA-256 only. The grants differ by vendor. An approver reading `idp.reset_password` in Slack
  cannot tell which of these will happen, and the audit row's type does not
  name the API that was called.
- The vendor is guessed from the credential's fields. `shoc/actions/idp.py`
  picks Okta when the secret holds an `api_token` and Entra otherwise;
  `credentials.flavour_of` does the same from `org_url`. An `edr` credential
  saved without a flavour fails at its first call. D116 records an Entra case
  that reached the Okta API under the shared `idp` provider.
- The IR Commander named `okta.revoke_sessions` from memory for an action
  called `idp.revoke_sessions` (`catalogue` in `shoc/cases/actions.py`). A model
  expects the vendor in the name.

## Guide-level explanation

A playbook names each vendor's step. `contain_account_takeover`:

```yaml
steps:
  - name: revoke the user's sessions in Okta
    action: okta.revoke_sessions
    optional: true
    params:
      user: "{{ entity.user }}"
  - name: revoke the user's sessions in Entra ID
    action: entra.revoke_sessions
    optional: true
    params:
      user: "{{ entity.user }}"
  - name: page the on-call engineer
    action: notify.page
    …
```

On an Okta case, in dry run, the run report starts:

```text
revoke the user's sessions in Okta: [dry run] Sign jane@example.com out of every Okta session and invalidate refresh tokens
revoke the user's sessions in Entra ID: skipped, entra.revoke_sessions acts on entra or m365 or azure; this case comes from okta
```

On a SentinelOne alert, `contain_endpoint_compromise` proposes
`sentinelone.isolate_host` and skips the CrowdStrike and Defender steps: "this
case's events come from SentinelOne".

A credential is configured under the vendor's name, with no flavour:

```text
credential.configure provider=okta settings={org_url: https://acme.okta.com} secret={api_token: …}
credential.configure provider=crowdstrike settings={cloud: eu-1} secret={client_id: …, client_secret: …}
```

## Reference-level explanation

**Actions and lookups.** `shoc/actions/idp.py`, `edr.py` and `waf.py` are
replaced by `okta.py`, `entra.py`, `crowdstrike.py`, `sentinelone.py` and
`defender.py`, and `BlockIP` moves into `cloudflare.py`. Each class keeps one
vendor's branch of the old one, and `crowdstrike.block_hash` refuses a SHA-1
before calling.

| Was | Now |
| --- | --- |
| `idp.revoke_sessions`, `suspend_user`, `reset_password`, `remove_admin_role`, `remove_factor` | `okta.*` and `entra.*`, same verbs |
| `idp.get_user`, `idp.recent_factor` (lookups) | `okta.*` and `entra.*` |
| `edr.isolate_host`, `edr.block_hash` | `crowdstrike.*`, `sentinelone.*`, `defender.*` |
| `edr.get_host`, `edr.find_hash` (lookups) | `crowdstrike.*`, `sentinelone.*`, `defender.*` |
| `waf.block_ip` | `cloudflare.block_ip` |

`okta.*` acts on `okta`. `entra.*` keeps the platforms the old action listed
without `okta`: `entra`, `m365` and `azure` for sessions, suspension, password
and user reads; `entra` for admin roles; `entra` and `m365` for factors. The EDR
actions act on `edr`, and `cloudflare.block_ip` on `cloudflare`. The identity
actions keep `linked_from` (RFC 0027).

**Credentials.** `NEEDS` in `shoc/actions/base.py` is keyed by provider alone,
and `RESPONDS` maps a connector to the providers that act on it.
`FLAVOUR_PLATFORMS`, `flavour_of` and an instance's platforms go from
`shoc/cases/credentials.py`: a provider's credentials only ever serve that
provider's actions. `credential.list` drops `flavour` from its rows, and
`providers.<name>` holds the need itself in place of a `flavours` map. The
Cloudflare credential's token needs Account API Tokens: Edit and Account
Firewall Access Rules: Edit.

**Which vendor's step runs.** Before proposing an optional step, the runner
skips it when:

1. its action is out of scope for the case and follows no link, with
   `out_of_scope`'s reason. Such a step used to be proposed and then blocked,
   which left a blocked action on the case.
2. it acts on the case's platform, and the case's cited events come from none
   of the connectors its provider answers (`RESPONDS`, matched on each
   mapping's `metadata_product`). When those events cannot be read, the
   providers the tenant uses stand in.
3. it acts through a link, and the tenant uses no such provider: no credential
   of it and no connected source it answers.

The IR Commander's catalogue is narrowed the same way, so a SentinelOne case
shows `sentinelone.*` and not the other two EDRs. A required step is never
skipped; as before, a playbook whose required step cannot act on the case does
not trigger.

**Linked identity actions.** The link from a case's user to a login still reads
every identity provider's events (RFC 0027): Entra may record the laptop while
Okta records only the login. Each vendor's action then goes ahead only if its
own events show that login signing in within 30 days, and is blocked with that
reason otherwise.

**Migration** (`043_vendor_actions`). After the SQL, `shoc migrate` runs a hook
with the master key:

- Credentials. `idp[:label]` becomes `okta[:label]` or `entra[:label]` by its
  flavour, read as the old code read it, and a label that names the vendor is
  dropped (`idp:entra` becomes `entra`). `edr[:label]` becomes its flavour; one
  saved without a flavour never worked and is left for a person. `waf[:label]`
  becomes `cloudflare[:label]`, or `cloudflare:waf` when that name is taken.
  The `flavour` key leaves `settings`. The provider name is part of the
  secret's associated data (SEC-1), so each secret is opened under the old
  name and sealed under the new one. With credentials to rename and no
  `SHOC_MASTER_KEY`, the migration stops and nothing is applied.
- Actions. `type`, `fallback`, `acts_in` and `playbook_steps.action_type` are
  renamed. The vendor comes from the credential the action acted with; else,
  for an identity action, from the case's platforms (`okta`, or `entra`, `m365`
  and `azure`); else from the tenant's one IdP or EDR credential or source;
  else Okta and CrowdStrike. The last two decide only dry runs, unrun
  proposals and actions whose credential has since been removed.
- The audit log keeps the old names. Its rows are hash-chained (SEC-1), and they
  record what happened under the names of the time.

Principles touched: 1 (the action list in the registry and the contract
changes), 5 (each vendor action keeps the autonomy, gates and reversibility of
the action it replaces).

## Drawbacks

- More steps. `contain_account_takeover` goes from five steps to nine, and
  `contain_endpoint_compromise` from three to seven. A new identity provider or
  EDR adds a step to each playbook that answers its rules.
- More action types: seven become fourteen, four become twelve, and
  `content/policy.yaml` has an entry for each.
- A company running two EDRs still gives each credential its `accounts` (RFC
  0025), as before, for a case whose events come from both.
- A run waiting for an approval at the upgrade resumes by step index, as after
  any playbook edit, so it may resume one step early or late.
- `entra_sign_in_failure_burst` joins the rules no step can act on. The `idp`
  step that seemed to answer it read the Okta rule's user, which never rendered
  on an Entra case; only the Okta rule pairs a spray with a success.

## Alternatives

- **Keep the categories and show the vendor elsewhere**, in the label or in
  `acts_in`. The flavour guessing stays, and one name keeps covering a recovery
  email and a replaced password.
- **A step that lists alternatives** (`action: [okta.revoke_sessions,
  entra.revoke_sessions]`). That is new playbook syntax for what optional steps
  already do once the runner skips the ones that do not apply.
- **Dispatch by verb**, with the runner choosing `*.isolate_host` by the case.
  The playbook would no longer say which API it calls.
- **Do nothing.** The next identity provider or EDR joins a flavour, and the
  guessing grows with it.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: the action list in `contract/v1.json`, the
  `credential.list` row shape (no `flavour`) and `credential.configure`'s
  provider names. Nothing has been released and the contract freezes only at
  v0.4 (D14), so there is no deprecation period.

## Security considerations

- A secret is re-sealed under its new row name and is never written out in
  clear. One the master key cannot open is left under its old name.
- Each new action type keeps the policy entry of the one it replaces: no
  autonomy level, confidence floor or gate is loosened.
- An Okta credential can no longer receive an Entra case's target: routing finds
  credentials by provider, and the provider is the vendor.

## Unresolved questions

- `m365.revoke_sessions` and `entra.revoke_sessions` make the same Graph call
  under two credentials. The `m365` one exists for a company that signs in with
  Okta and runs Microsoft 365 mail. Merging them is a separate change.
- `notify.page` names a channel, not a vendor: a page is not an action on the
  platform a case came from (D56), and PagerDuty is the only pager. A second
  pager would raise the question again.

## Adoption and migration

Run `shoc migrate`. Credentials, actions and steps carry over, and nothing has
to be configured again. A playbook kept outside `content/` that names an `idp.`,
`edr.` or `waf.` action fails to load, naming the unknown action; it needs the
vendor's steps.
