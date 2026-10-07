# Response

shoc's agents read. Only the playbook runner acts, and only through typed
actions the autonomy policy has allowed. This page is the contract: what can
happen automatically, what waits for you, and what any of it can undo.

## Autonomy in three levels

| Level | Meaning |
| --- | --- |
| **L0** | Notify only. Nothing is ever executed. |
| **L1** | Runs automatically, but only reversible actions, on a confident, severe case, within a per-case budget. |
| **L2** | A human approves, in Slack or any client. **No agent can ever approve an L2 action.**[^mcp] |

[^mcp]: An assistant driven by a person with the `operator` or `admin` role can
    ask to approve, and shoc then asks that person to confirm in their client;
    the model cannot answer the prompt (RFC 0018). See
    [`security-model.md`](security-model.md#an-assistant-asks-the-person-confirms).

`SHOC_DRY_RUN=1` (the default for a new install) means every action is
planned, recorded and shown, and nothing is executed anywhere. Turn it off when
you trust what you see in `shoc action list`.

## The policy

[`content/policy.yaml`](https://github.com/pwnera/shoc/blob/main/content/policy.yaml) decides. It is YAML, evaluated in
code, and it is the only thing that decides:

```yaml
actions:
  aws.disable_access_key:
    autonomy: L1
    reversible: true
    min_confidence: 0.85
    severity_at_least: high
guards:
  protected_targets: ["user:*admin*", "role:prod-*"]
  require_citations: true
  max_auto_actions_per_case: 3
```

The rules it enforces, in order:

1. An action not named in the policy cannot be proposed at all.
2. A principal cannot exceed its ceiling: an external agent is capped at L0,
   an agent or a service at L1, and only a human reaches L2.
3. A case with no cited events gets no action, whatever the verdict says.
4. A protected target is never automatic.
5. An L1 action must be reversible, confident enough, severe enough, and inside
   the per-case budget. Failing any of those, it drops to L2 and waits.
6. An action marked `research_before_action` runs automatically only once its
   target has been researched and is not shared infrastructure; one marked
   `review_before_action` only once the IR Commander's review raised no
   objection. Either gate failing drops it to L2.

`shoc policy show` prints exactly what is in force.

## Where a proposal comes from, and where it goes

The IR Commander proposes. It is shown the action catalogue (every action that
exists, what it does, what it acts on, and what the policy will do with it), and
it proposes by exact name, because an action nobody can resolve is a sentence in a
chat table rather than a response. Each proposal is put to the policy as soon as
it is made:

- allowed without a human, and it is queued and runs;
- needing a human, and it waits as `proposed` with a deadline;
- naming an action that does not exist, and the case says so.

Every proposal carries a blast radius: how many users, hosts or accounts sit
behind the target, counted from the graph and cited from the Surveyor, and what
the company loses while it runs. A missing or uncertain count refuses the
action (D45).

An action the policy approved, and an L2 action a human approved, are both
picked up and run by the worker.

## When nobody approves

The company running shoc has one technical person and no security team, and most
days they do not open it. An action waiting for an approval is therefore an action
that may never happen, so waiting has a deadline of four hours. Past it:

- on a `high` or `critical` case, the SOC Manager pages the operator, at most
  once a day per case. An action still undecided four hours after the page, or
  one whose page could not go out, is rejected like any other;
- on anything lower, the action is rejected and the case records what was not
  done and why.

**Every L2 names the fallback that runs if nobody answers** (a narrower
reversible action, or an expiry) and the window after which it runs. An L2
with neither is incomplete and is rejected as one.

No role may choose `needs_human`, for the same reason: a case still
reaches that disposition without being chosen (no model, an LLM failure,
citations that did not survive verification), and when it does it is treated the
same way. After six hours at most, sooner when the case's own deadline is
shorter, it is told in the openspace that nobody is coming, and
the crew is sent back to reach a disposition on the evidence it has or to propose
the smallest reversible thing it can do by itself. `shoc/cases/unattended.py` is
where this lives; it rejects and it asks the SOC Manager for a page, and it
never approves anything or raises an action's autonomy.

**And every case carries a deadline of its own**, derived from its severity. On
expiry the role holding it (the Investigator, or the Commander once there is a
response) is re-woken and must either close it or say what it is still waiting
for. A `high` or `critical` case that expires twice pages.

## Actions

| Action | Target | Platform | Automatic? | Undo |
| --- | --- | --- | --- | --- |
| `aws.disable_access_key` | access key | aws | L1 | re-activates the key |
| `aws.quarantine_user` | the IAM user behind an access key | aws | L2 | detaches AWSCompromisedKeyQuarantineV3 |
| `aws.isolate_instance` | EC2 instance | aws | L2 | gives each network interface its recorded security groups |
| `aws.detach_user_policy` | IAM user | aws | L1 | re-attaches the policy |
| `aws.detach_role_policy` | IAM role | aws | L2 | re-attaches the policy |
| `aws.revoke_role_sessions` | IAM role | aws | L2 | removes the revocation policy |
| `aws.revoke_sessions` | access key (AKIA or ASIA) | aws | L2 | removes the revocation policy |
| `aws.start_cloudtrail_logging` | trail | aws | L1 | stops it again |
| `aws.start_config_recorder` | Config recorder | aws | L1 | stops it again |
| `aws.enable_guardduty` | GuardDuty detector | aws | L1 | suspends it again |
| `aws.block_s3_public_access` | S3 bucket | aws | L1, reviewed | restores the recorded block, or deletes it |
| `aws.cancel_key_deletion` | KMS key | aws | L1 | disables it, or schedules the deletion 30 days out |
| `aws.unshare_snapshot` | EBS snapshot or AMI | aws | L1 | adds the recorded grants back |
| `okta.revoke_sessions` | user | okta | L1 | none needed: they sign in again |
| `okta.remove_admin_role` | user | okta | L1 | gives the recorded role back |
| `okta.suspend_user` | user | okta | L2 | unsuspends |
| `okta.reset_password` | user | okta | L2 | none: Okta emails the user a link to set a new one |
| `okta.remove_factor` | MFA factor | okta | L2 | none: only the user can enrol it again |
| `entra.revoke_sessions` | user | entra, m365, azure | L1 | none needed: they sign in again |
| `entra.remove_admin_role` | user | entra | L1 | gives the recorded role back |
| `entra.suspend_user` | user | entra, m365, azure | L2 | enables the account |
| `entra.reset_password` | user | entra, m365, azure | L2 | none: the user sets a new password |
| `entra.remove_factor` | MFA method | entra, m365 | L2 | none: only the user can register it again |
| `m365.delete_inbox_rule` | mailbox rule | m365 | L1 | recreates the recorded rule |
| `m365.revoke_app_consent` | app grant | entra, m365 | L1 | restores the recorded grant |
| `m365.revoke_sessions` | user | m365 | L1 | none needed: they sign in again |
| `google.revoke_sessions` | user | google | L1 | none needed: they sign in again |
| `google.suspend_user` | user | google | L2 | unsuspends |
| `google.reset_password` | user | google | L2 | none: an administrator or recovery sets a new one |
| `google.disable_mail_forwarding` | mailbox | google | L1 | turns the recorded forwarding back on |
| `google.revoke_app_token` | app token | google | L2 | none: the user must grant it again |
| `github.make_repo_private` | repository | github | L2 | restores the previous visibility |
| `github.demote_org_owner` | user | github | L2 | restores the recorded role |
| `github.remove_collaborator` | user | github | L2 | re-invites with the recorded permission |
| `github.remove_deploy_key` | deploy key | github | L2 | adds the recorded public key back |
| `github.enable_secret_scanning` | repository | github | L2 | restores the recorded scanning settings |
| `gitlab.block_user` | user | gitlab | L2 | unblocks |
| `crowdstrike.isolate_host` | device | edr | L2 | lifts the containment |
| `crowdstrike.block_hash` | SHA-256 | edr | L1, reviewed | deletes the indicator |
| `sentinelone.isolate_host` | agent | edr | L2 | reconnects it |
| `sentinelone.block_hash` | SHA-1 or SHA-256 | edr | L1, reviewed | deletes the blocklist item |
| `defender.isolate_host` | machine | edr | L2 | releases it from isolation |
| `defender.block_hash` | SHA-1 or SHA-256 | edr | L1, reviewed | deletes the indicator |
| `wazuh.block_ip` | address, on one agent or all | edr | L2 | none: Wazuh's API cannot lift it, so it lasts until the agent's active-response timeout |
| `azure.stop_vm` | virtual machine | azure | L2 | starts it |
| `gcp.disable_service_account_key` | key | gcp | L1 | enables it |
| `gcp.disable_service_account` | service account | gcp | L2 | enables it |
| `gcp.disable_firewall_rule` | VPC firewall rule | gcp | L2 | restores its recorded state |
| `cloudflare.disable_api_token` | account API token | cloudflare | L1 | enables it again |
| `tailscale.deauthorize_device` | device | tailscale | L2 | authorizes it again |
| `tailscale.enable_key_expiry` | device | tailscale | L1 | restores the recorded setting |
| `tailscale.suspend_user` | user | tailscale | L2 | restores the user |
| `tailscale.revoke_key` | auth key or API token | tailscale | L2 | none: a revoked key stays revoked |
| `stripe.block_charge_card` | charge | stripe | L1 | deletes the block-list items |
| `anthropic.disable_api_key` | API key | anthropic | L1 | enables it again |
| `openai.delete_api_key` | API key | openai | L2 | none: OpenAI can only delete a key |
| `openai.limit_project` | project | openai | L1 | restores the recorded rate limits |
| `cloudflare.block_ip` | address | cloudflare | L1, researched and reviewed | deletes the rule |
| `notify.page` | on-call | any | L1 | resolves the page |

`aws.revoke_sessions` denies every session issued before now to the IAM user
behind a long-term key, which ends what the key minted with GetSessionToken or
GetFederationToken, or to the role an ASIA session key was assumed from. The
user, or the role, and which of the two it is, come from the events where the
key acted. The restore actions find their own target: `aws.get_defences` reads
which trail, recorder or detector is off in the credential's `regions`, and a
step whose service is on proposes nothing. `okta.remove_factor` and
`entra.remove_factor` with no `factor_id` remove the newest factor enrolled in
the last week, which `okta.recent_factor` or `entra.recent_factor` reads; with
none that recent, they propose nothing.

Stripe's API cannot revoke a key, remove a team member or hold payouts for the
account that calls it, so a Stripe takeover ends in a page. No playbook blocks an
address at the edge: the Cloudflare account rules name no attacker address, and
a Gateway rule's address is the company's own device.

An action only answers a case seen on its platform: the `logsource.product` of
the rules behind the case's findings. Anything else is blocked by policy with
the reason, left out of the actions the Commander is shown, and a playbook whose
required step is aimed at another platform does not match. A public S3 bucket is
an aws case, so `github.make_repo_private` cannot run on it, and neither can a
Cloudflare block for an address that only called the AWS API.

Each action is named after the vendor it calls (RFC 0031), so a playbook names
one step per vendor: `contain_endpoint_compromise` has a CrowdStrike, a
SentinelOne and a Defender isolation step. Before proposing an optional step,
the runner skips the ones that do not answer the case, with the reason in the
run report. On the case's platform, that is a vendor the case's cited events do
not come from (a CrowdStrike step on a SentinelOne alert). Through a link, or
when those events cannot be read, it is a vendor the company neither reads a
source of nor holds a credential for. The Commander is shown the same
narrowed list.

Credentials live apart from everything else and only the runner reads them.
They are not the source's: a source reads with a read-only key, and the
response credential is the one allowed to change things. In the console a
product's credential sits beside its logs on Connections › Products: its
Response view lists the acts the credential unlocks and holds its form, and a
source's Delivery view says which credential acts on what it sees, or links to
connect one. PagerDuty, which pages the on-call person, is on Connections ›
Services.

```bash
shoc credential configure --provider aws \
  --settings '{"region": "eu-west-1"}' \
  --secret-file -    # {"access_key_id": "…", "secret_access_key": "…"} on stdin
shoc credential list
shoc credential check --provider aws
shoc credential remove --provider aws
```

`credential.configure` saves the credential, then makes one read with it (who
an AWS key is, the Okta token's own user, a GitHub token's login) and says what
came back. A refusal does not undo the save, since the grant may come later;
`verify: false` skips the read, and a PagerDuty routing key is only proven by a
page. `credential.check` makes the same read again with what is stored, and
both keep what came back, so `credential.list` says when each credential last
worked or what the vendor refused. In the console a product's Response side
has its own Review (the acts, the credential, its last check and Check now),
Settings (the form) and Onboarding (how far it got, what to grant, and a click
path to make it on the vendor's side), beside the Collection side's. `credential.list` lists each credential with its accounts, the sources it
acts for and the fields it still lacks, never the secret. It also lists every
kind of connected source no credential covers yet, and paging, which every case
uses, and for each provider the log connectors whose own credential it is.
`source.list` gives each source the same answer as `response`. A secret field
left blank on a later `credential.configure` keeps the stored one.

Give each one the narrowest permission that works: `iam:UpdateAccessKey` for
disabling a key, `User.ReadWrite.All` for suspending an Entra user, and so on.
The `aws` actions above need `iam:PutUserPolicy`, `iam:PutRolePolicy` and their
`Delete` pairs, `cloudtrail:StartLogging`, `config:StartConfigurationRecorder`,
`guardduty:UpdateDetector`, `s3:PutBucketPublicAccessBlock`,
`kms:CancelKeyDeletion` with `kms:EnableKey`, `ec2:ModifySnapshotAttribute` and
`ec2:ModifyImageAttribute`, `iam:AttachUserPolicy` and `iam:DetachUserPolicy` for
`aws.quarantine_user`, and `ec2:CreateSecurityGroup`,
`ec2:RevokeSecurityGroupEgress` and `ec2:ModifyNetworkInterfaceAttribute` for
`aws.isolate_instance`, which makes one `shoc-isolation` group per VPC, with the
matching reads. `m365.revoke_sessions` needs `User.RevokeSessions.All`,
`entra.remove_factor` `UserAuthenticationMethod.ReadWrite.All`,
`entra.reset_password` `User-PasswordProfile.ReadWrite.All` and the User
Administrator role for the app (Privileged Authentication Administrator to reset
an administrator's), and
`google.disable_mail_forwarding` the `gmail.settings.sharing` scope in the
domain-wide delegation.
The `gcp` service account needs Service Account Key Admin for the key and
service-account actions, and Compute Security Admin for
`gcp.disable_firewall_rule`.

| Provider | Settings | Secret |
| --- | --- | --- |
| `aws` | optional `regions` or `region` (default us-east-1) | `access_key_id`, `secret_access_key` |
| `okta` | `org_url` | `api_token` (a super administrator's) |
| `entra` | | `tenant_id`, `client_id`, `client_secret` |
| `m365` | | `tenant_id`, `client_id`, `client_secret` |
| `google` | `admin_email` | `client_email`, `private_key` (domain-wide delegation) |
| `github` | | `token` |
| `gitlab` | `base_url` | `token` (admin, for blocking) |
| `crowdstrike` | `cloud` | `client_id`, `client_secret` |
| `sentinelone` | `console_url` | `api_token` |
| `defender` | | `tenant_id`, `client_id`, `client_secret` |
| `wazuh` | `api_url` (the server API, port 55000), optional `verify_tls`, `block_command` (default `!firewall-drop`) | `username`, `password` of an API user with `active-response:command`, `agent:read` and `syscheck:read` |
| `azure` | | `tenant_id`, `client_id`, `client_secret` |
| `gcp` | | `client_email`, `private_key` |
| `cloudflare` | `account_id` | `api_token` with `Account Firewall Access Rules: Edit` and `Account API Tokens: Edit` |
| `tailscale` | optional `tailnet` | `client_id`, `client_secret`, or `api_key` |
| `stripe` | optional `block_lists` (`{"card_fingerprint": "rsl_…", "email": "rsl_…"}`) | `api_key`, restricted to Charges read and Radar write |
| `anthropic` | | `admin_key` |
| `openai` | | `admin_key` |
| `notify` | | `routing_key` (PagerDuty Events v2) |

### Several tenants of one provider

A second tenant of a provider is a credential named `provider:label`, the way a
second account of a vendor is a source named `connector:label`. Each lists the
accounts it acts in, written as the platform's events write them: an AWS
account ID, an Entra tenant ID, a GCP project, a GitHub organisation, an Okta
org host, a CrowdStrike CID, a SentinelOne account ID. `source.list` shows the
accounts each source's events have named.

```bash
shoc credential configure --provider aws \
  --settings '{"accounts": ["111111111111"]}' --secret-file -
shoc credential configure --provider aws:staging \
  --settings '{"accounts": ["222222222222"]}' --secret-file -
```

When an action is proposed, shoc reads the case's findings that name its target.
Each finding gives the rule's platform and the account its events came from,
and shoc picks the credential that serves both. An action only ever uses its
own vendor's credentials, so an Entra target never reaches an Okta token, and a
key seen in the staging account is disabled with `aws:staging`. A target seen in two tenants is acted on
in both. The action lists where it acts in `acts_in`, and its undo runs there.

A tenant with no credential, or one that two credentials could both claim, is
written into the action's reason and the action is not taken there. With one
credential per provider, accounts are optional and nothing changes.
`credential.configure` refuses a credential that would overlap another: two on the
same platform with no accounts, or the same account named twice.
`action.propose` and `platform.lookup` take an optional `credential`. It
narrows the choice to that credential and can never send an action to a tenant
the target was not seen in. See RFC 0025.

An EDR alert names a local account (`jdoe`), a Gateway log names a person's
email, and a GitHub event names a GitHub login. The Okta and Entra sign-out,
suspension and password reset still answer those cases, for the
identity-provider login `identity.resolve` links the user to: the login
GitHub's SAML identity names, the same name in the IdP's events, or the one
login the IdP saw signing in from the user's laptop. The link reads every
identity provider's events, and each vendor's action goes ahead only if its own
events show that login signing in in the last 30 days. The action's target
becomes that login and its reason cites the events that link them. The IdP
tenant is the one whose events name the login. If nothing links the user, or
two logins could be it, the action is blocked with that reason and the local
name is never sent. See RFC 0027 and RFC 0031.

## Lookups

The logs say what happened. Some questions are about what is true now: which
admin roles a user holds, which rules sit on a mailbox, who owns an access key,
which laptops ran a file. `platform.lookup` asks the platform, with the same
credentials, and only ever reads. `platform.lookups` lists them:

| Lookup | Answers |
| --- | --- |
| `okta.get_user`, `entra.get_user` | status, admin roles with their assignment ids, MFA factors, last sign-in or password change |
| `okta.recent_factor`, `entra.recent_factor` | MFA factors with their ids, and the newest enrolled in the last week |
| `m365.list_inbox_rules` | each rule's id, and what it forwards, moves or deletes |
| `m365.list_app_consents` | the apps a user granted, their scopes and publisher, with grant ids |
| `google.get_user` | suspended, admin, 2-step enrolment, last sign-in |
| `google.list_app_tokens` | the apps a user granted, with client ids and scopes |
| `crowdstrike.get_host`, `sentinelone.get_host`, `defender.get_host` | hostname, OS, last user, addresses, last seen, containment |
| `crowdstrike.find_hash`, `sentinelone.find_hash`, `defender.find_hash` | which endpoints have seen a file |
| `wazuh.get_agent` | name, addresses, OS, groups, version, whether it is connected |
| `wazuh.find_file` | which files on an agent have an MD5, SHA-1 or SHA-256, from file integrity monitoring |
| `aws.get_access_key` | who owns a key, and when, where and on what it was last used |
| `aws.get_user` | an IAM user's policies, groups, keys and MFA devices |
| `aws.get_defences` | which trails, Config recorders and GuardDuty detectors are off |
| `aws.get_instance` | an EC2 instance's state, type, addresses, security groups, role and tags |
| `github.get_repo_access` | visibility and collaborators with their permission |
| `gitlab.get_user` | state, admin flag, 2FA, last sign-in |
| `azure.get_vm` | size, OS, power state, network interfaces, tags |
| `gcp.list_service_account_keys` | which keys exist, which are disabled, how old |
| `tailscale.get_device` | owner, addresses, OS, last seen, authorization, key expiry |
| `cloudflare.get_api_token` | an account token's name, status, address conditions, expiry and last use |
| `stripe.get_charge` | amount, status, Radar outcome, dispute, card fingerprint and email |
| `anthropic.get_api_key` | a Claude API key's name, status, workspace, who made it and when |
| `openai.get_api_key` | a project key's name, owner, redacted value, when it was made and last used |

The Investigator, the IR Commander and the Surveyor can call them while they
work. The Commander uses them for the ids a removal needs (a role assignment, a
rule, a grant) and again to verify the removal took. Results reach the model as
untrusted data. External agents over MCP cannot call `platform.lookup`, because
the value they would look up comes from log content an attacker wrote. Lookups
run in dry-run mode too, since they change nothing.

## Playbooks

A playbook names the rules it answers, the questions the crew must settle before
a verdict, and the steps the runner takes after one
([`content/playbooks/`](https://github.com/pwnera/shoc/tree/main/content/playbooks), RFC 0013). Every rule belongs to
exactly one playbook, and CI fails on a rule that has none.

```yaml
rules: [aws_access_key_created, aws_secrets_enumeration, hunt:aws_rare_api_operation]
questions:
  - id: first_use
    ask: When and from which address was the key first used?
benign_when:
  - The principal is a CI role and its operations match its last 30 days.
trigger:
  verdict: [malicious]
  entity_kinds: [key]
  severity_at_least: high
  min_confidence: 0.8
steps:
  - name: disable the access key
    action: aws.disable_access_key
    params: { access_key_id: "{{ entity.key }}" }
  - name: revoke older sessions for the role
    action: aws.revoke_role_sessions
    optional: true
    params: { role_name: "{{ platform.aws.role }}" }
```

The questions and benign conditions of every playbook whose rules fired on a case
go into the dossier the crew reads. The steps run only when the trigger matches
and a finding from one of the rules is on the case. A required step must fit the
platform of every rule the playbook answers, so in a playbook that spans
platforms the containment steps are optional and the page is the required one.

`{{ case.title }}` comes from the case and `{{ entity.key }}` is the first key
on it. A case holds every finding linked to it, so a step can name where its
target comes from (RFC 0026): `{{ rule.okta_sign_in_after_attack_from_address.user }}`
is the account that signed in, not one of the twenty a spray tried, and
`{{ platform.edr.device }}` is the EDR's device id, not the WARP device a
Gateway finding on the same case reported. A rule named this way must be one
the playbook answers. The kinds are `user`, `key`, `ip`, `host`, `device`,
`resource`, `role` (the role behind a session key), `file_hash`,
`process_hash` and `account`. Roles, hashes and accounts do not link findings
into a case.

An **optional** step whose parameters cannot be filled is skipped; a required
one stops the run and says what was missing.

A run walks its steps until one needs a human, one fails, or the playbook
finishes. Each step is a row, so a restart resumes exactly where it stopped, and
an action that is already `done` returns its recorded result instead of acting
twice.

```bash
shoc playbook list --case-uid CASE-1a2b…
shoc playbook run --playbook-id contain_leaked_cloud_key --case-uid CASE-1a2b…
shoc action list --state proposed
shoc action approve ACT-9f8e…          # only a human can do this
shoc playbook resume --run-uid RUN-…
shoc action undo ACT-9f8e…
```

### Merging a playbook here

The playbooks in `content/` change with a deploy. A person with
`playbooks:merge`, which the `operator` role holds, can add one to a running
deployment with `playbook.merge` (RFC 0033). It has the same shape, and its
steps use the actions `policy.show` lists with their required parameters and
platforms. `playbook.list` returns every playbook in that shape, so a shipped
one can be copied and changed.

```bash
shoc playbook merge --playbook-file suspend_on_push_fatigue.yaml --reason "suspend at once" --dry-run
shoc playbook merge --playbook-file suspend_on_push_fatigue.yaml --reason "suspend at once"
shoc playbook revert --playbook-id suspend_on_push_fatigue --reason "too blunt"
```

`--dry-run` runs the gate and writes nothing. The console does the same from
Response › Playbooks › New playbook: Check, then Merge.

A merged playbook takes the rules it names from the playbook that answered
them, and `playbook.revert` gives them back. The gate refuses a playbook that
would answer a rule worse than before: a required step that cannot run on the
rule's platform, a parameter that nothing fills, or a rule taken from a playbook
that can act on its platform by one that cannot. Merging the same id again
replaces it. Replacing or reverting a playbook cancels its open runs, and the
actions they proposed stay for a person to approve or reject. The policy decides
each of its steps, as it does for a shipped playbook.

## What this looks like in an incident

A CI access key leaks. Detections fire, the findings become one case, the crew
reaches `malicious` at 0.93 with citations, and
`contain_leaked_cloud_key` starts:

1. **page the on-call engineer**: L1. The runner hands it to the SOC Manager,
   which pages at once on a critical case and otherwise holds it for the weekly.
2. **revoke the sessions minted from the key**: L2, so it is left for a human
   to approve and the run goes on.
3. **disable the access key**: L1, reversible, in the account the key was seen
   in. The key's user comes from the events where the key acted.

The page and the disabled key need nobody awake, and both run in the same pass. The page goes first
so that a key IAM cannot disable (a role's session key) or a missing credential,
either of which fails the run, never costs it.

A step that is the kind of decision a person should make waits four hours for
an approval: making a repository private, suspending an account, revoking a
role's sessions in `contain_workload_credentials`. Playbooks page before such a
step and mark it optional, so the rest of the response does not wait behind
it. On a high or critical case the Manager pages once when the four hours run
out; if nobody decides after that, the action is rejected and the case says
what was not done.
