---
rfc: 0013
title: Give every rule a playbook that says how to investigate it and how to respond
status: draft
authors: ["@Rettila"]
created: 2026-09-27
requirements: ["DET-2", "RSP-2", "RSP-4", "RSP-7", "AGT-1", "ING-1"]
supersedes: null
---

# RFC 0013: Give every rule a playbook that says how to investigate it and how to respond

## Summary

Each of the 50 rules in `content/rules/` names one playbook, and each playbook
carries two things: the questions the crew has to answer before it reaches a
verdict, and the steps the runner takes once it has one. Fourteen playbooks cover
the 50 rules. Eleven are new; the three that exist today gain a `rules` list and
questions. CI refuses a rule that no playbook claims, and a platform that ships a
connector without actions of its own.

## Motivation

Today 3 playbooks exist for 50 rules, and none of them knows which rule it is for.
A playbook fires on a case's verdict, severity, confidence and entity kinds. That
has two consequences.

- Playbooks fire on the shape of a case, whatever detected it.
  `aws_cloudtrail_logging_disabled` is critical and keyed by a user, so a
  malicious verdict matches `contain_account_takeover`. Its first step,
  `idp.revoke_sessions`, is refused because the case comes from AWS
  (`out_of_scope` in `shoc/actions/base.py`), the step is not optional, and the
  run fails before it reaches the page. The trail stays off and nobody is told.
  The same happens to every high-severity AWS, GitHub or Google rule keyed by a
  user, and Google has no action at all.
- Analysis has no content per detection. The dossier shows the crew the findings
  and the evidence, and every role reasons from its own prompt. A human SOC works
  from a runbook per alert type ("was the key used from a new ASN, did the same
  principal create persistence, what did it read"). The crew answers whatever it
  happens to ask, so two cases from the same rule are investigated differently,
  and the Challenger has no stated list of benign explanations to test.

The fix is to make "which rule, which playbook" explicit and checked, and to put
the investigation questions next to the response steps they justify.

## Guide-level explanation

A playbook lists the rules it serves, the questions a case from those rules must
answer, the conditions under which it is benign, and the response.

```yaml
id: contain_leaked_cloud_key
title: Contain a leaked cloud access key
rules:
  - aws_access_key_created
  - aws_access_denied_burst
  - aws_discovery_burst
  - aws_secrets_enumeration
  - aws_iam_user_created
  - aws_console_password_set_for_user
questions:
  - id: first_use
    ask: When and from which address was the key first used, and has that address used any other credential in this tenant?
  - id: new_behaviour
    ask: Which API operations did the principal call in the last 24 hours that it never called in the 30 days before?
  - id: persistence
    ask: Did the same principal create an access key, user, login profile or role trust in the same window?
  - id: data_touched
    ask: Which secrets, buckets or snapshots did it read, and how many objects?
benign_when:
  - The principal is a CI or deployment role and its operations match its last 30 days.
  - A named engineer created the key and deleted an older key of the same user within the hour.
trigger:
  verdict: [malicious]
  severity_at_least: high
  min_confidence: 0.8
steps:
  - name: disable the access key
    action: aws.disable_access_key
    params: {access_key_id: "{{ entity.key }}", user_name: "{{ entity.user }}"}
  - name: page the on-call engineer
    action: notify.page
    params: {summary: "shoc contained a leaked key: {{ case.title }}", severity: critical, dedup_key: "{{ case.case_uid }}"}
```

When a case opens with a finding from `aws_secrets_enumeration`, the dossier gains
a section headed "Questions for this case (contain_leaked_cloud_key)". The
Investigator answers each question with event IDs, or says no events answer it.
The Challenger argues from `benign_when`. The IR Commander's verdict carries the
answers. If the verdict is malicious and the trigger matches, the runner starts
the steps as it does today.

`playbook.list --rule aws_secrets_enumeration` returns the one playbook for that
rule. `shoc new rule` asks which playbook the rule belongs to and adds it to that
playbook's `rules` list.

## Reference-level explanation

### Binding

- A playbook gains a required `rules: [rule_id, …]`. Each id must exist in
  `content/rules/`, and each rule id appears in exactly one playbook. One rule,
  one playbook keeps the answer to "what happens when this fires" in one place.
  A case holding findings from rules of two playbooks gets both.
- `Trigger.misses` gains one condition: the case holds a finding whose `rule_id`
  is in the playbook's `rules`. The finding rule ids come from `shoc.findings`
  for the case's `finding_uids`, the same query `dossier.findings` runs.
  `entity_kinds` and `attack_any` stay, and gate the response as today.
- Hunt findings (`rule_id = "hunt:<pack>"`) may be listed the same way. CI does
  not require it yet.

### Analysis

- `questions` is a list of `{id, ask}`; `benign_when` is a list of sentences. At
  least two questions per playbook.
- `build_dossier` adds the questions and benign conditions of every playbook
  whose `rules` intersect the case's findings. They are our content, so they are
  not quoted as untrusted data. Log content stays quoted (principle 6).
- The verdict gains `answers: [{question_id, answer, event_uids}]`. An answer
  with no event IDs is recorded as unanswered. Unanswered questions are stored
  on the case and listed on the shift report.
- Unanswered questions do not block the response. A critical case whose logging
  source for one question is not connected still has to be contained.

### Response

Steps keep their current format and pass through the policy unchanged. Where the
change the rule detected can only be undone by an action that does not exist
yet, the playbook contains the actor (disable the key, revoke the sessions) and
pages in the critical band. The missing actions are listed below and belong to
RSP-4.

A step only runs on a platform the case was seen on: `out_of_scope` in
`shoc/actions/base.py` refuses `idp.revoke_sessions` on a case whose findings all
come from Google or GitHub. So each playbook needs, for every platform among its
rules, an action that belongs to that platform. Steps for a second platform in
the same playbook are `optional`, so the one that does not apply is skipped.

### The map

The fourteen playbooks are in `content/playbooks/`, with their questions and
benign conditions. This table and the platform table below record the map as
this RFC was written. The playbook files are the current map, and
`tests/unit/test_rules_content.py` keeps every rule in exactly one of them; the
detection gap review of 2026-10-02 added GCP, GitLab, Azure, Anthropic,
GuardDuty, infostealer and phishing-site playbooks, and the actions
`github.remove_deploy_key`, `github.enable_secret_scanning` and
`gcp.disable_firewall_rule`. Required steps are marked; everything else is optional. The
page is required in every playbook that spans platforms, so it goes out whether
or not containment was allowed.

| Playbook | Rules | Steps (required in bold) | Missing actions |
|---|---|---|---|
| `contain_leaked_cloud_key` | `aws_access_key_created`, `aws_access_denied_burst`, `aws_discovery_burst`, `aws_secrets_enumeration`, `aws_iam_user_created`, `aws_console_password_set_for_user`, hunts `aws_identity_first_api_call`, `aws_rare_api_operation` | **disable key**, **page**, revoke role sessions | `aws.quarantine_principal` |
| `contain_aws_privilege_escalation` | `aws_admin_policy_attached`, `aws_role_trust_policy_changed`, `aws_organization_changed`, `aws_root_account_activity`, `aws_console_login_without_mfa` | disable key, **page** | `aws.quarantine_principal`, `aws.detach_policy`, `aws.restore_trust_policy` |
| `restore_aws_defences` | `aws_cloudtrail_logging_disabled`, `aws_config_recorder_stopped`, `aws_guardduty_disabled`, `aws_password_policy_weakened` | disable key, **page** | `aws.start_cloudtrail_logging`, `aws.start_config_recorder`, `aws.enable_guardduty`, `aws.restore_password_policy` |
| `contain_aws_data_exposure` | `aws_s3_bucket_made_public`, `aws_ebs_snapshot_shared`, `aws_s3_mass_object_read`, `aws_kms_key_disabled_or_deleted` | disable key, **page** | `aws.block_s3_public_access`, `aws.unshare_snapshot`, `aws.cancel_key_deletion` |
| `contain_account_takeover` | `okta_mfa_push_fatigue`, `okta_mfa_factors_reset`, hunt `okta_first_login_country` | **revoke sessions**, **page**, **suspend (L2)** | |
| `contain_password_spray` | `okta_login_failure_burst`, `entra_sign_in_failure_burst`, `aws_console_login_failure_burst` | revoke sessions, **page** | `idp.block_address` |
| `contain_admin_account_misuse` | `okta_admin_privilege_granted`, `entra_admin_role_assigned`, `okta_api_token_created`, `okta_admin_console_sign_in`, `okta_password_reset_by_admin`, `entra_password_reset_by_admin`, `okta_user_deactivated_or_deleted` | revoke sessions, **page**, suspend (L2) | `idp.remove_admin_role`, `idp.revoke_api_token`, `idp.reactivate_user` |
| `contain_identity_policy_tampering` | `okta_security_policy_changed`, `entra_conditional_access_changed`, `okta_identity_provider_added` | revoke sessions, **page** | `idp.deactivate_identity_provider`, `idp.restore_policy` |
| `revoke_third_party_app_access` | `entra_app_consent_granted`, `m365_app_consent_granted`, `github_oauth_app_authorized` | revoke sessions, **page** | `idp.revoke_app_grant`, `github.revoke_app_installation` |
| `contain_m365_account_abuse` | `m365_inbox_rule_created`, `m365_mailbox_permission_granted`, `m365_anonymous_sharing_link_created` | revoke sessions, **page** | `m365.disable_inbox_rule`, `m365.remove_mailbox_permission`, `m365.remove_sharing_link` |
| `contain_google_workspace_compromise` | `google_two_step_verification_disabled`, `google_admin_privilege_granted`, `google_oauth_token_authorized`, `google_drive_mass_download` | **page** | `google.sign_out_user`, `google.suspend_user`, `google.revoke_admin_role`, `google.revoke_token` |
| `contain_public_repository` | `github_repo_made_public` | **make private (L2)**, **page** | |
| `contain_github_org_tampering` | `github_member_role_elevated`, `github_protected_branch_removed`, `github_secret_changed` | **page** | `github.demote_owner`, `github.restore_branch_protection` |
| `contain_endpoint_compromise` | `edr_high_severity_detection`, `edr_ransomware_detection` | isolate host (L2), **page** | |

Google has a playbook of its own because no action acts on Google: grouped with
the Okta account-takeover playbook, its required `idp.revoke_sessions` step
would stop that playbook from ever matching a Google case. `waf.block_ip` is in
no playbook. It acts on Cloudflare, which is not the platform of any rule (D53).

### Every platform brings its actions

A platform is integrated when it has a connector, a mapping, rules and its own
actions. A connector PR that adds a platform also adds, at the least, the action
that cuts the attacker off on that platform (sign out or revoke the credential)
with dry run, undo where the platform allows it, and an entry in
`content/policy.yaml`. The actions that revert the platform's risky changes come
with the rules that detect those changes.

Where each platform stands today:

| Platform (rule `product`) | Connector | Rules | Actions today | Missing to contain |
|---|---|---|---|---|
| aws | `aws_cloudtrail`, `aws_guardduty` | 20 | `aws.disable_access_key`, `aws.revoke_role_sessions` | `aws.quarantine_principal` |
| okta | `okta` | 10 | `idp.revoke_sessions`, `idp.suspend_user` | |
| entra | `entra` | 5 | `idp.revoke_sessions`, `idp.suspend_user` | |
| m365 | `m365` | 4 | `idp.revoke_sessions`, `idp.suspend_user` | |
| github | `github` | 5 | `github.make_repo_private` | `github.demote_owner` |
| google | `google_workspace` | 4 | none | `google.sign_out_user`, `google.suspend_user` |
| edr | `crowdstrike`, `defender`, `sentinelone` | 2 | `edr.isolate_host` | |
| gitlab | `gitlab` | 0 | none | `gitlab.block_user` |
| gcp | `gcp_audit` | 0 | none | `gcp.disable_service_account_key` |
| azure | `azure_activity` | 0 | none | covered by `idp.*` once `azure` is in their `platforms` |

`notify.page` is not tied to a platform and fits every case.

### CI

`tests/unit/test_rules_content.py` checks that every rule is in exactly one
playbook's `rules`, that every id in a `rules` list is a rule or a hunt, that
every playbook has at least two questions and one step, and that every required
step fits the platform of every rule its playbook answers. A playbook with no
`rules` fails to load. A fourth check, still to come, walks the connectors:
every `source` maps to a rule `product`, and at least one action has that
product in its `platforms`. It starts with an allowlist of today's gaps (google,
gitlab, gcp, azure) that may only shrink.

### Who keeps it true

Writing the first fourteen playbooks by hand is a one-off. From here on the
Detection Engineer owns the binding. A rule it proposes carries its playbook in
the same diff, either as a new entry in an existing playbook's `rules` or as a
new playbook with questions and steps. Its health pass flags a rule whose
playbook cannot act on the rule's platform. The CI check is the backstop for a
rule written by a person.

## Drawbacks

- Fourteen playbooks that name 27 actions which do not exist yet. Until they
  exist, ten playbooks can only contain the actor and page, and the change the
  rule detected stays in place until the operator reverts it.
- The questions are prose. Their quality depends on who writes them, and a
  vague question produces a vague answer. Review of content catches this; code
  does not.
- A longer dossier. Two playbooks of four questions add about 30 lines to every
  prompt for a case.

## Alternatives

- `playbook:` on each rule instead of `rules:` on each playbook. It reads well
  from the rule, but the playbook then cannot show what it covers without a scan,
  and adding a rule edits one file either way. The `rules:` list also keeps the
  map above visible in fourteen files instead of fifty.
- One playbook per rule. Fifty files, most of them copies: the eight admin-misuse
  rules have the same questions and the same response.
- Analysis in the rule file (`investigate:` next to `detection:`). It keeps the
  questions closest to the logic, but rules in the same incident class would
  repeat them, and the response would still live elsewhere.
- Do nothing. Playbooks keep firing on the shape of a case, AWS, GitHub and
  Google cases keep matching nothing that can act on them, and each case is
  investigated from scratch.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: the playbook YAML gains `rules`, `questions` and
  `benign_when`, with `rules` required. `playbook.list` gains a `rule` filter.
  The verdict gains `answers`. The case gains `unanswered`. All are pre-1.0.

## Security considerations

- Questions and benign conditions come from `content/`, reviewed in git. They
  enter the prompt as our instructions. An attacker who can edit `content/`
  already controls the rules and the response.
- `benign_when` gives the Challenger a script for arguing a case down. The
  Challenger still has to cite events for each condition it claims, or the
  claim does not count (principle 6).
- No step gains autonomy. Every step goes through the policy as before, and the
  new playbooks use only actions the policy already knows.

## Unresolved questions

1. Medium-severity rules. `idp.revoke_sessions` requires `high` in
   `content/policy.yaml`, so a malicious verdict on `okta_password_reset_by_admin`
   or `github_secret_changed` proposes an L2 action that `shoc/cases/unattended.py`
   abandons after four hours. Either allow `idp.revoke_sessions` and
   `aws.quarantine_principal` at `medium` with `min_confidence: 0.9`, or accept
   that medium cases end with a disposition and no containment.
2. Ransomware. `edr.isolate_host` is L2, so `edr_ransomware_detection` waits up
   to four hours for a human while it encrypts. The policy has no condition on
   ATT&CK technique. Should it gain one (`when_attack: [T1486]` → L1)?
3. Restoring a previous configuration (`aws.restore_trust_policy`,
   `aws.restore_password_policy`, `idp.restore_policy`) needs the state before
   the change. CloudTrail and the Okta log carry the new value only. The
   Surveyor could snapshot these, or the actions stay out of scope.
4. Should an unanswered question cap the verdict's confidence below the
   trigger's `min_confidence`? It enforces evidence, and it also stops a
   critical containment because one log source is not connected.
5. Cross-product identity. An AWS or GitHub actor who is also an Okta user
   could have their Okta sessions revoked too, but `out_of_scope` refuses it
   today and nothing maps one identity to the other. RFC 0027 answers it for
   EDR, Cloudflare and GitHub cases: the IdP actions act on the login
   `identity.resolve` links the case's user to. AWS stays refused.
6. Which of the 27 missing actions ship in v0.3 alongside the six in RSP-4.
   The candidates for L1 are the reversible ones with no business reason to
   stay undone: `aws.start_cloudtrail_logging`, `aws.enable_guardduty`,
   `aws.start_config_recorder`, `aws.block_s3_public_access`,
   `aws.quarantine_principal`, `m365.disable_inbox_rule`. Google's two
   containment actions come first regardless, since Google has four rules and
   no action.

## Adoption and migration

- Add a requirement to `docs/prd.md`: RSP-8, "Every rule belongs to one playbook
  with investigation questions and response steps", targeted at v0.3 with DET-2.
- Land in three changes. First the binding, the eleven new playbooks with
  today's actions, the dossier section and the CI checks (done). Then `answers`
  on the verdict, `unanswered` on the case and the `rule` filter on
  `playbook.list`. Then the missing actions, one provider at a time, each added
  to its playbook as it lands.
- A tenant with its own playbooks in `content/playbooks/` gets a load error
  naming the playbooks without `rules`. There is no default: a playbook that
  claims no rule would never fire.
