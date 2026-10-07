---
rfc: 0026
title: A playbook step names the findings its target comes from
status: accepted
authors: ["@Rettila"]
created: 2026-10-04
requirements: ["RSP-2", "RSP-4", "DET-1", "DET-3"]
supersedes: null
---

# RFC 0026: A playbook step names the findings its target comes from

## Summary

A step's parameters can read an entity from the findings of one rule,
`{{ rule.<rule_id>.<kind> }}`, or from the findings on one platform,
`{{ platform.<product>.<kind> }}`, as well as from the whole case,
`{{ entity.<kind> }}`. Findings carry four new entity kinds: `device` (the
source's id for the machine), `role` (the role behind a session key),
`process_hash` and `file_hash`. Roles and hashes do not join findings into a
case. `contain_password_spray` revokes the account that signed in,
`contain_endpoint_compromise` and `contain_infostealer` isolate the EDR's
device, `contain_endpoint_compromise` can block the file the alert named,
`contain_workload_credentials` revokes the role's sessions by the role entity,
and `contain_aws_guardduty_finding` acts on the key its finding named.

## Motivation

A review on 2026-10-04 found these wrong targets:

- `{{ entity.X }}` renders the alphabetically first value of kind X on the
  case. A spray case holds up to twenty users the address tried and one that
  signed in. `contain_password_spray` revoked the first name in the alphabet.
  In the `okta_spray_one_sign_in` scenario that is adam@example.com, who never
  got in. mia@example.com, who did, stayed signed in.
- `edr.isolate_host` took `{{ entity.resource }}`. That is the device id on
  CrowdStrike alerts and FDR (`aid`), on SentinelOne alerts (`agentId`) and on
  Defender alerts (`machineId`). On a Defender Advanced Hunting registry event
  it is the registry key, and on a SentinelOne Cloud Funnel registry or task
  event it is the key path or the task name. A Cloudflare Gateway finding on
  the same case adds the WARP device. Any of those can sort first.
- No entity carried a file hash, so `edr.block_hash` (L1, reviewed) had no
  playbook step.
- The role behind an ASIA session key was not an entity. IAM cannot disable a
  session key, so `contain_leaked_cloud_key` and `contain_aws_guardduty_finding`
  could only page. `contain_workload_credentials` read the role's name from
  `{{ entity.user }}`. On a case that also names an IAM user, that is whichever
  name sorts first. `aws.revoke_sessions` (RSP-4, landed the same day) now
  answers a session key by key: it reads the role a key was assumed from in the
  key's own events. The GuardDuty playbook still took `{{ entity.key }}`, the
  first key on the case, not the one in the finding.

## Guide-level explanation

```yaml
steps:
  - name: revoke the sessions of the account that signed in
    action: idp.revoke_sessions
    optional: true
    params:
      user: "{{ rule.okta_sign_in_after_attack_from_address.user }}"
  - name: isolate the host
    action: edr.isolate_host
    optional: true
    params:
      device_id: "{{ platform.edr.device }}"
```

`rule.<id>` reads the entities of that rule's findings on the case. The rule
must be one the playbook answers, or the playbook fails to load. A misspelt
rule would otherwise render empty on every case, and an optional step would be
skipped without a word. `platform.<product>` reads the findings of every rule
and hunt pack whose `logsource.product` is that product, as `engine.platforms`
does. A scope with no finding renders empty. The optional step is then
skipped, saying which parameter was unknown.

New kinds, from every event a finding cites:

| kind | column | links findings into a case |
|---|---|---|
| `device` | `device_uid` | yes |
| `role` | `actor_user_name` when `actor_user_type` is `AssumedRole` | no |
| `process_hash` | `process_hash_sha256` | no |
| `file_hash` | `file_hash_sha256` | no |

A case is named by the first kind present, in this order: key, user, host,
device, resource, role, ip, file_hash, process_hash, account.

## Reference-level explanation

- `shoc/detect/engine.py`: `ENTITY_COLUMNS` gains `device_uid`. The hash
  columns are kept in a separate `HASH_COLUMNS`, read only by `entities_of`.
  The graph and the Surveyor's inventory read `ENTITY_COLUMNS`, and a hash such
  as powershell.exe's would connect every laptop in the graph and add a row per
  binary to the attack surface. `entities_of` adds `role:` for an assumed role.
  `compiler.EVIDENCE_COLUMNS` selects the four columns on every rule.
- `shoc/cases/engine.py`: `NOT_LINKING` adds `role:`, `process_hash:` and
  `file_hash:`. A role is shared by every session that assumed it. An SSO
  permission-set role is shared by every engineer. The `user:` entity of the
  same name already links the session's own findings. `device:` links, since a
  device id names one machine. `LABEL_ORDER` adds the kinds above.
- `shoc/cases/playbooks.py`: `scoped_entities` reads the case's findings once
  and keeps the first value per kind per rule and per platform, sorted the way
  `entities_of_case` sorts. `context_for` stores both maps in the run's
  `context`. `Playbook.validate` refuses a `rule.<id>` the playbook does not
  answer.
- `edr.isolate_host` on SentinelOne: the device entity is the agent UUID
  (`device_uid` on alerts and on Cloud Funnel). The agent actions filter on the
  console's agent id, so a UUID is first looked up with `GET
  /web/api/v2.1/agents?uuids=`. An unknown UUID fails the action. CrowdStrike's
  `device_uid` is the `aid` its containment takes. Defender's is the
  `machineId` (Advanced Hunting `DeviceId`), which `/api/machines/{id}/isolate`
  takes.
- `contain_endpoint_compromise` blocks
  `{{ rule.edr_high_severity_detection.file_hash }}`, the file an EDR alert
  named, and never a hash from telemetry. A CrowdStrike alert on a script names
  its interpreter in the same field. The block is L1 only when research calls
  the hash malicious or suspicious (RSP-5) and the crew's review agrees
  (RSP-6). A powershell.exe hash fails research and waits for a person.
- `contain_workload_credentials` revokes `{{ entity.role }}` with
  `aws.revoke_role_sessions`, which stays L2.
  `contain_aws_guardduty_finding` disables and revokes the sessions of
  `{{ rule.aws_guardduty_finding.key }}`. `contain_leaked_cloud_key` keeps
  `{{ entity.key }}` and `aws.revoke_sessions`. A role step there on
  `{{ platform.aws.role }}` would ask a person to approve the same deny twice
  whenever the case's only key is a session key.

Upgrade: findings stored before this change have no `device`, `role` or hash
entities. A run on such a case renders those placeholders empty and skips the
optional steps that read them. Nothing is migrated. A finding refreshed by new
events is rewritten with the new kinds.

## Drawbacks

- A scope still picks one value. If two accounts signed in during a spray, the
  step revokes the first, and the page and the crew have to deal with the
  second. A step that fans out over every value would need one action row per
  value, and the runner keeps one per step.
- Every telemetry finding on a host now carries its processes' hashes. They do
  not link, but they make the case's entity list longer.

## Alternatives

- **A step-level `when_rules: [...]`** that restricts the whole step to some
  rules' findings. It covers the spray, but the isolate step would have to list
  all eighteen endpoint rules and hunt packs to leave out Gateway's WARP device.
  Both scopes fit in the placeholder, where the value is read.
- **Rank `entity.X` by finding severity or recency instead of the alphabet.**
  The failed attempts in a spray are as severe and as recent as the success.
- **Map SentinelOne's `agentId` into `device_uid`.** Alerts would then stop
  joining Cloud Funnel telemetry, which carries only the UUID, and Cloud Funnel
  findings would still need the lookup.
- **Resolve the device id inside `edr.isolate_host` from a host name.** Okta,
  Entra, Google and Tailscale also report devices by name. The lookup would be
  ambiguous on exactly the cases that span sources.

## Dependency and scope impact

- New dependencies: none.
- New required services: none.
- Public contract changes: playbook YAML gains the `rule.` and `platform.`
  template scopes; findings and `case_entities` carry four new entity kinds;
  `playbook_runs.context` gains `rule` and `platform`. No capability schema
  changes.

## Security considerations

The scopes only narrow which entity a step acts on. Autonomy, guards, research
and review apply as before. `role:prod-*` is a protected target, and a role
whose name matches is never revoked automatically. Entity values come from log
content: a forged CloudTrail record with `userIdentity.type: AssumedRole` puts
a `role:` on the case. The revocation that reads it is L2, so a person decides.

## Unresolved questions

- Whether a step should act on every value of a scope, not only the first.
- Whether `file_hash` should be read from alerts only, not from telemetry.
- `contain_leaked_cloud_key` acts on the first key. A case with a user's AKIA
  key and a stolen ASIA key revokes the user's sessions and not the role's.

## Adoption and migration

On by default. Playbooks that keep `{{ entity.X }}` render as before.
