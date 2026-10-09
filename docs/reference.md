# Capability reference

Generated from the registry in shoc 0.0.1 by `python scripts/generate_reference.py`. Do not edit by hand.

Every capability below exists on REST, MCP and the CLI. The response envelope is
always `{data, summary, citations}`.

| Capability | Scope | Autonomy | Principals | REST | MCP tool | CLI |
| --- | --- | --- | --- | --- | --- | --- |
| `action.approve` | `actions:approve` | L2 | human | `POST /v1/action/approve` | `action_approve` | `shoc action approve` |
| `action.expire` | `actions:run` | L0 | service | `POST /v1/action/expire` | `action_expire` | `shoc action expire` |
| `action.list` | `actions:read` | L0 | human, agent, external_agent, service | `POST /v1/action/list` | `action_list` | `shoc action list` |
| `action.propose` | `actions:propose` | L0 | human, agent, service | `POST /v1/action/propose` | `action_propose` | `shoc action propose` |
| `action.reject` | `actions:approve` | L0 | human | `POST /v1/action/reject` | `action_reject` | `shoc action reject` |
| `action.run` | `actions:run` | L0 | human, service | `POST /v1/action/run` | `action_run` | `shoc action run` |
| `action.undo` | `actions:run` | L2 | human | `POST /v1/action/undo` | `action_undo` | `shoc action undo` |
| `ask` | `ask:read` | L0 | human, agent, external_agent, service | `POST /v1/ask` | `ask` | `shoc ask` |
| `asset.identify` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/asset/identify` | `asset_identify` | `shoc asset identify` |
| `capability.describe` | `meta:read` | L0 | human, agent, external_agent, service | `POST /v1/capability/describe` | `capability_describe` | `shoc capability describe` |
| `capability.list` | `meta:read` | L0 | human, agent, external_agent, service | `POST /v1/capability/list` | `capability_list` | `shoc capability list` |
| `case.acknowledge` | `cases:transition` | L2 | human | `POST /v1/case/acknowledge` | `case_acknowledge` | `shoc case acknowledge` |
| `case.chase` | `cases:chase` | L0 | human, service | `POST /v1/case/chase` | `case_chase` | `shoc case chase` |
| `case.close` | `cases:transition` | L2 | human | `POST /v1/case/close` | `case_close` | `shoc case close` |
| `case.get` | `cases:read` | L0 | human, agent, external_agent, service | `POST /v1/case/get` | `case_get` | `shoc case get` |
| `case.history` | `cases:read` | L0 | human, agent, external_agent, service | `POST /v1/case/history` | `case_history` | `shoc case history` |
| `case.investigate` | `cases:investigate` | L0 | human, agent, service | `POST /v1/case/investigate` | `case_investigate` | `shoc case investigate` |
| `case.list` | `cases:read` | L0 | human, agent, external_agent, service | `POST /v1/case/list` | `case_list` | `shoc case list` |
| `case.recheck` | `cases:recheck` | L0 | human, service | `POST /v1/case/recheck` | `case_recheck` | `shoc case recheck` |
| `case.set_state` | `cases:transition` | L0 | human, agent | `POST /v1/case/set_state` | `case_set_state` | `shoc case set_state` |
| `config.apply` | `config:write` | L2 | human | `POST /v1/config/apply` | `config_apply` | `shoc config apply` |
| `config.plan` | `config:read` | L0 | human, service | `POST /v1/config/plan` | `config_plan` | `shoc config plan` |
| `credential.check` | `actions:configure` | L0 | human, service | `POST /v1/credential/check` | `credential_check` | `shoc credential check` |
| `credential.configure` | `actions:configure` | L2 | human | `POST /v1/credential/configure` | `credential_configure` | `shoc credential configure` |
| `credential.list` | `actions:read` | L0 | human, agent, external_agent, service | `POST /v1/credential/list` | `credential_list` | `shoc credential list` |
| `credential.remove` | `actions:configure` | L2 | human | `POST /v1/credential/remove` | `credential_remove` | `shoc credential remove` |
| `detect.run` | `detection:run` | L0 | human, agent, service | `POST /v1/detect/run` | `detect_run` | `shoc detect run` |
| `detection.backlog` | `detection:read` | L0 | human, agent, external_agent, service | `POST /v1/detection/backlog` | `detection_backlog` | `shoc detection backlog` |
| `detection.decide` | `detection:write` | L0 | human | `POST /v1/detection/decide` | `detection_decide` | `shoc detection decide` |
| `detection.merge` | `detection:merge` | L0 | human, agent | `POST /v1/detection/merge` | `detection_merge` | `shoc detection merge` |
| `detection.propose` | `detection:write` | L0 | human, agent | `POST /v1/detection/propose` | `detection_propose` | `shoc detection propose` |
| `detection.revert` | `detection:merge` | L0 | human, agent | `POST /v1/detection/revert` | `detection_revert` | `shoc detection revert` |
| `detection.work` | `detection:work` | L0 | human, service, agent | `POST /v1/detection/work` | `detection_work` | `shoc detection work` |
| `events.ingest` | `events:write` | L0 | human, service | `POST /v1/events/ingest` | `events_ingest` | `shoc events ingest` |
| `events.query` | `events:read` | L0 | human, agent, external_agent, service | `POST /v1/events/query` | `events_query` | `shoc events query` |
| `events.retain` | `events:retain` | L0 | human, service | `POST /v1/events/retain` | `events_retain` | `shoc events retain` |
| `events.summarize` | `events:read` | L0 | human, agent, external_agent, service | `POST /v1/events/summarize` | `events_summarize` | `shoc events summarize` |
| `finding.get` | `findings:read` | L0 | human, agent, external_agent, service | `POST /v1/finding/get` | `finding_get` | `shoc finding get` |
| `finding.list` | `findings:read` | L0 | human, agent, external_agent, service | `POST /v1/finding/list` | `finding_list` | `shoc finding list` |
| `finding.set_status` | `findings:write` | L0 | human, agent | `POST /v1/finding/set_status` | `finding_set_status` | `shoc finding set_status` |
| `graph.neighbours` | `graph:read` | L0 | human, agent, external_agent, service | `POST /v1/graph/neighbours` | `graph_neighbours` | `shoc graph neighbours` |
| `graph.refresh` | `graph:write` | L0 | human, agent, service | `POST /v1/graph/refresh` | `graph_refresh` | `shoc graph refresh` |
| `health.audit` | `audit:read` | L0 | human, agent, service | `POST /v1/health/audit` | `health_audit` | `shoc health audit` |
| `health.cost` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/cost` | `health_cost` | `shoc health cost` |
| `health.jobs` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/jobs` | `health_jobs` | `shoc health jobs` |
| `health.quality` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/quality` | `health_quality` | `shoc health quality` |
| `health.rules` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/rules` | `health_rules` | `shoc health rules` |
| `health.sources` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/sources` | `health_sources` | `shoc health sources` |
| `health.status` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/health/status` | `health_status` | `shoc health status` |
| `hunt.backlog` | `hunts:read` | L0 | human, agent, external_agent, service | `POST /v1/hunt/backlog` | `hunt_backlog` | `shoc hunt backlog` |
| `hunt.daily` | `hunts:work` | L0 | human, agent, service | `POST /v1/hunt/daily` | `hunt_daily` | `shoc hunt daily` |
| `hunt.decide` | `hunts:work` | L0 | human | `POST /v1/hunt/decide` | `hunt_decide` | `shoc hunt decide` |
| `hunt.merge` | `hunts:merge` | L0 | human, agent | `POST /v1/hunt/merge` | `hunt_merge` | `shoc hunt merge` |
| `hunt.pack` | `hunts:work` | L0 | human, agent, service | `POST /v1/hunt/pack` | `hunt_pack` | `shoc hunt pack` |
| `hunt.propose` | `hunts:work` | L0 | human, agent | `POST /v1/hunt/propose` | `hunt_propose` | `shoc hunt propose` |
| `hunt.results` | `hunts:read` | L0 | human, agent, external_agent, service | `POST /v1/hunt/results` | `hunt_results` | `shoc hunt results` |
| `hunt.revert` | `hunts:merge` | L0 | human, agent | `POST /v1/hunt/revert` | `hunt_revert` | `shoc hunt revert` |
| `hunt.run` | `hunts:run` | L0 | human, agent, external_agent, service | `POST /v1/hunt/run` | `hunt_run` | `shoc hunt run` |
| `hunt.suggest` | `hunts:read` | L0 | human, agent, external_agent, service | `POST /v1/hunt/suggest` | `hunt_suggest` | `shoc hunt suggest` |
| `hunt.work` | `hunts:work` | L0 | human, agent, service | `POST /v1/hunt/work` | `hunt_work` | `shoc hunt work` |
| `identity.resolve` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/identity/resolve` | `identity_resolve` | `shoc identity resolve` |
| `intel.add` | `intel:write` | L0 | human, agent, external_agent | `POST /v1/intel/add` | `intel_add` | `shoc intel add` |
| `intel.configure` | `intel:configure` | L0 | human | `POST /v1/intel/configure` | `intel_configure` | `shoc intel configure` |
| `intel.digest` | `intel:write` | L0 | human, agent, external_agent, service | `POST /v1/intel/digest` | `intel_digest` | `shoc intel digest` |
| `intel.list` | `intel:read` | L0 | human, agent, external_agent, service | `POST /v1/intel/list` | `intel_list` | `shoc intel list` |
| `intel.lookup` | `intel:read` | L0 | human, agent, external_agent, service | `POST /v1/intel/lookup` | `intel_lookup` | `shoc intel lookup` |
| `intel.refresh` | `intel:write` | L0 | human, agent, external_agent, service | `POST /v1/intel/refresh` | `intel_refresh` | `shoc intel refresh` |
| `intel.remove` | `intel:write` | L0 | human, agent, external_agent | `POST /v1/intel/remove` | `intel_remove` | `shoc intel remove` |
| `intel.reports` | `intel:read` | L0 | human, agent, external_agent, service | `POST /v1/intel/reports` | `intel_reports` | `shoc intel reports` |
| `llm.configure` | `llm:write` | L2 | human | `POST /v1/llm/configure` | `llm_configure` | `shoc llm configure` |
| `llm.show` | `llm:read` | L0 | human, service | `POST /v1/llm/show` | `llm_show` | `shoc llm show` |
| `manager.deliver` | `manager:deliver` | L0 | human, service | `POST /v1/manager/deliver` | `manager_deliver` | `shoc manager deliver` |
| `mapping.test` | `sources:read` | L0 | human, agent, external_agent, service | `POST /v1/mapping/test` | `mapping_test` | `shoc mapping test` |
| `mapping.write` | `sources:write` | L0 | human | `POST /v1/mapping/write` | `mapping_write` | `shoc mapping write` |
| `memory.add_fact` | `memory:write` | L0 | human, agent, external_agent | `POST /v1/memory/add_fact` | `memory_add_fact` | `shoc memory add_fact` |
| `memory.search` | `memory:read` | L0 | human, agent, external_agent, service | `POST /v1/memory/search` | `memory_search` | `shoc memory search` |
| `metrics.export` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/metrics/export` | `metrics_export` | `shoc metrics export` |
| `metrics.get` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/metrics/get` | `metrics_get` | `shoc metrics get` |
| `openspace.post` | `cases:write` | L0 | human, agent, external_agent | `POST /v1/openspace/post` | `openspace_post` | `shoc openspace post` |
| `ops.alerts` | `health:read` | L0 | human, agent, external_agent, service | `POST /v1/ops/alerts` | `ops_alerts` | `shoc ops alerts` |
| `own.add` | `own:write` | L2 | human | `POST /v1/own/add` | `own_add` | `shoc own add` |
| `own.list` | `own:read` | L0 | human, agent | `POST /v1/own/list` | `own_list` | `shoc own list` |
| `own.remove` | `own:write` | L0 | human | `POST /v1/own/remove` | `own_remove` | `shoc own remove` |
| `platform.lookup` | `platforms:lookup` | L0 | human, agent, service | `POST /v1/platform/lookup` | `platform_lookup` | `shoc platform lookup` |
| `platform.lookups` | `platforms:read` | L0 | human, agent, external_agent, service | `POST /v1/platform/lookups` | `platform_lookups` | `shoc platform lookups` |
| `playbook.get` | `playbooks:read` | L0 | human, agent, external_agent, service | `POST /v1/playbook/get` | `playbook_get` | `shoc playbook get` |
| `playbook.list` | `playbooks:read` | L0 | human, agent, external_agent, service | `POST /v1/playbook/list` | `playbook_list` | `shoc playbook list` |
| `playbook.merge` | `playbooks:merge` | L0 | human | `POST /v1/playbook/merge` | `playbook_merge` | `shoc playbook merge` |
| `playbook.resume` | `playbooks:run` | L0 | human, service, agent | `POST /v1/playbook/resume` | `playbook_resume` | `shoc playbook resume` |
| `playbook.revert` | `playbooks:merge` | L0 | human | `POST /v1/playbook/revert` | `playbook_revert` | `shoc playbook revert` |
| `playbook.run` | `playbooks:run` | L0 | human, service, agent | `POST /v1/playbook/run` | `playbook_run` | `shoc playbook run` |
| `playbook.runs` | `playbooks:read` | L0 | human, agent, external_agent, service | `POST /v1/playbook/runs` | `playbook_runs` | `shoc playbook runs` |
| `policy.show` | `policy:read` | L0 | human, agent, external_agent, service | `POST /v1/policy/show` | `policy_show` | `shoc policy show` |
| `posture.exposure` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/posture/exposure` | `posture_exposure` | `shoc posture exposure` |
| `posture.get` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/posture/get` | `posture_get` | `shoc posture get` |
| `report.get` | `reports:read` | L0 | human, agent, external_agent, service | `POST /v1/report/get` | `report_get` | `shoc report get` |
| `report.send` | `reports:send` | L0 | human, service | `POST /v1/report/send` | `report_send` | `shoc report send` |
| `rule.backtest` | `rules:read` | L0 | human, agent, external_agent, service | `POST /v1/rule/backtest` | `rule_backtest` | `shoc rule backtest` |
| `rule.list` | `rules:read` | L0 | human, agent, external_agent, service | `POST /v1/rule/list` | `rule_list` | `shoc rule list` |
| `rule.test` | `rules:read` | L0 | human, agent, external_agent, service | `POST /v1/rule/test` | `rule_test` | `shoc rule test` |
| `search` | `ask:read` | L0 | human, agent, external_agent, service | `POST /v1/search` | `search` | `shoc search` |
| `slack.configure` | `slack:write` | L2 | human | `POST /v1/slack/configure` | `slack_configure` | `shoc slack configure` |
| `slack.notify` | `slack:write` | L0 | human, agent | `POST /v1/slack/notify` | `slack_notify` | `shoc slack notify` |
| `slack.show` | `slack:read` | L0 | human, service | `POST /v1/slack/show` | `slack_show` | `shoc slack show` |
| `snapshot.list` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/snapshot/list` | `snapshot_list` | `shoc snapshot list` |
| `source.configure` | `sources:write` | L0 | human | `POST /v1/source/configure` | `source_configure` | `shoc source configure` |
| `source.list` | `sources:read` | L0 | human, agent, external_agent, service | `POST /v1/source/list` | `source_list` | `shoc source list` |
| `source.onboard` | `sources:onboard` | L0 | human, service, agent | `POST /v1/source/onboard` | `source_onboard` | `shoc source onboard` |
| `source.push_key` | `sources:write` | L0 | human | `POST /v1/source/push_key` | `source_push_key` | `shoc source push_key` |
| `source.remove` | `sources:write` | L0 | human | `POST /v1/source/remove` | `source_remove` | `shoc source remove` |
| `source.sample` | `sources:sample` | L0 | human, agent, service | `POST /v1/source/sample` | `source_sample` | `shoc source sample` |
| `source.sync` | `sources:sync` | L0 | human, agent, service | `POST /v1/source/sync` | `source_sync` | `shoc source sync` |
| `sso.configure` | `sso:write` | L2 | human | `POST /v1/sso/configure` | `sso_configure` | `shoc sso configure` |
| `sso.show` | `sso:read` | L0 | human | `POST /v1/sso/show` | `sso_show` | `shoc sso show` |
| `stream.deliver` | `stream:deliver` | L0 | human, service | `POST /v1/stream/deliver` | `stream_deliver` | `shoc stream deliver` |
| `stream.subscribe` | `stream:write` | L0 | human | `POST /v1/stream/subscribe` | `stream_subscribe` | `shoc stream subscribe` |
| `stream.tail` | `stream:read` | L0 | human, agent, external_agent, service | `POST /v1/stream/tail` | `stream_tail` | `shoc stream tail` |
| `suppression.list` | `detection:read` | L0 | human, agent, external_agent, service | `POST /v1/suppression/list` | `suppression_list` | `shoc suppression list` |
| `surface.list` | `posture:read` | L0 | human, agent, external_agent, service | `POST /v1/surface/list` | `surface_list` | `shoc surface list` |
| `timeline.build` | `cases:read` | L0 | human, agent, external_agent, service | `POST /v1/timeline/build` | `timeline_build` | `shoc timeline build` |
| `timeline.extend` | `cases:read` | L0 | human, agent, external_agent, service | `POST /v1/timeline/extend` | `timeline_extend` | `shoc timeline extend` |
| `token.create` | `tokens:write` | L2 | human | `POST /v1/token/create` | `token_create` | `shoc token create` |
| `token.list` | `tokens:read` | L0 | human | `POST /v1/token/list` | `token_list` | `shoc token list` |
| `token.revoke` | `tokens:write` | L2 | human | `POST /v1/token/revoke` | `token_revoke` | `shoc token revoke` |
| `user.invite` | `users:write` | L2 | human | `POST /v1/user/invite` | `user_invite` | `shoc user invite` |
| `user.list` | `users:read` | L0 | human | `POST /v1/user/list` | `user_list` | `shoc user list` |
| `user.me` | `meta:read` | L0 | human, agent, external_agent, service | `POST /v1/user/me` | `user_me` | `shoc user me` |
| `user.reset` | `users:write` | L2 | human | `POST /v1/user/reset` | `user_reset` | `shoc user reset` |
| `user.update` | `users:write` | L2 | human | `POST /v1/user/update` | `user_update` | `shoc user update` |

## `action.approve`

Approve a response action the crew proposed.

- **Scope:** `actions:approve` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "ApprovalInput",
  "properties": {
    "action_uid": {
      "type": "string",
      "description": "The action to approve"
    },
    "note": {
      "type": "string",
      "description": "Anything the record should say"
    }
  },
  "additionalProperties": false,
  "required": [
    "action_uid"
  ]
}
```

## `action.expire`

Undo a block whose lifetime ran out.

- **Scope:** `actions:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** service

Input schema:

```json
{
  "type": "object",
  "title": "ExpireInput",
  "properties": {
    "action_uid": {
      "type": "string",
      "description": "The done action whose `ttl_minutes` ran out"
    }
  },
  "additionalProperties": false,
  "required": [
    "action_uid"
  ]
}
```

## `action.list`

List response actions and what they are waiting for.

- **Scope:** `actions:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ActionFilter",
  "properties": {
    "state": {
      "type": "string",
      "description": "proposed, approved, running, done, failed, rejected or blocked"
    },
    "case_uid": {
      "type": "string",
      "description": "Only actions for this case"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows"
    }
  },
  "additionalProperties": false
}
```

## `action.propose`

Propose a response action; the policy decides whether a human must approve it.

- **Scope:** `actions:propose` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ProposeInput",
  "properties": {
    "action": {
      "type": "string",
      "description": "Action type, e.g. aws.disable_access_key"
    },
    "params": {
      "type": "object",
      "additionalProperties": {},
      "description": "Action parameters, e.g. {'access_key_id': 'AKIA\u2026'}"
    },
    "case_uid": {
      "type": "string",
      "description": "The case this responds to"
    },
    "rationale": {
      "type": "string",
      "description": "Why, in one sentence"
    },
    "credential": {
      "type": "string",
      "description": "One of the provider's credentials, e.g. aws:staging. Left empty, shoc acts in every account the target was seen in; a name only narrows that"
    }
  },
  "additionalProperties": false,
  "required": [
    "action"
  ]
}
```

## `action.reject`

Reject a proposed action.

- **Scope:** `actions:approve` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "ApprovalInput",
  "properties": {
    "action_uid": {
      "type": "string",
      "description": "The action to approve"
    },
    "note": {
      "type": "string",
      "description": "Anything the record should say"
    }
  },
  "additionalProperties": false,
  "required": [
    "action_uid"
  ]
}
```

## `action.run`

Run an approved action now.

- **Scope:** `actions:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "RunActionInput",
  "properties": {
    "action_uid": {
      "type": "string",
      "description": "The approved action to run"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Plan it without touching anything"
    }
  },
  "additionalProperties": false,
  "required": [
    "action_uid"
  ]
}
```

## `action.undo`

Roll a completed action back.

- **Scope:** `actions:run` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "ApprovalInput",
  "properties": {
    "action_uid": {
      "type": "string",
      "description": "The action to approve"
    },
    "note": {
      "type": "string",
      "description": "Anything the record should say"
    }
  },
  "additionalProperties": false,
  "required": [
    "action_uid"
  ]
}
```

## `ask`

Ask the crew a question, in a conversation, and get a cited answer.

- **Scope:** `ask:read` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Question",
  "properties": {
    "question": {
      "type": "string",
      "description": "A plain-language question, e.g. 'what happened with AKIA\u2026?'"
    },
    "since": {
      "type": "string",
      "description": "How far back to look"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows per section"
    },
    "history": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "description": "Earlier turns of this conversation, oldest first: {role: operator|manager, text}"
    }
  },
  "additionalProperties": false,
  "required": [
    "question"
  ],
  "description": "Ask the crew something. An answer about a case, key, address, account or finding cites the events behind it."
}
```

## `asset.identify`

What an address, host or identity is to this company: declared, listed or observed.

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "IdentifyInput",
  "properties": {
    "target": {
      "type": "string",
      "description": "An address, host or identity, typed (ip:\u2026, user:\u2026) or bare"
    },
    "days": {
      "type": "integer",
      "description": "How far back to look at behaviour"
    }
  },
  "additionalProperties": false,
  "required": [
    "target"
  ]
}
```

## `capability.describe`

Describe one capability: schemas, scope, autonomy and surfaces.

- **Scope:** `meta:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "CapabilityRef",
  "properties": {
    "name": {
      "type": "string",
      "description": "Capability name, e.g. events.query"
    }
  },
  "additionalProperties": false,
  "required": [
    "name"
  ]
}
```

## `capability.list`

List every capability, with its schemas and how each surface exposes it.

- **Scope:** `meta:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "CapabilityFilter",
  "properties": {
    "area": {
      "type": "string",
      "description": "Only capabilities in this area, e.g. events, finding, rule"
    },
    "principal": {
      "type": "string",
      "description": "Only capabilities this principal kind may call"
    }
  },
  "additionalProperties": false
}
```

## `case.acknowledge`

Acknowledge a case closed without its containment, so it stops asking for you.

- **Scope:** `cases:transition` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "CaseRef",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "Case identifier, e.g. CASE-1a2b\u2026"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `case.chase`

Page, abandon or send the crew back on whatever has waited past its deadline.

- **Scope:** `cases:chase` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `case.close`

Close a case with your disposition: the crew stops, and what it means is routed.

- **Scope:** `cases:transition` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "CloseInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case to close"
    },
    "disposition": {
      "type": "string",
      "enum": [
        "malicious",
        "suspicious",
        "benign_expected",
        "false_positive"
      ],
      "description": "malicious or suspicious: it was an attack; benign_expected: real activity that is normal here, the rule was right to fire; false_positive: the rule should not have fired on this"
    },
    "reason": {
      "type": "string",
      "description": "Why, in a sentence or two. The crew reads it on the next case"
    },
    "remember_days": {
      "type": "integer",
      "description": "How long the crew remembers this closure for the same rule and resource"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `case.get`

Get one case with its findings and the openspace transcript.

- **Scope:** `cases:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "CaseRef",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "Case identifier, e.g. CASE-1a2b\u2026"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `case.history`

Earlier cases on the same entities, and how each one ended.

- **Scope:** `cases:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "HistoryInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case whose entities to look back on"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum cases"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `case.investigate`

Run the crew on a case and record a cited verdict.

- **Scope:** `cases:investigate` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "InvestigateInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case the crew should discuss"
    },
    "max_rounds": {
      "type": "integer",
      "description": "Override the severity-based round budget (0 keeps it)"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `case.list`

List cases, newest first.

- **Scope:** `cases:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "CaseFilter",
  "properties": {
    "state": {
      "type": "string",
      "description": "triage, analysis, containment, eradication, recovery, post_incident or closed"
    },
    "verdict": {
      "type": "string",
      "description": "malicious, suspicious, benign_expected, false_positive, needs_human or unknown"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows, capped at 200"
    },
    "unacknowledged": {
      "type": "boolean",
      "description": "Only cases closed without their containment that nobody has acknowledged"
    }
  },
  "additionalProperties": false
}
```

## `case.recheck`

Read a few closures the crew called nothing again, blind, and reopen any it got wrong.

- **Scope:** `cases:recheck` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `case.set_state`

Move a case to another state in the incident-response process.

- **Scope:** `cases:transition` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "StateChange",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case to move"
    },
    "state": {
      "type": "string",
      "enum": [
        "triage",
        "analysis",
        "containment",
        "eradication",
        "recovery",
        "post_incident",
        "closed"
      ],
      "description": "The NIST 800-61 state to move to"
    },
    "note": {
      "type": "string",
      "description": "Why \u2014 kept in the audit log and the stream"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `config.apply`

Make the deployment match the config file.

- **Scope:** `config:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "ConfigInput",
  "properties": {
    "config": {
      "type": "object",
      "additionalProperties": {},
      "description": "The deployment config, as `shoc.yaml` parses. `shoc plan -f` reads the file and sends it here; the server reads no path a caller names"
    }
  },
  "additionalProperties": false
}
```

## `config.plan`

Show what applying this deployment config would change.

- **Scope:** `config:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "ConfigInput",
  "properties": {
    "config": {
      "type": "object",
      "additionalProperties": {},
      "description": "The deployment config, as `shoc.yaml` parses. `shoc plan -f` reads the file and sends it here; the server reads no path a caller names"
    }
  },
  "additionalProperties": false
}
```

## `credential.check`

Make one read with a stored response credential and say whether it still works.

- **Scope:** `actions:configure` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "CheckInput",
  "properties": {
    "provider": {
      "type": "string",
      "description": "The credential's name, e.g. aws or aws:staging"
    }
  },
  "additionalProperties": false,
  "required": [
    "provider"
  ]
}
```

## `credential.configure`

Give the playbook runner the credentials it acts with.

- **Scope:** `actions:configure` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "CredentialInput",
  "properties": {
    "provider": {
      "type": "string",
      "description": "The vendor: aws, cloudflare, crowdstrike, entra, okta, notify (PagerDuty) \u2026, or provider:label for another tenant of the same vendor, e.g. aws:staging"
    },
    "settings": {
      "type": "object",
      "additionalProperties": {},
      "description": "Non-secret settings, e.g. {'org_url': 'https://acme.okta.com'}. `accounts` lists the accounts it acts in, as their events name them (an AWS account ID, an Entra tenant ID, an Okta org host); needed once two credentials act on the same platform"
    },
    "secret": {
      "type": "object",
      "additionalProperties": {},
      "description": "Credentials; encrypted with the master key"
    },
    "verify": {
      "type": "boolean",
      "description": "Make one read with it once it is saved"
    }
  },
  "additionalProperties": false,
  "required": [
    "provider"
  ]
}
```

## `credential.list`

List where shoc can act: the response credentials, and the sources none covers.

- **Scope:** `actions:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `credential.remove`

Remove a response credential; shoc stops acting with it.

- **Scope:** `actions:configure` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "DisconnectInput",
  "properties": {
    "provider": {
      "type": "string",
      "description": "The credential's name, e.g. aws or aws:staging"
    }
  },
  "additionalProperties": false,
  "required": [
    "provider"
  ]
}
```

## `detect.run`

Run a detection cycle now and write the findings.

- **Scope:** `detection:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "DetectRun",
  "properties": {
    "rule_id": {
      "type": "string",
      "description": "Run only this rule; empty runs every rule"
    },
    "lookback": {
      "type": "string",
      "description": "Evaluate events from this far back, e.g. 24h (default: what was ingested since the last cycle)"
    },
    "open_cases": {
      "type": "boolean",
      "description": "Group the new findings into cases (RSP-1)"
    }
  },
  "additionalProperties": false
}
```

## `detection.backlog`

Every idea for a detection change, ranked, with where it came from.

- **Scope:** `detection:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "BacklogInput",
  "properties": {
    "run": {
      "type": "boolean",
      "description": "Sweep the intakes into the backlog first (needs detection:run)"
    },
    "state": {
      "type": "string",
      "description": "open, accepted, rejected or done. Empty lists every state"
    },
    "limit": {
      "type": "integer",
      "description": "How many items to return"
    }
  },
  "additionalProperties": false
}
```

## `detection.decide`

End a detection backlog item, or put it back in the queue.

- **Scope:** `detection:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "BacklogDecision",
  "properties": {
    "item_uid": {
      "type": "string",
      "description": "The backlog item to decide on"
    },
    "state": {
      "type": "string",
      "enum": [
        "rejected",
        "done",
        "open"
      ],
      "description": "rejected or done to end it, open to put it back in the queue"
    },
    "reason": {
      "type": "string",
      "description": "Why: required to end it, and shown on the item. Optional when reopening"
    }
  },
  "additionalProperties": false,
  "required": [
    "item_uid"
  ]
}
```

## `detection.merge`

Narrow a shipped rule or add a new one, behind the gate that replays stored evidence.

- **Scope:** `detection:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "MergeInput",
  "properties": {
    "item_uid": {
      "type": "string",
      "description": "The open backlog item this answers; it is closed on merge. A person adding a new rule may leave it out: the merge records an item of its own. Narrowing a shipped rule always names one, dry run included"
    },
    "narrows": {
      "type": "string",
      "description": "A shipped rule to narrow. With it, give `exclude` and not `rule`"
    },
    "exclude": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": {}
      },
      "description": "Alternatives to exclude from the shipped rule. Each holds one exact src_endpoint.ip, exactly one of actor.user.uid, resource.uid or actor.session.uid, and optionally api.operation, api.service.name or cloud.account.uid. Exact values only"
    },
    "hide_events": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "For an item from a benign closure: the event_uids the narrowing must stop matching, at least three on two days"
    },
    "rule": {
      "type": "object",
      "additionalProperties": {},
      "description": "A new rule: id, title, description, severity, attack, logsource.product, detection (selections and condition; timeframe, group_by and count inside it for a count) and entity, as in content/rules; rule.list shows real ones. A shipped id is refused: narrow it instead"
    },
    "playbook_id": {
      "type": "string",
      "description": "The existing playbook that answers it, as playbook.list names it; it must act on the rule's product"
    },
    "ads": {
      "type": "object",
      "additionalProperties": {
        "type": "string"
      },
      "description": "goal, categorization, strategy, technical_context, blind_spots, false_positives, validation, priority, and response, which defaults to the playbook"
    },
    "fixtures": {
      "type": "object",
      "additionalProperties": {},
      "description": "{source, positive: [raw records], negative: [raw records]}: records as that source sends them, without timestamps; events.query with include_raw returns real ones in `raw`"
    },
    "backtest_days": {
      "type": "integer",
      "description": "History the backtest replays, 1 to 30 days"
    },
    "reason": {
      "type": "string",
      "description": "One sentence on why this change, now"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Run the whole gate and write nothing. A new rule then needs no item_uid"
    }
  },
  "additionalProperties": false
}
```

## `detection.propose`

Put a rule idea on the detection backlog, for detection.merge to answer.

- **Scope:** `detection:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "BacklogProposal",
  "properties": {
    "title": {
      "type": "string",
      "description": "What a rule should catch, in a line"
    },
    "product": {
      "type": "string",
      "description": "The product whose events it reads, as a rule's logsource.product (okta, aws). The item waits as a source gap until a connected source delivers it"
    },
    "logic": {
      "type": "string",
      "description": "What to look for: fields, values, a threshold and the window"
    },
    "false_positives": {
      "type": "string",
      "description": "Legitimate activity that looks the same; it becomes the negative fixture"
    },
    "event_uids": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Events that show it, from events.query; they seed the positive fixture"
    },
    "why": {
      "type": "string",
      "description": "The report, case or change that raised it"
    },
    "attack": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "ATT&CK technique ids, e.g. T1562.008"
    }
  },
  "additionalProperties": false,
  "required": [
    "title"
  ]
}
```

## `detection.revert`

Take back a merged rule; the shipped rule it narrowed, if any, returns.

- **Scope:** `detection:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "RevertInput",
  "properties": {
    "rule_id": {
      "type": "string",
      "description": "A rule merged here. A rule shipped in content/ is out of reach"
    },
    "reason": {
      "type": "string",
      "description": "Why: the volume or the false-positive ratio"
    }
  },
  "additionalProperties": false,
  "required": [
    "rule_id",
    "reason"
  ]
}
```

## `detection.work`

The Detection Engineer works the top of the backlog to an end.

- **Scope:** `detection:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service, agent

Input schema:

```json
{
  "type": "object",
  "title": "WorkInput",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "How many backlog items to work, 1 to 20"
    }
  },
  "additionalProperties": false
}
```

## `events.ingest`

Map raw source records to OCSF and load them.

- **Scope:** `events:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "IngestInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "Connector/mapping name, e.g. aws_cloudtrail, okta, github"
    },
    "records": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": {}
      },
      "description": "Raw source records, exactly as the API returns them"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ],
  "description": "Push raw source records in; they are mapped to OCSF and stored."
}
```

## `events.query`

Search OCSF events by filter or one-box query, and get cited rows back.

- **Scope:** `events:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "EventQuery",
  "properties": {
    "since": {
      "type": "string",
      "description": "ISO-8601 timestamp or a relative window like -24h"
    },
    "until": {
      "type": "string",
      "description": "ISO-8601 timestamp; defaults to now"
    },
    "actor": {
      "type": "string",
      "description": "Exact actor.user.name"
    },
    "src_ip": {
      "type": "string",
      "description": "Exact src_endpoint.ip"
    },
    "api_operation": {
      "type": "string",
      "description": "Exact api.operation, e.g. ListBuckets"
    },
    "product": {
      "type": "string",
      "description": "metadata.product.name, e.g. 'AWS CloudTrail'"
    },
    "class_uid": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "description": "OCSF class_uid, e.g. 6003"
    },
    "status": {
      "type": "string",
      "description": "Success or Failure"
    },
    "contains": {
      "type": "string",
      "description": "Substring matched against the message and the operation"
    },
    "q": {
      "type": "string",
      "description": "One-box search. A bare word is matched against the message, the operation, the actor, the source IP and the resource; `field=value`, `field!=value`, `field~substring`, `field!~substring` and `field>=n` (also >, <, <=) narrow it. A field is an OCSF path (actor.user.name), a column name, or a source path (raw.debugContext.debugData.dtHash). Quote a value that contains spaces"
    },
    "event_uids": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Fetch these exact events (used to resolve citations)"
    },
    "include_raw": {
      "type": "boolean",
      "description": "Return every column, including the original record in `raw` and `unmapped`"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows, capped at 1000"
    }
  },
  "additionalProperties": false,
  "description": "Search OCSF events and get cited rows back."
}
```

## `events.retain`

Drop the event partitions older than the retention window.

- **Scope:** `events:retain` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "RetainInput",
  "properties": {
    "days": {
      "type": "integer",
      "description": "Keep this many days of events; older whole months are dropped"
    }
  },
  "additionalProperties": false
}
```

## `events.summarize`

Count matching events per group: a histogram over time, or a field's top values.

- **Scope:** `events:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SummarizeInput",
  "properties": {
    "since": {
      "type": "string",
      "description": "ISO-8601 timestamp or a relative window like -24h"
    },
    "until": {
      "type": "string",
      "description": "ISO-8601 timestamp; defaults to now"
    },
    "actor": {
      "type": "string",
      "description": "Exact actor.user.name"
    },
    "src_ip": {
      "type": "string",
      "description": "Exact src_endpoint.ip"
    },
    "api_operation": {
      "type": "string",
      "description": "Exact api.operation, e.g. ListBuckets"
    },
    "product": {
      "type": "string",
      "description": "metadata.product.name, e.g. 'AWS CloudTrail'"
    },
    "class_uid": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "description": "OCSF class_uid, e.g. 6003"
    },
    "status": {
      "type": "string",
      "description": "Success or Failure"
    },
    "contains": {
      "type": "string",
      "description": "Substring matched against the message and the operation"
    },
    "q": {
      "type": "string",
      "description": "One-box search. A bare word is matched against the message, the operation, the actor, the source IP and the resource; `field=value`, `field!=value`, `field~substring`, `field!~substring` and `field>=n` (also >, <, <=) narrow it. A field is an OCSF path (actor.user.name), a column name, or a source path (raw.debugContext.debugData.dtHash). Quote a value that contains spaces"
    },
    "by": {
      "type": "string",
      "description": "Group by `time` for a histogram, or by any field \u2014 actor.user.name, metadata_product, raw.<source path>"
    },
    "interval": {
      "type": "string",
      "description": "Bucket width when grouping by time: minute, hour or day. Defaults to fit the window"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum groups, capped at 500"
    }
  },
  "additionalProperties": false,
  "description": "Count matching events per group: a histogram over time, or a field's top values."
}
```

## `finding.get`

Get one finding with the events that back it.

- **Scope:** `findings:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "FindingRef",
  "properties": {
    "finding_uid": {
      "type": "string",
      "description": "The finding identifier, e.g. F-1a2b\u2026"
    }
  },
  "additionalProperties": false,
  "required": [
    "finding_uid"
  ]
}
```

## `finding.list`

List findings the detection engine produced.

- **Scope:** `findings:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "FindingFilter",
  "properties": {
    "status": {
      "type": "string",
      "description": "new, triage, closed or false_positive"
    },
    "severity": {
      "type": "string",
      "description": "informational, low, medium, high or critical"
    },
    "rule_id": {
      "type": "string",
      "description": "Only this rule"
    },
    "entity": {
      "type": "string",
      "description": "Only this entity key (a user, key or IP)"
    },
    "since": {
      "type": "string",
      "description": "Relative window like -7d, or an ISO-8601 timestamp"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows, capped at 500"
    }
  },
  "additionalProperties": false,
  "description": "List findings, newest first."
}
```

## `finding.set_status`

Change a finding's status (triage, close, mark a false positive).

- **Scope:** `findings:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "StatusUpdate",
  "properties": {
    "finding_uid": {
      "type": "string",
      "description": "The finding to update"
    },
    "status": {
      "type": "string",
      "enum": [
        "new",
        "triage",
        "closed",
        "false_positive"
      ],
      "description": "New status for the finding"
    },
    "note": {
      "type": "string",
      "description": "Why \u2014 kept in the audit log"
    }
  },
  "additionalProperties": false,
  "required": [
    "finding_uid"
  ]
}
```

## `graph.neighbours`

What this user, key, address or resource is connected to.

- **Scope:** `graph:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "GraphQuery",
  "properties": {
    "node": {
      "type": "string",
      "description": "A node id like user:jane@acme.com, or just the value"
    },
    "hops": {
      "type": "integer",
      "description": "How far to walk, capped at three"
    }
  },
  "additionalProperties": false,
  "required": [
    "node"
  ]
}
```

## `graph.refresh`

Rebuild the world graph from recent events.

- **Scope:** `graph:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "GraphRefresh",
  "properties": {
    "days": {
      "type": "integer",
      "description": "How much history to rebuild the graph from"
    }
  },
  "additionalProperties": false
}
```

## `health.audit`

Verify the hash-chained audit log and show recent entries.

- **Scope:** `audit:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "AuditQuery",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "How many recent audit rows to return"
    },
    "head": {
      "type": "string",
      "description": "A seq:hash kept outside the database, e.g. from a webhook delivery; the chain must still hold that row"
    }
  },
  "additionalProperties": false
}
```

## `health.cost`

What this deployment is costing: events stored and LLM spend.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "CostWindow",
  "properties": {
    "days": {
      "type": "integer",
      "description": "How many days of spend to add up"
    }
  },
  "additionalProperties": false
}
```

## `health.jobs`

Which worker jobs gave up, and why.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "JobsQuery",
  "properties": {
    "days": {
      "type": "integer",
      "description": "How far back to look for failed jobs"
    }
  },
  "additionalProperties": false
}
```

## `health.quality`

How good the data is, not just whether it is arriving.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "QualityInput",
  "properties": {
    "days": {
      "type": "integer",
      "description": "The window to score over"
    }
  },
  "additionalProperties": false
}
```

## `health.rules`

Which rules are noisy, silent or failing.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RuleHealthFilter",
  "properties": {
    "only": {
      "type": "string",
      "enum": [
        "all",
        "noisy",
        "silent",
        "failing"
      ],
      "description": "Narrow the list"
    }
  },
  "additionalProperties": false
}
```

## `health.sources`

Which log sources are fresh, late or failing.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `health.status`

Pipeline health: store, sources, rules, jobs and finding volume.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `hunt.backlog`

Hypotheses waiting for a pack, with why each was raised and how each ended.

- **Scope:** `hunts:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "HuntBacklogInput",
  "properties": {
    "state": {
      "type": "string",
      "description": "open, packed, rejected or done. Empty lists every state"
    },
    "limit": {
      "type": "integer",
      "description": "How many items to return"
    }
  },
  "additionalProperties": false
}
```

## `hunt.daily`

Run today's behavioural hunts, chosen by what intel and incidents say.

- **Scope:** `hunts:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "DailyInput",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "Run at most this many due packs (0 = every due pack). The day's budget is the triage ceiling set with llm.configure (hunt_tokens_per_day)"
    }
  },
  "additionalProperties": false
}
```

## `hunt.decide`

End a hunt backlog item, or put it back in the queue.

- **Scope:** `hunts:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "BacklogDecision",
  "properties": {
    "item_uid": {
      "type": "string",
      "description": "The backlog item to decide on"
    },
    "state": {
      "type": "string",
      "enum": [
        "rejected",
        "done",
        "open"
      ],
      "description": "rejected or done to end it, open to put it back in the queue"
    },
    "reason": {
      "type": "string",
      "description": "Why: required to end it, and shown on the item. Optional when reopening"
    }
  },
  "additionalProperties": false,
  "required": [
    "item_uid"
  ]
}
```

## `hunt.merge`

Add a hunt pack for a backlog item, behind a gate that runs its fixtures and its query.

- **Scope:** `hunts:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "HuntMergeInput",
  "properties": {
    "item_uid": {
      "type": "string",
      "description": "The open hunt backlog item this pack answers. A person may leave it out: the merge records an item of its own"
    },
    "pack": {
      "type": "object",
      "additionalProperties": {},
      "description": "The pack: id, title, hypothesis, attack, logsource.product, detection, baseline (first_seen: [fields] or rare: {by, among, seen_by_fewer_than}, and lookback), window, pivot and triage, as in content/hunts; hunt.results shows each pack's logic. A shipped id is refused, and an id merged here is refused until hunt.revert takes it back"
    },
    "fixtures": {
      "type": "object",
      "additionalProperties": {},
      "description": "{source, surfaced: [raw records], baseline: [raw records]}: records as that source sends them, without timestamps; events.query with include_raw returns real ones in `raw`. The pack must return surfaced once baseline came first"
    },
    "reason": {
      "type": "string",
      "description": "One sentence on why this pack, now"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Run the whole gate and write nothing; item_uid is optional"
    }
  },
  "additionalProperties": false
}
```

## `hunt.pack`

Run one hunt pack now, and say what came back.

- **Scope:** `hunts:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "PackInput",
  "properties": {
    "pack_id": {
      "type": "string",
      "description": "A pack, as hunt.results lists it"
    }
  },
  "additionalProperties": false,
  "required": [
    "pack_id"
  ]
}
```

## `hunt.propose`

Hand the Hunter a hypothesis to test: a report described it, nothing checks for it.

- **Scope:** `hunts:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "HuntBacklogAdd",
  "properties": {
    "title": {
      "type": "string",
      "description": "What to hunt for, in a line"
    },
    "hypothesis": {
      "type": "string",
      "description": "What an adversary would be doing here, and why it would show"
    },
    "would_confirm": {
      "type": "string",
      "description": "What in our data would confirm it"
    },
    "data_needed": {
      "type": "string",
      "description": "Which sources and fields it reads"
    },
    "why_now": {
      "type": "string",
      "description": "The report, case or change that raised it"
    },
    "attack": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "ATT&CK technique ids, e.g. T1078"
    }
  },
  "additionalProperties": false,
  "required": [
    "title"
  ]
}
```

## `hunt.results`

What the hunts have concluded, and the measures that count.

- **Scope:** `hunts:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ResultsInput",
  "properties": {
    "pack_id": {
      "type": "string",
      "description": "Only this pack"
    },
    "days": {
      "type": "integer",
      "description": "How far back to look"
    },
    "limit": {
      "type": "integer",
      "description": "How many runs to return"
    }
  },
  "additionalProperties": false
}
```

## `hunt.revert`

Take back a merged hunt pack; it stops running.

- **Scope:** `hunts:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "HuntRevertInput",
  "properties": {
    "pack_id": {
      "type": "string",
      "description": "A pack hunt.merge added"
    },
    "reason": {
      "type": "string",
      "description": "Why it goes"
    }
  },
  "additionalProperties": false,
  "required": [
    "pack_id",
    "reason"
  ]
}
```

## `hunt.run`

Hunt for an indicator across the retention window.

- **Scope:** `hunts:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "HuntInput",
  "properties": {
    "value": {
      "type": "string",
      "description": "What to hunt for: an IP, a domain or a user name"
    },
    "days": {
      "type": "integer",
      "description": "How far back to look"
    },
    "field": {
      "type": "string",
      "description": "auto, src_ip, domain or actor"
    }
  },
  "additionalProperties": false,
  "required": [
    "value"
  ],
  "description": "Search history for an indicator, an address or a user."
}
```

## `hunt.suggest`

What the Hunter thinks is worth looking for this week, and why.

- **Scope:** `hunts:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "HuntSuggestInput",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "How many suggestions to return"
    }
  },
  "additionalProperties": false
}
```

## `hunt.work`

The Hunter works the top of its backlog: a pack for each item, or why not.

- **Scope:** `hunts:work` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "HuntWorkInput",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "How many open items to work, priority first, 1 to 20"
    }
  },
  "additionalProperties": false
}
```

## `identity.resolve`

The same actor under its other names: its keys, its users, what sources list for it.

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ResolveInput",
  "properties": {
    "identity": {
      "type": "string",
      "description": "A user or a key, typed (user:\u2026, key:\u2026) or bare"
    }
  },
  "additionalProperties": false,
  "required": [
    "identity"
  ]
}
```

## `intel.add`

Add indicators by value, or pull them from one URL.

- **Scope:** `intel:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent

Input schema:

```json
{
  "type": "object",
  "title": "AddInput",
  "properties": {
    "values": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Indicators, one per entry; each type is worked out"
    },
    "url": {
      "type": "string",
      "description": "Or a page, list or advisory to pull indicators from, once"
    },
    "severity": {
      "type": "string",
      "description": "low, medium, high or critical"
    },
    "confidence": {
      "type": "number",
      "description": "0 to 1; an agent's indicators are capped at 0.55"
    },
    "description": {
      "type": "string",
      "description": "Why these are bad"
    },
    "days": {
      "type": "integer",
      "description": "Days until they expire; 0 means never"
    },
    "retro_hunt": {
      "type": "boolean",
      "description": "Search the retention window for them now"
    }
  },
  "additionalProperties": false,
  "description": "Indicators somebody hands in: typed values, or a page that names them."
}
```

## `intel.configure`

Add, change, disable or remove a threat-intel source.

- **Scope:** `intel:configure` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "FeedConfig",
  "properties": {
    "feed": {
      "type": "string",
      "description": "The source's name. For a built-in feed, its name is its parser; empty means the preset's or the lookup's name"
    },
    "preset": {
      "type": "string",
      "description": "A report source shoc knows by name, e.g. microsoft_ti or the_dfir_report (intel.list names them). It fills in the parser and the URL"
    },
    "lookup": {
      "type": "string",
      "description": "Configure a lookup source that needs an account instead of a feed, e.g. abuse_ch, ipapi_is or virustotal (intel.list names them). The first save needs its key in secret under the source's secret_field: api_key, or auth_key for abuse_ch and key for ipapi_is. settings take per_day, and commercial_licence: true where intel.list says licence_needed, since that free tier is non-commercial"
    },
    "parser": {
      "type": "string",
      "description": "Indicators: abuse_ch_feodo, abuse_ch_urlhaus, otx, misp or list (any URL naming indicators). Reports: rss, otx_pulses or misp_events. Empty means the name"
    },
    "settings": {
      "type": "object",
      "additionalProperties": {},
      "description": "Source settings, e.g. {'url': '\u2026'}; report sources take max_items per poll"
    },
    "secret": {
      "type": "object",
      "additionalProperties": {},
      "description": "Source credentials, e.g. {'api_key': '\u2026'}"
    },
    "enabled": {
      "type": "boolean",
      "description": "Whether the worker polls it"
    },
    "remove": {
      "type": "boolean",
      "description": "Forget the source. Indicators it brought in stay until intel.remove"
    }
  },
  "additionalProperties": false
}
```

## `intel.digest`

Read a threat report and turn it into indicators, techniques and hunts.

- **Scope:** `intel:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "DigestInput",
  "properties": {
    "url": {
      "type": "string",
      "description": "A link to a report \u2014 a blog post, an advisory or a PDF"
    },
    "text": {
      "type": "string",
      "description": "Or the report pasted in, instead of a URL"
    },
    "title": {
      "type": "string",
      "description": "A title for pasted text"
    },
    "store_indicators": {
      "type": "boolean",
      "description": "Store what the report publishes as indicators we will match against"
    },
    "retro_hunt": {
      "type": "boolean",
      "description": "Search the retention window for what the report publishes"
    }
  },
  "additionalProperties": false,
  "description": "Hand the CTI role a threat report and get indicators, techniques and hunts."
}
```

## `intel.list`

List known indicators and the health of the feeds behind them.

- **Scope:** `intel:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "IocFilter",
  "properties": {
    "type": {
      "type": "string",
      "description": "ip, domain, url, sha256 or cve"
    },
    "contains": {
      "type": "string",
      "description": "Substring of the value or the description"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows"
    }
  },
  "additionalProperties": false
}
```

## `intel.lookup`

Research an indicator across OSINT sources and our own history.

- **Scope:** `intel:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "LookupInput",
  "properties": {
    "value": {
      "type": "string",
      "description": "An IP, a domain, a URL, a hash or a CVE"
    },
    "type": {
      "type": "string",
      "description": "Leave empty to work it out from the value"
    },
    "refresh": {
      "type": "boolean",
      "description": "Ignore the cached answer and ask every source again"
    },
    "sources": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Only these sources, e.g. ['rdap', 'tor_exit']. Empty means all that apply"
    }
  },
  "additionalProperties": false,
  "required": [
    "value"
  ],
  "description": "Research one indicator the way an analyst would."
}
```

## `intel.refresh`

Poll threat-intel sources and retro-hunt anything new.

- **Scope:** `intel:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RefreshInput",
  "properties": {
    "feed": {
      "type": "string",
      "description": "One source, or empty for every enabled source"
    },
    "retro_hunt": {
      "type": "boolean",
      "description": "Search the retention window for indicators that are new to us"
    }
  },
  "additionalProperties": false
}
```

## `intel.remove`

Withdraw indicators by value, by source or by report.

- **Scope:** `intel:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent

Input schema:

```json
{
  "type": "object",
  "title": "RemoveInput",
  "properties": {
    "values": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "These values, whatever their type"
    },
    "source": {
      "type": "string",
      "description": "Everything from this source, e.g. manual:human:ana or report:example.com"
    },
    "report_uid": {
      "type": "string",
      "description": "Everything one digested report brought in"
    }
  },
  "additionalProperties": false,
  "description": "Withdraw indicators: named ones, or everything one source or report brought in."
}
```

## `intel.reports`

List the threat reports we have read, and what came out of them.

- **Scope:** `intel:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ReportFilter",
  "properties": {
    "contains": {
      "type": "string",
      "description": "Substring of the title, summary, an actor or a malware name"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows"
    },
    "state": {
      "type": "string",
      "description": "read (the default); or waiting, skipped, same_story or dropped for items not read, with the reason; or queue for all of those"
    }
  },
  "additionalProperties": false
}
```

## `llm.configure`

Change the crew's model, or what it may spend, without a restart.

- **Scope:** `llm:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "LLMConfig",
  "properties": {
    "provider": {
      "type": "string",
      "description": "anthropic, openai (any /chat/completions endpoint), openai-responses (a /responses endpoint) or none"
    },
    "model": {
      "type": "string",
      "description": "The model every role uses"
    },
    "model_cheap": {
      "type": "string",
      "description": "The model for the narrow roles; empty runs them on `model`"
    },
    "base_url": {
      "type": "string",
      "description": "The endpoint; its host must be in SHOC_LLM_BASE_URL_ALLOWLIST"
    },
    "api_key": {
      "type": "string",
      "description": "The provider key; stored encrypted, never returned"
    },
    "spend_usd_per_day": {
      "type": "number",
      "description": "Raise cost.over_budget when a day's spend passes this; 0 keeps what is stored"
    },
    "hunt_tokens_per_day": {
      "type": "integer",
      "description": "Ceiling of the Hunter's daily triage turn, in tokens; 0 keeps what is stored"
    },
    "intel_reports_per_day": {
      "type": "integer",
      "description": "Threat reports CTI reads in a day; 0 keeps what is stored"
    },
    "intel_tokens_per_day": {
      "type": "integer",
      "description": "Tokens CTI spends reading reports in a day; 0 keeps what is stored"
    },
    "clear": {
      "type": "boolean",
      "description": "Remove the stored settings and fall back to SHOC_LLM_*"
    }
  },
  "additionalProperties": false,
  "description": "Change the provider, models, endpoint or key. Empty fields keep what is there."
}
```

## `llm.show`

Show the crew's model, endpoint and where each setting comes from.

- **Scope:** `llm:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `manager.deliver`

Run the page gate over every undelivered page notice, one page per incident.

- **Scope:** `manager:deliver` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `mapping.test`

Say which rules a source can carry, from the fields its events fill.

- **Scope:** `sources:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "MappingTestInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "A source, e.g. okta"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `mapping.write`

Move a source's field paths for this tenant, kept only if its events fill more.

- **Scope:** `sources:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "MappingWriteInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "The mapping, named after its connector, e.g. okta"
    },
    "fields": {
      "type": "object",
      "additionalProperties": {},
      "description": "Column to a path, or to {paths, transform}, merged over the shipped fields. Empty removes this tenant's override"
    },
    "reason": {
      "type": "string",
      "description": "Which vendor field replaced which"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `memory.add_fact`

Tell the crew something about this company that logs cannot show.

- **Scope:** `memory:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent

Input schema:

```json
{
  "type": "object",
  "title": "MemoryFact",
  "properties": {
    "body": {
      "type": "string",
      "description": "The fact, in one sentence, e.g. 'The VPN pool is 10.8.0.0/16'"
    },
    "subject": {
      "type": "string",
      "description": "What it is about \u2014 a user, an IP range, a system"
    },
    "kind": {
      "type": "string",
      "enum": [
        "semantic",
        "episodic",
        "correction"
      ],
      "description": "Kind of memory"
    },
    "expires_at": {
      "type": "string",
      "description": "ISO-8601 timestamp after which this stops being true"
    }
  },
  "additionalProperties": false,
  "required": [
    "body"
  ]
}
```

## `memory.search`

Search what the crew knows about this company.

- **Scope:** `memory:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "MemoryQuery",
  "properties": {
    "query": {
      "type": "string",
      "description": "Words to search for; empty returns the most recent facts"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows"
    }
  },
  "additionalProperties": false
}
```

## `metrics.export`

Findings, jobs and source age in the Prometheus text format, as /metrics serves them.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `metrics.get`

MTTD and MTTR per incident type, false positives, and what it cost.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "MetricsInput",
  "properties": {
    "days": {
      "type": "integer",
      "description": "The window to measure over"
    }
  },
  "additionalProperties": false
}
```

## `openspace.post`

Post a message into an openspace: a fact, a challenge, a question for one agent.

- **Scope:** `cases:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, external_agent

Input schema:

```json
{
  "type": "object",
  "title": "OpenspacePost",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The openspace to post into"
    },
    "body": {
      "type": "string",
      "description": "What you want the openspace to know"
    },
    "kind": {
      "type": "string",
      "enum": [
        "observation",
        "hypothesis",
        "evidence",
        "challenge",
        "concede",
        "proposal",
        "decision",
        "inject",
        "request",
        "answer",
        "interject"
      ],
      "description": "Message kind; 'inject' is how a human adds a fact from above"
    },
    "to": {
      "type": "string",
      "description": "The agent a 'request' is for, or the one an 'answer' replies to"
    },
    "citations": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "event_uid values that back this message"
    },
    "round": {
      "type": "integer",
      "description": "Round to post into (0 continues the current one)"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid",
    "body"
  ]
}
```

## `ops.alerts`

What the Ops role would raise right now: stale sources, noisy rules, stuck approvals.

- **Scope:** `health:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "AlertBudget",
  "properties": {
    "budget_usd_per_day": {
      "type": "number",
      "description": "Warn when today's LLM spend passes this (0 = the budget set with llm.configure)"
    }
  },
  "additionalProperties": false
}
```

## `own.add`

Record a credential, address or account as shoc's own or the operator's.

- **Scope:** `own:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "OwnIdentity",
  "properties": {
    "kind": {
      "type": "string",
      "enum": [
        "credential",
        "address",
        "operator",
        "automation"
      ],
      "description": "credential: a credential id shoc reads with; address: an address shoc calls out from; operator: an account of the person who runs shoc; automation: an account of the company's own automation"
    },
    "value": {
      "type": "string",
      "description": "The id, address or account, exactly as the logs show it"
    },
    "source": {
      "type": "string",
      "description": "The source a credential belongs to, e.g. google_workspace"
    },
    "scope": {
      "type": "string",
      "description": "What a credential was granted, space-separated"
    },
    "note": {
      "type": "string",
      "description": "Why, in one sentence"
    }
  },
  "additionalProperties": false
}
```

## `own.list`

What shoc knows is its own: its credentials and addresses, the operator's and the company's automation accounts.

- **Scope:** `own:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `own.remove`

Forget one of shoc's own identities.

- **Scope:** `own:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "OwnRemove",
  "properties": {
    "kind": {
      "type": "string",
      "description": "credential, address, operator or automation"
    },
    "value": {
      "type": "string",
      "description": "The value to forget"
    }
  },
  "additionalProperties": false,
  "required": [
    "kind",
    "value"
  ]
}
```

## `platform.lookup`

Read live state from a connected platform: a user, a mailbox, a key, a host.

- **Scope:** `platforms:lookup` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "LookupInput",
  "properties": {
    "lookup": {
      "type": "string",
      "description": "Lookup name from platform.lookups, e.g. okta.get_user"
    },
    "params": {
      "type": "object",
      "additionalProperties": {},
      "description": "Its parameters, e.g. {'user': 'alice@example.com'}"
    },
    "case_uid": {
      "type": "string",
      "description": "The case it is for: the read goes to the tenant the case saw"
    },
    "credential": {
      "type": "string",
      "description": "One of the provider's credentials, e.g. entra:emea"
    }
  },
  "additionalProperties": false,
  "required": [
    "lookup"
  ]
}
```

## `platform.lookups`

List the live reads available on connected platforms, and their parameters.

- **Scope:** `platforms:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "LookupFilter",
  "properties": {
    "platform": {
      "type": "string",
      "description": "Only lookups for this platform, e.g. okta, m365, edr, aws"
    }
  },
  "additionalProperties": false
}
```

## `playbook.get`

Read one playbook run and its steps.

- **Scope:** `playbooks:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RunRef",
  "properties": {
    "run_uid": {
      "type": "string",
      "description": "The playbook run"
    }
  },
  "additionalProperties": false,
  "required": [
    "run_uid"
  ]
}
```

## `playbook.list`

List playbooks, or the ones that match a case.

- **Scope:** `playbooks:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "PlaybookFilter",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "Only playbooks whose trigger matches this case"
    }
  },
  "additionalProperties": false
}
```

## `playbook.merge`

Add or replace a playbook here, made of existing actions, behind a gate.

- **Scope:** `playbooks:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "PlaybookMerge",
  "properties": {
    "playbook": {
      "type": "object",
      "additionalProperties": {},
      "description": "The playbook in the YAML shape of content/playbooks, as JSON, or as playbook.list returns one: id, title, rules, questions, benign_when, trigger, steps. A step uses an action policy.show lists. A shipped id is refused; an id merged here before is replaced"
    },
    "reason": {
      "type": "string",
      "description": "One sentence on why this playbook, now"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Run the whole gate and write nothing"
    }
  },
  "additionalProperties": false
}
```

## `playbook.resume`

Continue a run that was waiting for an approval or a fix.

- **Scope:** `playbooks:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service, agent

Input schema:

```json
{
  "type": "object",
  "title": "RunRef",
  "properties": {
    "run_uid": {
      "type": "string",
      "description": "The playbook run"
    }
  },
  "additionalProperties": false,
  "required": [
    "run_uid"
  ]
}
```

## `playbook.revert`

Take back a merged playbook; its rules go back to the playbooks that had them.

- **Scope:** `playbooks:merge` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "PlaybookRevert",
  "properties": {
    "playbook_id": {
      "type": "string",
      "description": "A playbook playbook.merge added"
    },
    "reason": {
      "type": "string",
      "description": "Why it goes"
    }
  },
  "additionalProperties": false,
  "required": [
    "playbook_id",
    "reason"
  ]
}
```

## `playbook.run`

Start a playbook on a case and run it until something needs a human.

- **Scope:** `playbooks:run` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service, agent

Input schema:

```json
{
  "type": "object",
  "title": "StartRun",
  "properties": {
    "playbook_id": {
      "type": "string",
      "description": "Which playbook to run"
    },
    "case_uid": {
      "type": "string",
      "description": "The case it responds to"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Plan every step without touching anything"
    }
  },
  "additionalProperties": false,
  "required": [
    "playbook_id",
    "case_uid"
  ]
}
```

## `playbook.runs`

List playbook runs and where each one stopped.

- **Scope:** `playbooks:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RunFilter",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "Only runs for this case"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows"
    }
  },
  "additionalProperties": false
}
```

## `policy.show`

Show the autonomy policy: what may run alone, and what needs a human.

- **Scope:** `policy:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `posture.exposure`

Is this identity, key or host privileged, exposed or stale?.

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ExposureInput",
  "properties": {
    "entity": {
      "type": "string",
      "description": "An entity like user:alice, key:AKIA\u2026 or just the value"
    }
  },
  "additionalProperties": false,
  "required": [
    "entity"
  ]
}
```

## `posture.get`

What this company has, what is exposed, and what nothing is watching.

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "PostureInput",
  "properties": {
    "days": {
      "type": "integer",
      "description": "How far back to read events"
    },
    "refresh": {
      "type": "boolean",
      "description": "Re-read the events and keep the new survey (needs posture:write). False answers from the last survey"
    }
  },
  "additionalProperties": false
}
```

## `report.get`

Build the shift, weekly, executive or exception report.

- **Scope:** `reports:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ReportInput",
  "properties": {
    "kind": {
      "type": "string",
      "enum": [
        "shift",
        "weekly",
        "exec",
        "exception"
      ],
      "description": "Which report to build. `exception` lists the decisions that need a person"
    },
    "narrate": {
      "type": "boolean",
      "description": "Add a short written summary (needs an LLM)"
    }
  },
  "additionalProperties": false
}
```

## `report.send`

Build the weekly or executive report and send it to Slack and the stream.

- **Scope:** `reports:send` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "SendInput",
  "properties": {
    "kind": {
      "type": "string",
      "enum": [
        "weekly",
        "exec",
        "exception"
      ],
      "description": "The weekly report, the monthly one for a founder, or the decisions that need a person"
    }
  },
  "additionalProperties": false
}
```

## `rule.backtest`

Replay a rule over our own history and count what it would have raised.

- **Scope:** `rules:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "BacktestInput",
  "properties": {
    "rule": {
      "type": "object",
      "additionalProperties": {},
      "description": "The rule, in the YAML shape of content/rules, as JSON"
    },
    "rule_id": {
      "type": "string",
      "description": "Or an existing rule, by id"
    },
    "days": {
      "type": "integer",
      "description": "How much history to replay, 1 to 30 days"
    }
  },
  "additionalProperties": false
}
```

## `rule.list`

List the detection rules this deployment runs.

- **Scope:** `rules:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RuleFilter",
  "properties": {
    "severity": {
      "type": "string",
      "description": "Only rules of this severity"
    },
    "product": {
      "type": "string",
      "description": "Only rules whose logsource product matches"
    },
    "contains": {
      "type": "string",
      "description": "Substring matched against id, title and description"
    }
  },
  "additionalProperties": false
}
```

## `rule.test`

Run one rule over a window and show what it would find, writing nothing.

- **Scope:** `rules:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "RuleRef",
  "properties": {
    "rule_id": {
      "type": "string",
      "description": "Rule id, as listed by rule.list"
    },
    "since": {
      "type": "string",
      "description": "Window to evaluate, relative or ISO-8601"
    }
  },
  "additionalProperties": false,
  "required": [
    "rule_id"
  ]
}
```

## `search`

Search findings and events for what a question names, without a model.

- **Scope:** `ask:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Query",
  "properties": {
    "question": {
      "type": "string",
      "description": "A plain-language question or identifier, e.g. 'AKIA\u2026' or an IP"
    },
    "since": {
      "type": "string",
      "description": "How far back to look"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows per section"
    }
  },
  "additionalProperties": false,
  "required": [
    "question"
  ],
  "description": "Search findings and events for what a question names. No model is called."
}
```

## `slack.configure`

Connect the Slack app and say who may approve from it.

- **Scope:** `slack:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "SlackConfig",
  "properties": {
    "bot_token": {
      "type": "string",
      "description": "xoxb-\u2026 bot token; stored encrypted"
    },
    "signing_secret": {
      "type": "string",
      "description": "The app's signing secret; stored encrypted"
    },
    "channel": {
      "type": "string",
      "description": "Channel id to post into, e.g. C0123456789"
    },
    "approvers": {
      "type": "object",
      "additionalProperties": {
        "type": "string"
      },
      "description": "Slack user id -> the person's name, for everyone allowed to approve"
    }
  },
  "additionalProperties": false,
  "description": "Configure the Slack app. Approvers are named explicitly \u2014 being in the channel is not authority."
}
```

## `slack.notify`

Post a message or a case to Slack; unattended, only the SOC Manager may.

- **Scope:** `slack:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent

Input schema:

```json
{
  "type": "object",
  "title": "NotifyInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "A case to post, with buttons for anything waiting on a human"
    },
    "text": {
      "type": "string",
      "description": "A message to post; escaped, so it cannot ping anyone or hide a link"
    }
  },
  "additionalProperties": false
}
```

## `slack.show`

Show the Slack app's channel and approvers, and whether its secrets are set.

- **Scope:** `slack:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `snapshot.list`

What each source's own API says exists, whether or not it ever acted (D49).

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SnapshotInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "One source, or empty for all"
    },
    "kind": {
      "type": "string",
      "description": "user or network; empty for all"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum rows, capped at 1000"
    }
  },
  "additionalProperties": false
}
```

## `source.configure`

Add or update a log source and its credentials.

- **Scope:** `sources:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "SourceConfig",
  "properties": {
    "source": {
      "type": "string",
      "description": "Connector name, e.g. cloudflare, or connector:label for another account of the same vendor, e.g. cloudflare:acme"
    },
    "settings": {
      "type": "object",
      "additionalProperties": {},
      "description": "Non-secret settings, e.g. {'org_url': '\u2026'}"
    },
    "secret": {
      "type": "object",
      "additionalProperties": {},
      "description": "Credentials, e.g. {'api_token': '\u2026'}"
    },
    "interval_seconds": {
      "type": "integer",
      "description": "How often the worker polls this source"
    },
    "enabled": {
      "type": "boolean",
      "description": "Whether the worker should poll it at all"
    },
    "verify": {
      "type": "boolean",
      "description": "Try the credential once before saving it"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ],
  "description": "Configure a connector. The secret is encrypted with the master key."
}
```

## `source.list`

List configured log sources, the connectors available and what each one needs.

- **Scope:** `sources:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `source.onboard`

The Integrator works each source until it has produced a finding.

- **Scope:** `sources:onboard` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service, agent

Input schema:

```json
{
  "type": "object",
  "title": "OnboardInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "One source, or empty for all of them"
    }
  },
  "additionalProperties": false
}
```

## `source.push_key`

Create or rotate the signing key a push source must use.

- **Scope:** `sources:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "PushKeyInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "The push source: github"
    },
    "rotate": {
      "type": "boolean",
      "description": "Replace the existing key; the old one stops working"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `source.remove`

Disconnect a log source; the events it already delivered stay.

- **Scope:** `sources:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "RemoveInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "The connected source to remove"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `source.sample`

Read one page from a source and map it, storing nothing.

- **Scope:** `sources:sample` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SampleInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "A configured source"
    },
    "limit": {
      "type": "integer",
      "description": "Records to read, at most 20"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `source.sync`

Pull new events from a source now.

- **Scope:** `sources:sync` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SyncInput",
  "properties": {
    "source": {
      "type": "string",
      "description": "Which source to pull now"
    },
    "limit": {
      "type": "integer",
      "description": "Records per page"
    },
    "max_pages": {
      "type": "integer",
      "description": "Safety cap on pages per run"
    }
  },
  "additionalProperties": false,
  "required": [
    "source"
  ]
}
```

## `sso.configure`

Let the company's email domains sign in through its OpenID Connect provider.

- **Scope:** `sso:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "SsoConfig",
  "properties": {
    "issuer": {
      "type": "string",
      "description": "The provider's issuer, e.g. https://accounts.google.com"
    },
    "client_id": {
      "type": "string",
      "description": "The client id the provider gave shoc"
    },
    "client_secret": {
      "type": "string",
      "description": "Stored encrypted; empty keeps the stored one for the same issuer and client"
    },
    "domains": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "The company's email domains that sign in there, e.g. example.com"
    },
    "clear": {
      "type": "boolean",
      "description": "Turn SSO off"
    }
  },
  "additionalProperties": false
}
```

## `sso.show`

Show the company's identity provider and the email domains that use it.

- **Scope:** `sso:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `stream.deliver`

Send pending events to every enabled webhook.

- **Scope:** `stream:deliver` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human, service

Input schema:

```json
{
  "type": "object",
  "title": "DeliverInput",
  "properties": {},
  "additionalProperties": false,
  "description": "Each webhook resumes from its own cursor (API-2)."
}
```

## `stream.subscribe`

Register a signed webhook for events.

- **Scope:** `stream:write` · **Autonomy:** L0 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "WebhookInput",
  "properties": {
    "url": {
      "type": "string",
      "description": "Where to POST events"
    },
    "types": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Event types to send; empty means all"
    },
    "enabled": {
      "type": "boolean",
      "description": "Whether to deliver to it"
    }
  },
  "additionalProperties": false,
  "required": [
    "url"
  ]
}
```

## `stream.tail`

Read events since a sequence number: findings, cases, openspace messages, health.

- **Scope:** `stream:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "TailInput",
  "properties": {
    "since_seq": {
      "type": "integer",
      "description": "Return events after this sequence number"
    },
    "types": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Only these event types, e.g. ['case.opened']"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum events, capped at 500"
    }
  },
  "additionalProperties": false
}
```

## `suppression.list`

What is currently suppressed, why, and when it comes back.

- **Scope:** `detection:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SuppressionInput",
  "properties": {
    "review": {
      "type": "boolean",
      "description": "Expire what has run out before listing"
    },
    "rule_id": {
      "type": "string",
      "description": "Only suppressions for this rule"
    }
  },
  "additionalProperties": false
}
```

## `surface.list`

The attack surface as the events describe it.

- **Scope:** `posture:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "SurfaceInput",
  "properties": {
    "kind": {
      "type": "string",
      "description": "Limit to one entity kind: user, key, ip, resource or account"
    },
    "exposed_only": {
      "type": "boolean",
      "description": "Only what has been used from outside our own ranges"
    },
    "limit": {
      "type": "integer",
      "description": "How many rows to return"
    }
  },
  "additionalProperties": false
}
```

## `timeline.build`

The case's timeline in the source that alerted: its entities' events, oldest first.

- **Scope:** `cases:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "BuildInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case"
    },
    "margin_hours": {
      "type": "integer",
      "description": "How far either side of the case's events to read"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum events, capped at 500"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid"
  ]
}
```

## `timeline.extend`

Extend a case's timeline on one identity or indicator, in every source.

- **Scope:** `cases:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "ExtendInput",
  "properties": {
    "case_uid": {
      "type": "string",
      "description": "The case"
    },
    "value": {
      "type": "string",
      "description": "An identity or an indicator: user:\u2026, key:\u2026, ip:\u2026, resource:\u2026, host:\u2026, or a bare value matched against all of them"
    },
    "hours": {
      "type": "integer",
      "description": "How far either side of the case's events to read"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum events, capped at 500"
    }
  },
  "additionalProperties": false,
  "required": [
    "case_uid",
    "value"
  ]
}
```

## `token.create`

Issue a bearer token for a person or a machine; the token is returned once.

- **Scope:** `tokens:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "TokenCreate",
  "properties": {
    "who": {
      "type": "string",
      "description": "The person or machine the token is for, e.g. alice@example.com or ci"
    },
    "role": {
      "type": "string",
      "enum": [
        "",
        "admin",
        "operator",
        "deployer",
        "reader"
      ],
      "description": "A person's role; leave empty for a machine token"
    },
    "kind": {
      "type": "string",
      "enum": [
        "service",
        "agent",
        "external_agent"
      ],
      "description": "A machine token's principal; ignored when a role is set"
    },
    "scopes": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "A machine token's scopes, e.g. events:write"
    },
    "expires_days": {
      "type": "integer",
      "description": "Days until it stops working; 0 never expires"
    }
  },
  "additionalProperties": false,
  "required": [
    "who"
  ]
}
```

## `token.list`

List issued bearer tokens: who, role or scopes, and when they end.

- **Scope:** `tokens:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "TokenQuery",
  "properties": {
    "revoked": {
      "type": "boolean",
      "description": "Include revoked and expired tokens"
    }
  },
  "additionalProperties": false
}
```

## `token.revoke`

Revoke a bearer token; it stops working on the next request.

- **Scope:** `tokens:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "TokenRevoke",
  "properties": {
    "token_id": {
      "type": "string",
      "description": "The token's id, tok_\u2026, from token.list"
    }
  },
  "additionalProperties": false,
  "required": [
    "token_id"
  ]
}
```

## `user.invite`

Invite a person to sign in; the link is emailed or returned once.

- **Scope:** `users:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "UserInvite",
  "properties": {
    "email": {
      "type": "string",
      "description": "The person's address, e.g. ann@example.com"
    },
    "role": {
      "type": "string",
      "enum": [
        "admin",
        "operator",
        "deployer",
        "reader"
      ],
      "description": "What the person may do"
    }
  },
  "additionalProperties": false,
  "required": [
    "email"
  ]
}
```

## `user.list`

List the people who sign in: role, how they sign in, and when they last did.

- **Scope:** `users:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "UserQuery",
  "properties": {
    "disabled": {
      "type": "boolean",
      "description": "Include disabled people"
    }
  },
  "additionalProperties": false
}
```

## `user.me`

Who is calling: id, kind, role, tenant and, for an account, its email.

- **Scope:** `meta:read` · **Autonomy:** L0 · **Audited:** no
- **Principals:** human, agent, external_agent, service

Input schema:

```json
{
  "type": "object",
  "title": "Empty",
  "properties": {},
  "additionalProperties": false
}
```

## `user.reset`

Replace a person's password and authenticator; the link is emailed or returned once.

- **Scope:** `users:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "UserRef",
  "properties": {
    "email": {
      "type": "string",
      "description": "The person's address"
    }
  },
  "additionalProperties": false,
  "required": [
    "email"
  ]
}
```

## `user.update`

Change a person's role, or disable or enable them.

- **Scope:** `users:write` · **Autonomy:** L2 · **Audited:** yes
- **Principals:** human

Input schema:

```json
{
  "type": "object",
  "title": "UserUpdate",
  "properties": {
    "email": {
      "type": "string",
      "description": "The person's address"
    },
    "role": {
      "type": "string",
      "enum": [
        "",
        "admin",
        "operator",
        "deployer",
        "reader"
      ],
      "description": "The new role; empty keeps it"
    },
    "disabled": {
      "anyOf": [
        {
          "type": "boolean"
        },
        {
          "type": "null"
        }
      ],
      "description": "true signs the person out everywhere and keeps them out; false lets them back"
    }
  },
  "additionalProperties": false,
  "required": [
    "email"
  ]
}
```
