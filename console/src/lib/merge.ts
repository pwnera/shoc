/**
 * What MergeDialog starts from: each merge's input cut into the parts a tab
 * edits, every field its gate reads, with a worked example beside each field
 * as a comment (YAML drops it). The reason and anything linked by name, such
 * as a rule's playbook, are fields of the dialog instead. A backlog item seeds
 * a template with what it already says. And the facts a passing check shows,
 * naming rules, packs and playbooks by their titles.
 */

/** One editor tab: the input field it fills and the YAML it starts with. */
export type Section = { field: string; label: string; template: string };

type Data = Record<string, unknown>;

/** A rule's or hunt pack's title (`hunt:<id>`), and a playbook's, by id; the id when the console has none. */
export type Names = { rule: (id: string) => string; playbook: (id: string) => string };

export function ruleFacts(d: Data, name: Names): [string, string | null][] {
  const run = (d.backtest ?? {}) as { days?: number; findings?: number };
  return d.narrows
    ? [["stops matching", `${run.findings ?? 0} events · 30d`]]
    : [
        ["rule", name.rule(String(d.rule_id))],
        ["playbook", name.playbook(String(d.playbook_id))],
        ["would have fired", `${run.findings ?? 0} · ${run.days ?? 0}d`],
      ];
}

export function packFacts(d: Data, name: Names): [string, string | null][] {
  const checked = (d.checked ?? {}) as { readiness?: string; tuples?: number; window?: string };
  return [
    ["pack", name.rule(`hunt:${String(d.pack_id)}`)],
    ["readiness", checked.readiness ?? null],
    ["would return", checked.tuples !== undefined ? `${checked.tuples} · ${checked.window}` : null],
  ];
}

export function playbookFacts(d: Data, name: Names): [string, string | null][] {
  const took = Object.entries((d.took_from ?? {}) as Record<string, string>);
  return [
    ["playbook", name.playbook(String(d.playbook_id))],
    ["answers", ((d.rules ?? []) as string[]).map(name.rule).join(", ")],
    ["takes", took.length ? took.map(([rule, from]) => `${name.rule(rule)} ← ${name.playbook(from)}`).join(", ") : null],
  ];
}

/** A plain YAML scalar when it reads as one, else JSON, which YAML reads too. */
const scalar = (v: unknown) => (typeof v === "string" && /^[\w.-]+$/.test(v) ? v : JSON.stringify(v));

/**
 * A tab's template with what a backlog item already says: a list tab
 * (`hide_events`) becomes the list, and each key of `values` replaces its
 * line's example (`attack`, `title`, `product` under logsource). Empty values
 * keep the example.
 */
export function seeded(sections: Section[], field: string, values: Data | unknown[]): Section[] {
  const kept = Array.isArray(values)
    ? values
    : Object.fromEntries(Object.entries(values).filter(([, v]) => v !== undefined && v !== "" && !(Array.isArray(v) && !v.length)));
  return sections.map((s) => {
    if (s.field !== field) return s;
    if (Array.isArray(kept)) return kept.length ? { ...s, template: `${JSON.stringify(kept)}\n` } : s;
    return {
      ...s,
      template: s.template.replace(/^(\s*)([\w.]+):.*$/gm, (line, pad: string, key: string) =>
        key in kept ? `${pad}${key}: ${scalar(kept[key])}` : line,
      ),
    };
  });
}

export const RULE_SECTIONS: Section[] = [
  {
    field: "rule",
    label: "Rule",
    template: `id:                     # okta_log_stream_disabled
title:                  # An Okta log stream was deactivated or deleted
description:            # An admin turned off the stream that feeds the SIEM.
severity: medium        # low, medium, high or critical
attack: []              # [T1562.008]
logsource:
  product:              # okta
detection:
  selection:
    api.operation:      # [system.log_stream.lifecycle.deactivate, system.log_stream.lifecycle.delete]
  condition: selection
entity: actor.user.name
`,
  },
  {
    field: "fixtures",
    label: "Fixtures",
    template: `source:                 # okta
positive: []            # raw records that must fire, as the source sends them, without timestamps
negative: []            # raw records that must not
`,
  },
  {
    field: "ads",
    label: "ADS",
    template: `goal:                   # Catch an admin cutting Okta's audit feed
categorization:         # Defense Evasion / T1562.008
strategy:               # Match the two log-stream lifecycle events
technical_context:      # Okta System Log eventType, outcome SUCCESS
blind_spots:            # Editing the stream's destination instead
false_positives:        # A planned SIEM migration
validation:             # Deactivate a test stream in a preview org
priority:               # high
`,
  },
];

export const NARROWING_SECTIONS: Section[] = [
  {
    field: "exclude",
    label: "Exclude",
    template: `- src_endpoint.ip:      # 198.51.100.7
  actor.user.uid:       # svc-backup
`,
  },
  {
    field: "hide_events",
    label: "Hide events",
    template: `[]                      # event ids the narrowing must stop matching
`,
  },
];

export const PACK_SECTIONS: Section[] = [
  {
    field: "pack",
    label: "Pack",
    template: `id:                     # okta_admin_first_policy_change
title:                  # An admin changes an Okta policy they never touched
hypothesis:             # A stolen admin session loosens policy first
attack: []              # [T1556]
logsource:
  product:              # okta
window: 1d
cadence_days: 1
detection:
  selection:
    api.operation|startswith:   # policy.
  condition: selection
baseline:
  first_seen: []        # [actor.user.name, api.operation]
  lookback: 30d
pivot: []               # [actor.user.name, api.operation, src_endpoint.ip]
triage:                 # Was the change ticketed, and did the session add an admin?
`,
  },
  {
    field: "fixtures",
    label: "Fixtures",
    template: `source:                 # okta
baseline: []            # raw records seen before: the pack stays quiet on them
surfaced: []            # raw records it must return once baseline came first
`,
  },
];

export const PLAYBOOK_SECTIONS: Section[] = [
  {
    field: "playbook",
    label: "Playbook",
    template: `id:                     # contain_okta_audit_tampering
title:                  # Contain an Okta admin blinding the audit trail
description:
rules: []               # [okta_log_stream_disabled, hunt:okta_admin_first_policy_change]
questions:              # at least two, each with its own id
  - id:                 # who_and_where
    ask:                # Which admin made the change, and from which address?
  - id:                 # around_it
    ask:                # What did the same session do an hour either side?
benign_when: []         # [A planned SIEM migration, with a new stream within the hour]
trigger:
  verdict: [malicious]
  severity_at_least: high
  min_confidence: 0.8
steps:                  # actions and their parameters: Response › Autonomy
  - name: page the on-call engineer
    action: notify.page
    params:
      summary: "shoc: {{ case.title }}"
      severity: critical
      dedup_key: "{{ case.case_uid }}"
`,
  },
];
