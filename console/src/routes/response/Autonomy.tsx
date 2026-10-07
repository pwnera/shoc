/**
 * Response › Autonomy: what shoc may do without you, per action type, grouped
 * by product ("AWS · 3 auto · 2 you"). A row is reversible or one-way, its
 * autonomy and its label; it opens a popup (`?policy=<type>`) with the type
 * config as code names, the floors, how long it lasts, what it waits for
 * before acting alone and what it needs to act. Read-only: policy changes go
 * through config as code, and credentials through Connections. The
 * default floors, the guards and each caller's ceiling are the strip's, so
 * they are not repeated here. The text (`?aq=`) matches the action and its
 * product; chips narrow to a product, an autonomy or one-way actions.
 *
 * Capabilities used: policy.show.
 */
import { platformOf } from "@/components/brands";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Dialog, Fields } from "@/components/ui/dialog";
import { FilterBar } from "@/components/ui/filterbar";
import { Meter } from "@/components/ui/meter";
import { Empty } from "@/components/ui/misc";
import { QueryState } from "@/components/ui/state";
import { AutonomyBadge } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { percent, span } from "@/lib/format";
import { actionLabel, AUTONOMY } from "@/lib/labels";
import { usePopValue } from "@/lib/popup";
import { actionTypes, ruleOf, type ActionRule } from "@/lib/policy";
import { usePolicy } from "@/lib/queries";
import type { PolicyView } from "@/types";
import { PlatformMark, Reach } from "./marks";

const COLUMNS: Column<ActionRule>[] = [
  { label: "", width: 36, truncate: false, cell: (rule) => <Reach reversible={rule.reversible} /> },
  // A width, not fit: every group is its own table, and the labels line up across them.
  { label: "", width: 72, truncate: false, cell: (rule) => <AutonomyBadge level={rule.autonomy} /> },
  { label: "", strong: true, cell: (rule) => actionLabel(rule.type) },
];

export function Autonomy() {
  const policy = usePolicy();
  const data = policy.data?.data;
  const [open, pop] = usePopValue("policy");

  const all = actionTypes(data).map((type) => ruleOf(data, type));
  const platforms = [...new Set(all.map((r) => platformOf(r.type).id))];
  const count = (test: (r: ActionRule) => boolean) => all.filter(test).length;
  const dims: Dim<ActionRule>[] = [
    {
      id: "product",
      label: "product",
      options: platforms
        .map((id) => ({ value: id, label: platformOf(id).name, count: count((r) => platformOf(r.type).id === id) }))
        .sort((a, b) => a.label.localeCompare(b.label)),
      test: (r, v) => platformOf(r.type).id === v,
    },
    {
      id: "autonomy",
      label: "autonomy",
      options: (["L1", "L2", "L0"] as const).map((level) => ({
        value: level,
        label: AUTONOMY[level],
        count: count((r) => r.autonomy === level),
      })),
      test: (r, v) => r.autonomy === v,
    },
    {
      id: "reach",
      label: "reach",
      options: [{ value: "one-way", count: count((r) => !r.reversible) }],
      test: (r) => !r.reversible,
    },
  ];
  const filters = useFilters(dims, {
    text: "aq",
    match: (r, text) => `${actionLabel(r.type)} ${r.type} ${platformOf(r.type).name}`.toLowerCase().includes(text),
  });

  const byPlatform = new Map<string, ActionRule[]>();
  for (const rule of all.filter(filters.keep)) {
    const id = platformOf(rule.type).id;
    byPlatform.set(id, [...(byPlatform.get(id) ?? []), rule]);
  }
  const groups = [...byPlatform]
    .map(([id, rules]) => ({
      id,
      name: platformOf(id).name,
      rules: rules.sort((a, b) => actionLabel(a.type).localeCompare(actionLabel(b.type))),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const flat = groups.flatMap((g) => g.rules);
  const nav = useListNav(flat, (rule) => rule.type, { onOpen: (rule) => pop(rule.type) });
  const at = flat.findIndex((rule) => rule.type === open);
  const picked = flat[at];
  // Stepping in the popup moves the list behind it too.
  const step = (rule: ActionRule | undefined) => () => {
    if (!rule) return;
    nav.setActive(rule.type);
    pop(rule.type, true);
  };

  return (
    <Card>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter actions"
      />
      <QueryState
        queries={policy}
        isEmpty={!flat.length}
        empty={
          all.length ? (
            <Empty kind="filtered" title="No action matches" onClear={filters.clear} />
          ) : (
            <Empty title="No action in the policy" />
          )
        }
      >
        <div className="max-h-[min(72dvh,760px)] overflow-y-auto scrollbar-thin">
          {groups.map((group) => (
            <section key={group.id} aria-label={group.name}>
              <h2 className="sh-label sticky top-0 z-[1] m-0 flex h-7 items-center gap-2 border-b border-line-1 bg-bg-1 px-3">
                <PlatformMark id={group.id} small />
                {[group.name, ...(["L1", "L2", "L0"] as const).flatMap((level) => {
                  const n = group.rules.filter((r) => r.autonomy === level).length;
                  return n ? [`${n} ${AUTONOMY[level]}`] : [];
                })].join(" · ")}
              </h2>
              <Table columns={COLUMNS} rows={group.rules} rowKey={(rule) => rule.type} rowProps={nav.rowProps} label={group.name} />
            </section>
          ))}
        </div>
      </QueryState>
      {picked ? (
        <PolicyDialog
          rule={picked}
          policy={data}
          onClose={() => pop(null)}
          step={{
            index: at,
            total: flat.length,
            onPrev: at > 0 ? step(flat[at - 1]) : undefined,
            onNext: at < flat.length - 1 ? step(flat[at + 1]) : undefined,
          }}
        />
      ) : null}
    </Card>
  );
}

/** A required parameter in words: `access_key_id` is the access key, `user_name` the user. */
const PARAMS: Record<string, string> = {
  user_name: "user",
  role_name: "role",
  policy_arn: "policy",
  vm_id: "VM",
  client_id: "app",
  hash: "file hash",
  ip: "IP",
  summary: "message",
};
const paramWord = (param: string) => PARAMS[param] ?? param.replace(/_id$/, "").replace(/_/g, " ");

/** One action type's policy: the playbook page's step popup shows the same. */
export function PolicyDialog({
  rule,
  policy,
  onClose,
  step,
}: {
  rule: ActionRule;
  policy: PolicyView | undefined;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const floor = policy?.defaults.min_confidence;
  return (
    <Dialog
      title={actionLabel(rule.type)}
      // The type is what config as code names: a copy chip, so a 390px head keeps the title and the stepper.
      id={rule.type}
      onClose={onClose}
      step={step}
      head={<AutonomyBadge level={rule.autonomy} />}
    >
      <Fields
        ruled
        rows={[
          ["Undo", rule.reversible ? <Badge tone="idle">↺ reversible</Badge> : <Badge tone="bad">⊘ one-way</Badge>],
          [
            "Confidence",
            rule.min_confidence !== undefined ? (
              <Meter
                value={rule.min_confidence}
                marks={typeof floor === "number" && floor !== rule.min_confidence ? [{ at: floor, label: "default" }] : undefined}
                label="Minimum confidence"
                valueText={`at least ${percent(rule.min_confidence)}`}
                format={(v) => `≥ ${percent(v)}`}
                width={120}
              />
              ) : null,
            ],
            [
              "Severity",
              rule.severity_at_least ? (
                <span className="inline-flex items-center gap-1.5">
                  <span className="text-fg-3">≥</span>
                  <SeverityBadge severity={rule.severity_at_least} />
                </span>
              ) : null,
            ],
            ["Lasts", rule.ttl_minutes ? <span className="sh-mono sh-mono--strong">{span(rule.ttl_minutes * 60)}</span> : null],
            [
              // The gates before it may act alone (RSP-5, RSP-6); failing one, it waits for you.
              "Checks first",
              rule.research || rule.review ? (
                <span className="flex flex-wrap gap-1.5">
                  {rule.research ? <Badge title="Not shared infrastructure, not our own egress">target researched</Badge> : null}
                  {rule.review ? <Badge title="The IR Commander raised no objection">crew review</Badge> : null}
                </span>
              ) : null,
            ],
            [
              "Needs",
              rule.required.length ? (
                <span className="flex flex-wrap gap-1.5">
                  {rule.required.map((p) => (
                    <Badge key={p} title={p}>
                      {paramWord(p)}
                    </Badge>
                  ))}
                </span>
              ) : null,
            ],
        ]}
      />
    </Dialog>
  );
}
