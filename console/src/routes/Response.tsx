/**
 * Response: what shoc did or tried, whom it paged, and what it may do without
 * you. The strip holds the policy's standing facts (dry run or acting, the
 * default floors, the guards, each caller's ceiling); the tabs are Activity
 * (default), Pages, Playbooks and Autonomy. Approving lives in the Overview
 * inbox and on the case; Undo and Run now live in ActionDialog. Where shoc can
 * act is Connections' (each product's Response view).
 *
 * Capabilities used: action.list, policy.show, playbook.list; the tabs name
 * the rest.
 */
import type { ReactNode } from "react";
import { SeverityBadge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page";
import { Popover } from "@/components/ui/pop";
import { AutonomyBadge } from "@/components/ui/status";
import { Strip, type StripFact } from "@/components/ui/strip";
import { TabPanel, Tabs } from "@/components/ui/misc";
import { useTabKeys } from "@/lib/commands";
import { percent } from "@/lib/format";
import { isPage, principalWord } from "@/lib/labels";
import { useTab } from "@/lib/param";
import { actionTypes } from "@/lib/policy";
import { staleSince } from "@/lib/loaded";
import { useActionLog, usePlaybooks, usePolicy } from "@/lib/queries";
import type { Severity } from "@/types";
import { Activity } from "./response/Activity";
import { Autonomy } from "./response/Autonomy";
import { Pages } from "./response/Pages";
import { Playbooks } from "./response/Playbooks";
import { isActivity } from "./response/policy";

const TABS = ["activity", "pages", "playbooks", "autonomy"] as const;
type Tab = (typeof TABS)[number];

export function Response() {
  const [tab, setTab] = useTab(TABS);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  const log = useActionLog();
  const playbooks = usePlaybooks();
  const policy = usePolicy();
  const rows = log.data?.rows;

  const tabs: { value: Tab; label: string; count: number | null }[] = [
    { value: "activity", label: "Activity", count: rows ? rows.filter(isActivity).length : null },
    // Pages, as the Overview's counter counts them; the list's pager says how many groups hold them.
    { value: "pages", label: "Pages", count: rows ? rows.filter(isPage).length : null },
    { value: "playbooks", label: "Playbooks", count: playbooks.data?.count ?? null },
    { value: "autonomy", label: "Autonomy", count: policy.data ? actionTypes(policy.data.data).length : null },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Response" strip={<PolicyStrip />} />
      <Tabs id="response" label="Response" tabs={tabs} value={tab} onChange={setTab} />
      <TabPanel id="response" value={tab}>
        {tab === "activity" ? <Activity /> : null}
        {tab === "pages" ? <Pages /> : null}
        {tab === "playbooks" ? <Playbooks /> : null}
        {tab === "autonomy" ? <Autonomy /> : null}
      </TabPanel>
    </div>
  );
}

/** A strip fact whose count opens a popover of what it counts; loaded, its label sits inside the trigger. */
function Counted({ n, label, title, children }: { n: number; label: string; title: string; children: ReactNode }) {
  if (!n)
    return (
      <span className="inline-flex items-baseline gap-1.5">
        0<span className="sh-strip__label">{label}</span>
      </span>
    );
  return (
    <Popover
      pad
      label={title}
      trigger={(props) => (
        <button {...props} type="button" className="inline-flex items-baseline gap-1.5 bg-transparent p-0 text-inherit [font:inherit]">
          {n}
          <span className="sh-strip__label">{label}</span>
        </button>
      )}
    >
      <span className="sh-label">{title}</span>
      {children}
    </Popover>
  );
}

/** Dry run or acting, the default floors, the guards and each caller's ceiling: the policy facts this screen owns. */
function PolicyStrip() {
  const policy = usePolicy();
  const log = useActionLog();
  const data = policy.data?.data;
  const defaults = data?.defaults ?? {};
  const guards = data?.guards ?? {};
  const severity = typeof defaults.severity_at_least === "string" ? (defaults.severity_at_least as Severity) : null;
  const confidence = typeof defaults.min_confidence === "number" ? defaults.min_confidence : null;
  const most = typeof guards.max_auto_actions_per_case === "number" ? guards.max_auto_actions_per_case : null;
  const protectedTargets = Array.isArray(guards.protected_targets) ? guards.protected_targets.map(String) : [];
  const callers = Object.entries(data?.principals ?? {});

  // Five facts at most: the two default floors share one.
  const facts: StripFact[] = [
    {
      key: "floor",
      label: "to act alone",
      value:
        severity || confidence !== null ? (
          <span className="inline-flex items-center gap-1.5">
            {severity ? (
              <>
                ≥ <SeverityBadge severity={severity} />
              </>
            ) : null}
            {confidence !== null ? <span>≥ {percent(confidence)}</span> : null}
          </span>
        ) : null,
      tip: "Acts alone at this severity and confidence or higher",
    },
    { label: "auto per case", value: most, tip: "Most actions run alone on one case" },
  ];
  if (guards.require_citations === true) facts.push({ label: "required", value: "citations", key: "citations" });
  facts.push({
    key: "protected",
    label: data ? "" : "never acted on alone",
    value: data ? (
      <Counted n={protectedTargets.length} label="never acted on alone" title="Targets">
        <ul className="m-0 mt-2 flex list-none flex-col gap-1 p-0">
          {protectedTargets.map((pattern) => (
            <li key={pattern} className="sh-mono sh-mono--strong">
              {pattern}
            </li>
          ))}
        </ul>
      </Counted>
    ) : null,
  });
  facts.push({
    key: "callers",
    label: data ? "" : "caller ceilings",
    value: data ? (
      <Counted n={callers.length} label="caller ceilings" title="The most each caller may do">
        <ul className="m-0 mt-2 flex list-none flex-col gap-1 p-0">
          {callers.map(([caller, level]) => (
            <li key={caller} className="flex items-center justify-between gap-4">
              <span>{principalWord(caller)}</span>
              <AutonomyBadge level={String(level)} />
            </li>
          ))}
        </ul>
      </Counted>
    ) : null,
  });

  return (
    <Strip
      state={defaults.dry_run === true ? { tone: "warn", word: "Dry run" } : { tone: "idle", word: "Acting" }}
      facts={facts}
      loading={policy.isPending}
      error={policy.data ? undefined : policy.error}
      onRetry={() => void policy.refetch()}
      // The tabs' lists come from the shared log: a failed refresh of either says how old the screen is.
      asOf={staleSince(policy) ?? staleSince(log)}
    />
  );
}
