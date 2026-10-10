/**
 * Detection: can my rules see an attack today, which tactics can they see in
 * the data that arrives, and what has the crew changed or muted? Beside the
 * state word, the readiness share splits the catalogue with a count and word
 * per state (each filters Rules); the tabs are the rules, the tactics they
 * cover, the crew's proposed changes and what is muted. Running every rule
 * lives in ⋯, behind a confirm.
 *
 * Capabilities used: rule.list, health.rules, detection.backlog,
 * suppression.list, detect.run; Coverage adds health.quality and hunt.results.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/ui/page";
import { Skel } from "@/components/ui/state";
import { Strip, type StripTone } from "@/components/ui/strip";
import { TabPanel, Tabs } from "@/components/ui/misc";
import { useCommand, useTabKeys } from "@/lib/commands";
import { count } from "@/lib/format";
import { RULE_STATES, type RuleState } from "@/lib/labels";
import { loadError, staleSince } from "@/lib/loaded";
import { useTab } from "@/lib/param";
import { useDetectionBacklog, useRunDetections, useSuppressions } from "@/lib/queries";
import { Changes } from "./detection/Changes";
import { Coverage } from "./detection/Coverage";
import { MoreMenu } from "./detection/MoreMenu";
import { Rules } from "./detection/Rules";
import { ShareBar, type ShareSegment } from "./detection/ShareBar";
import { Suppressions } from "./detection/Suppressions";
import { useRuleRows } from "./detection/state";

const TABS = ["rules", "coverage", "changes", "suppressions"] as const;
const RUN_ALL = "Run every rule now";


export function Detection() {
  const [tab, setTab] = useTab(TABS);
  const [params, setParams] = useSearchParams();
  const { rules, health, rows } = useRuleRows();
  const backlog = useDetectionBacklog("open");
  const suppressions = useSuppressions();
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));

  // The menu opens from ".", and on its confirm from the palette (`?do=detection.run-all`).
  const [menu, setMenu] = useState(false);
  const [asking, setAsking] = useState<string | null>(null);
  const run = useRunDetections();
  useCommand("detection.menu", () => {
    setAsking(null);
    setMenu(true);
  });
  useCommand("detection.run-all", () => {
    setAsking(RUN_ALL);
    setMenu(true);
  });

  const picked = params.get("state") ?? "";
  // A segment filters Rules: one URL write, so the tab and the filter change together.
  const pick = (state: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.delete("tab");
      out.delete("pane");
      if (picked === state) out.delete("state");
      else out.set("state", state);
      return out;
    });

  const tally = new Map<string, number>();
  for (const row of rows) if (row.state) tally.set(row.state, (tally.get(row.state) ?? 0) + 1);
  const word: { tone: StripTone; word: string } = tally.get("failing")
    ? { tone: "bad", word: "Failing" }
    : rows.some((r) => (r.health?.findings_7d ?? 0) > 0)
      ? { tone: "good", word: "Live" }
      : { tone: "warn", word: "Blind" };
  const total = rules.data?.count;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Detection"
        aside={
          <MoreMenu
            label="Detection"
            open={menu}
            asking={asking}
            onOpenChange={setMenu}
            onAsk={setAsking}
            items={[
              {
                label: RUN_ALL,
                onSelect: () => run.mutateAsync({}),
                confirm: {
                  what: total ? `${RUN_ALL} · ${count(total, "rule")}` : RUN_ALL,
                  go: "Run",
                },
              },
            ]}
          />
        }
        strip={
          // The share sits beside the strip rather than in its 240px viz slot: the
          // whole catalogue's readiness, with a word for every state that holds rules.
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <Strip
              state={word}
              loading={health.isPending || rules.isPending}
              error={loadError(health) ?? loadError(rules)}
              asOf={staleSince(health) ?? staleSince(rules)}
              onRetry={() => {
                void health.refetch();
                void rules.refetch();
              }}
            />
            {health.isPending || rules.isPending ? (
              // As tall as the bar and its legend (two lines on a phone), so the tabs never move when it lands.
              <div className="flex min-w-0 flex-1 basis-80 flex-col gap-1.5" aria-hidden>
                <Skel kind="row" className="!h-2" />
                <span className="flex h-[18px] items-center">
                  <Skel kind="row" width="60%" />
                </span>
                <span className="flex h-[18px] items-center md:hidden">
                  <Skel kind="row" width="35%" />
                </span>
              </div>
            ) : (loadError(health) ?? loadError(rules)) ? null : (
              <ShareBar
                legend
                label="Rules by state"
                className="flex-1 basis-80"
                segments={RULE_STATES.map((s) => ({
                  key: s.id,
                  label: s.word,
                  value: tally.get(s.id) ?? 0,
                  ...SHARE[s.id],
                  pressed: picked === s.id,
                  onClick: () => pick(s.id),
                }))}
              />
            )}
          </div>
        }
      />

      <Tabs
        id="detection"
        label="Detection"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "rules", label: "Rules", count: rules.data ? rules.data.count : null },
          { value: "coverage", label: "Coverage" },
          { value: "changes", label: "Changes", count: backlog.data ? backlog.data.count : null },
          {
            value: "suppressions",
            label: "Muted",
            count: suppressions.data ? suppressions.data.count : null,
          },
        ]}
      />
      <TabPanel id="detection" value={tab}>
        {tab === "rules" ? <Rules rows={rows} rules={rules} health={health} /> : null}
        {tab === "coverage" ? <Coverage /> : null}
        {tab === "changes" ? <Changes /> : null}
        {tab === "suppressions" ? <Suppressions /> : null}
      </TabPanel>
    </div>
  );
}

/* Bad and warn are worth a look; live is good; the blind states fade: armed solid, never sent dashed, no source hatched. */
const SHARE: Record<RuleState, Pick<ShareSegment, "tone" | "fill">> = {
  failing: { tone: "bad" },
  noisy: { tone: "warn" },
  field_empty: { tone: "warn" },
  live: { tone: "good" },
  armed: { tone: "muted" },
  never_sent: { tone: "idle", fill: "dashed" },
  no_source: { tone: "idle", fill: "hatched" },
};
