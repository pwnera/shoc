/**
 * Hunts: is the crew hunting, and did any hunt turn up something it cannot
 * explain? The strip counts the window's runs by outcome, and the chart under
 * it draws them by day (by week over 90 days); Runs lists them, Packs says which packs can run here, Backlog holds the
 * hypotheses no pack answers yet. Hunting here means testing a behaviour, not
 * sweeping for a value: value sweeps live on Intel.
 *
 * Capabilities: hunt.results (runs, metrics, readiness), hunt.backlog,
 * hunt.daily (Run today's hunts, behind a confirm), hunt.pack (the pack and item dialogs),
 * hunt.merge (New pack, an item's Merge), hunt.decide (an item's Reject, Done, Reopen),
 * hunt.revert (the pack dialog), intel.reports (report titles); reads ops.alerts for
 * `hunt.gap` marks.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Button, CrewMark } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Spinner, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Confirm, Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { Skel } from "@/components/ui/state";
import { Strip } from "@/components/ui/strip";
import { TimeBar } from "@/components/ui/timebar";
import { Tip } from "@/components/ui/tip";
import { useCommand, useTabKeys } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { day } from "@/lib/format";
import { OUTCOMES } from "@/lib/labels";
import { staleSince } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { useParam, useTab } from "@/lib/param";
import { usePopParam } from "@/lib/popup";
import { useAlerts, useHuntBacklog, useHuntResults, useRunDailyHunts } from "@/lib/queries";
import { toastError } from "@/lib/toast";
import type { HuntOutcome, HuntRun } from "@/types";
import { Backlog } from "./hunts/Backlog";
import { PackDialog } from "./hunts/PackDialog";
import { Packs } from "./hunts/Packs";
import { Runs } from "./hunts/Runs";
import { applicable, byReadiness, byWeek, dayOf, outcomeBuckets, weekOf } from "./hunts/runs";

const TABS = ["runs", "packs", "backlog"] as const;
const WINDOWS = ["7", "30", "90"] as const;
type Window = (typeof WINDOWS)[number];


export function Hunts() {
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useTab(TABS);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  const [days, setDays] = useParam<Window>("days", "7");
  const win = WINDOWS.includes(days) ? days : "7";
  const results = useHuntResults("", Number(win), 200);
  const backlog = useHuntBacklog("");
  const alerts = useAlerts();
  const daily = useRunDailyHunts();
  const hunt = () => {
    if (!daily.isPending) daily.mutate(undefined, { onError: (error) => toastError(error, "Hunts failed") });
  };
  // The button and the palette (`?do=hunts.daily`) open the confirm; only its Enter spends crew tokens.
  const [asking, setAsking] = useState(false);
  useCommand("hunts.daily", () => setAsking(true));

  const runs = results.data?.runs ?? [];
  const readiness = [...(results.data?.readiness ?? [])].sort(byReadiness);
  const titles = new Map(readiness.map((r) => [r.pack_id, r.title ?? r.pack_id]));
  const titleOf = (id: string) => titles.get(id) ?? id;
  const lastRun = new Map<string, string>();
  for (const run of runs) if ((lastRun.get(run.pack_id) ?? "") < run.ran_at) lastRun.set(run.pack_id, run.ran_at);
  const gaps = new Set((alerts.data?.alerts ?? []).filter((a) => a.kind === "hunt.gap").map((a) => a.subject));

  // The filter matches the bars: days up to 30 days, weeks past it. A value from the other window still shows its chip.
  const weeks = byWeek(Number(win));
  const starts = (of: (iso: string) => string) => [...new Set(runs.map((r) => of(r.ran_at)))].sort().reverse();
  const dims: Dim<HuntRun>[] = [
    {
      id: "outcome",
      label: "outcome",
      options: (Object.keys(OUTCOMES) as HuntOutcome[]).map((o) => ({
        value: o,
        label: OUTCOMES[o].word,
        count: runs.filter((r) => r.outcome === o).length,
      })),
      test: (r, v) => r.outcome === v,
    },
    {
      id: "day",
      label: "day",
      options: weeks ? [] : starts(dayOf).map((d) => ({ value: d, label: day(`${d}T12:00:00`) })),
      test: (r, v) => dayOf(r.ran_at) === v,
    },
    {
      id: "week",
      label: "week of",
      options: weeks ? starts(weekOf).map((d) => ({ value: d, label: day(`${d}T12:00:00`) })) : [],
      test: (r, v) => weekOf(r.ran_at) === v,
    },
    {
      id: "finding",
      label: "raised",
      options: [{ value: "yes", label: "a finding", count: runs.filter((r) => r.finding_uid).length }],
      test: (r) => Boolean(r.finding_uid),
    },
  ];
  const filters = useFilters(dims, {
    match: (r, text) => `${titleOf(r.pack_id)} ${r.pack_id} ${r.triage}`.toLowerCase().includes(text),
  });
  /** A strip fact or a bar: one filter on, on the Runs tab, in one history step. */
  const press = (id: string, value: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      for (const dim of dims) if (dim.id !== id) out.delete(dim.id);
      if (!value || out.get(id) === value) out.delete(id);
      else out.set(id, value);
      out.delete("tab");
      out.delete("pane");
      return out;
    });

  const by = results.data?.metrics.by_outcome ?? {};
  const total = Object.values(by).reduce((sum, n) => sum + n, 0);
  const suspicious = by.suspicious ?? 0;
  const found = runs.filter((r) => r.finding_uid).length;
  const state = suspicious
    ? { tone: "warn" as const, word: "Suspicious" }
    : total
      ? { tone: "good" as const, word: "Hunting" }
      : { tone: "idle" as const, word: "Idle" };
  const buckets = outcomeBuckets(runs, Number(win), now, weeks ? filters.values.week : filters.values.day);

  const openItems = (backlog.data?.items ?? []).filter((i) => i.state === "open").length;
  const packId = params.get("pack");
  const [packList, setPackList] = useState<string[]>([]);
  const openPack = usePopParam("pack");
  const packAt = packId ? packList.indexOf(packId) : -1;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Hunts"
        aside={
          <Popover
            label="Run today's hunts"
            align="end"
            open={asking}
            onOpenChange={setAsking}
            trigger={(props) => (
              <Tip label="Every pack that is due, as the schedule runs them">
                <Button {...props} variant="crew" disabled={daily.isPending}>
                  {daily.isPending ? <Spinner /> : <CrewMark />}
                  {daily.isPending ? "Hunting…" : "Run today's hunts"}
                </Button>
              </Tip>
            )}
          >
            <Confirm
              what="Run every pack that is due"
              go="Run"
              onConfirm={() => {
                setAsking(false);
                hunt();
              }}
              onCancel={() => setAsking(false)}
            />
          </Popover>
        }
        strip={
          <>
            <Strip
              state={state}
              loading={results.isPending}
              error={results.isError && !results.data ? results.error : undefined}
              onRetry={() => void results.refetch()}
              asOf={staleSince(results)}
              facts={[
                { label: "runs", value: total, onClick: () => press("outcome", ""), key: "runs" },
                {
                  label: "suspicious",
                  value: suspicious,
                  tone: suspicious ? "warn" : undefined,
                  onClick: () => press("outcome", "suspicious"),
                  pressed: filters.values.outcome === "suspicious",
                },
                {
                  label: found === 1 ? "finding" : "findings",
                  value: found,
                  onClick: () => press("finding", "yes"),
                  pressed: filters.values.finding === "yes",
                },
                {
                  label: "couldn't look",
                  value: by.gap ?? 0,
                  onClick: () => press("outcome", "gap"),
                  pressed: filters.values.outcome === "gap",
                },
              ]}
              aside={
                <Seg
                  label="Window"
                  value={win}
                  onChange={setDays}
                  options={WINDOWS.map((w) => ({ value: w, label: `${w}d` }))}
                />
              }
            />
            {/* Full width under the strip, as on Findings and Explore; its height is held while the runs load. */}
            {results.isPending ? (
              <Skel kind="block" />
            ) : runs.length ? (
              <TimeBar
                variant="bars"
                from={buckets[0]!.from}
                to={buckets[buckets.length - 1]!.to}
                bars={buckets}
                onBucket={(b) => press(weeks ? "week" : "day", b.key)}
                label={weeks ? "Runs by week and outcome" : "Runs by day and outcome"}
              />
            ) : null}
          </>
        }
      />
      <Tabs
        id="hunts"
        label="Hunts"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "runs", label: "Runs" },
          { value: "packs", label: "Packs", count: results.data ? readiness.filter(applicable).length : null },
          { value: "backlog", label: "Backlog", count: backlog.data ? openItems : null },
        ]}
      />
      <TabPanel id="hunts" value={tab}>
        <Card>
          {tab === "runs" ? (
            <Runs
              runs={runs}
              titleOf={titleOf}
              dims={dims}
              filters={filters}
              days={win}
              loading={results.isPending}
              error={results.isError && !results.data ? results.error : undefined}
              onRetry={() => void results.refetch()}
            />
          ) : tab === "packs" ? (
            <Packs
              readiness={readiness}
              lastRun={lastRun}
              gaps={gaps}
              loading={results.isPending}
              error={results.isError && !results.data ? results.error : undefined}
              onRetry={() => void results.refetch()}
              onOpen={(row, list) => {
                setPackList(list.map((r) => r.pack_id));
                openPack(row.pack_id);
              }}
            />
          ) : (
            <Backlog
              items={backlog.data?.items ?? []}
              loading={backlog.isPending}
              error={backlog.isError && !backlog.data ? backlog.error : undefined}
              onRetry={() => void backlog.refetch()}
              titles={titles}
            />
          )}
        </Card>
      </TabPanel>
      {packId ? (
        <PackDialog
          packId={packId}
          pack={readiness.find((r) => r.pack_id === packId)}
          runs={runs.filter((r) => r.pack_id === packId)}
          days={win}
          pending={results.isPending}
          error={results.isError && !results.data ? results.error : undefined}
          onRetry={() => void results.refetch()}
          onClose={() => openPack(null, true)}
          step={
            packAt >= 0
              ? {
                  index: packAt,
                  total: packList.length,
                  onPrev: packAt > 0 ? () => openPack(packList[packAt - 1]!, true) : undefined,
                  onNext: packAt < packList.length - 1 ? () => openPack(packList[packAt + 1]!, true) : undefined,
                }
              : undefined
          }
        />
      ) : null}
    </div>
  );
}
