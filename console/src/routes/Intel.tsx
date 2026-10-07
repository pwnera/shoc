/**
 * Intel: does anything our threat feeds carry show up in our logs, and what
 * has CTI read? The strip says whether the feeds are healthy (the sources
 * themselves are Connections › Intel's, where it links), the last pull, and
 * what CTI read today against its daily budget. Indicators lists what the
 * feeds and reports stored, Leads the values worth sweeping, Reports what the
 * CTI role read and what it left unread. Looking a value up is EntityDialog's
 * (Look up in the indicator dialog opens it there).
 *
 * Capabilities: intel.list (indicators, total, feeds, budget), intel.add,
 * intel.remove, intel.reports, intel.digest, hunt.suggest, hunt.run (sweeps),
 * hunt.propose (a report's suggested hunts).
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Meter } from "@/components/ui/meter";
import { TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Strip, type StripFact } from "@/components/ui/strip";
import { useCommand, useTabKeys } from "@/lib/commands";
import { age, compact, num, stamp } from "@/lib/format";
import { loadError, staleSince } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { useTab } from "@/lib/param";
import { useHuntSuggestions, useIndicators, useIntelReports } from "@/lib/queries";
import { AddDialog } from "./intel/AddDialog";
import { DigestDialog } from "./intel/DigestDialog";
import { lastPull } from "./intel/feeds";
import { Indicators } from "./intel/Indicators";
import { Leads } from "./intel/Leads";
import { Reports } from "./intel/Reports";

const TABS = ["indicators", "leads", "reports"] as const;
/** `intel.list` rows asked for; at this many the list is the newest slice. */
const LIMIT = 200;

export function Intel() {
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useTab(TABS);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  const indicators = useIndicators(params.get("type") ?? "", params.get("q") ?? "", LIMIT);
  const leads = useHuntSuggestions(50);
  const reports = useIntelReports(params.get("rq") ?? "");
  const [adding, setAdding] = useState(false);
  const [reading, setReading] = useState(false);
  useCommand("intel.add", () => setAdding(true), tab === "indicators");

  const feeds = indicators.data?.feeds ?? [];
  const budget = indicators.data?.budget;
  const failing = feeds.filter((f) => f.enabled && f.last_error).length;
  const pulled = lastPull(feeds);
  // What CTI read today against its daily budget (RFC 0029), warn at the cap.
  const used = (label: string, value: number, cap: number, show: (n: number) => string): StripFact => ({
    key: label,
    label,
    value: (
      <Meter
        value={value}
        max={cap}
        tone={(v) => (v >= cap ? "warn" : "crew")}
        label={`${label} against the daily budget`}
        format={(v) => `${show(v)}/${show(cap)}`}
        width={48}
      />
    ),
  });
  const setParam = (name: string, value: string | null, extra: Record<string, string | null> = {}) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      for (const [k, v] of Object.entries({ [name]: value, ...extra })) {
        if (v) out.set(k, v);
        else out.delete(k);
      }
      return out;
    });
  const rows = indicators.data?.rows ?? [];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Intel"
        strip={
          <Strip
            state={
              !feeds.length
                ? { tone: "idle", word: "No feeds" }
                : failing
                  ? { tone: "bad", word: "Feed failing" }
                  : { tone: "good", word: "Feeds ok" }
            }
            loading={indicators.isPending}
            error={loadError(indicators)}
            onRetry={() => void indicators.refetch()}
            asOf={staleSince(indicators) ?? staleSince(leads) ?? staleSince(reports)}
            facts={[
              {
                label: "feeds failing",
                value: indicators.data ? failing : null,
                tone: failing ? "bad" : undefined,
                to: "/connections?tab=intel",
                tip: "The sources, on Connections",
              },
              { label: "last pull", value: pulled ? age(pulled, now) : null, tip: pulled ? stamp(pulled) : undefined },
              ...(budget
                ? [
                    used("reports today", budget.reports_today, budget.reports_per_day, num),
                    used("tokens today", budget.tokens_today, budget.tokens_per_day, compact),
                  ]
                : []),
            ]}
          />
        }
      />
      <Tabs
        id="intel"
        label="Intel"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "indicators", label: "Indicators", count: indicators.data ? indicators.data.total : null },
          { value: "leads", label: "Leads", count: leads.data ? leads.data.suggestions.length : null },
          { value: "reports", label: "Reports", count: reports.data ? reports.data.rows.length : null },
        ]}
      />
      <TabPanel id="intel" value={tab}>
        <Card>
          {tab === "indicators" ? (
            <Indicators
              rows={rows}
              capped={rows.length >= LIMIT}
              loading={indicators.isPending}
              error={loadError(indicators)}
              onRetry={() => void indicators.refetch()}
              onAdd={() => setAdding(true)}
            />
          ) : tab === "leads" ? (
            <Leads
              leads={leads.data?.suggestions ?? []}
              loading={leads.isPending}
              error={loadError(leads)}
              onRetry={() => void leads.refetch()}
            />
          ) : (
            <Reports
              reports={reports.data?.rows ?? []}
              loading={reports.isPending}
              fetching={reports.isFetching}
              error={loadError(reports)}
              onRetry={() => void reports.refetch()}
              onRead={() => setReading(true)}
            />
          )}
        </Card>
      </TabPanel>
      {adding ? <AddDialog onClose={() => setAdding(false)} /> : null}
      {reading ? (
        <DigestDialog
          onClose={() => setReading(false)}
          onRead={(uid) => {
            setReading(false);
            setParam("report", uid, { tab: "reports", rq: null });
          }}
        />
      ) : null}
    </div>
  );
}
