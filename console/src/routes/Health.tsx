/**
 * Health: is shoc itself working, and what does it cost? The strip draws the
 * pipeline as stages, each a name and a status square linking its owner (its
 * number in the tip, so a stage keeps its size from loading to loaded); the
 * worker is two facts, its queue and its overdue schedules. A failed stage
 * reads bad and says what failed ("Crew down"), a late one or any listed
 * problem "Degraded" (a bad problem reads bad), and a
 * stage query that failed "Can't tell" with Retry. The tabs are paths
 * (`/health`, `/health/crew`, `/health/jobs`, `/health/spend`), so old links
 * to `/health/jobs` keep working. Problems lists only the platform's own:
 * worker, model, spend and store. The store's facts open in `?store=1`.
 *
 * Capabilities used: health.status, ops.alerts, llm.show, health.jobs,
 * health.cost, source.list and health.sources (the Sources stage reads what
 * Sources reads), playbook.runs and action.list (the Playbooks and Notify
 * stages); on the Crew tab stream.tail and health.audit.
 */
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { closeParams } from "@/lib/popup";
import { Card } from "@/components/ui/card";
import { TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Steps, type Step } from "@/components/ui/steps";
import { Strip, type StripFact } from "@/components/ui/strip";
import { useCommand, useTabKeys } from "@/lib/commands";
import { ROLES } from "@/lib/crew";
import { useAlerts, useFailedJobs } from "@/lib/queries";
import { Crew } from "./health/Crew";
import { Jobs } from "./health/Jobs";
import { groupJobs, WINDOWS, type Days } from "./health/model";
import { Problems, StoreDialog } from "./health/Problems";
import { usePipeline } from "./health/pipeline";
import { Spend } from "./health/Spend";

const TABS = ["problems", "crew", "jobs", "spend"] as const;
type Tab = (typeof TABS)[number];

export function Health() {
  const location = useLocation();
  const { pathname } = location;
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const asked = pathname.split("/")[2] ?? "";
  const tab: Tab = (TABS as readonly string[]).includes(asked) ? (asked as Tab) : "problems";
  const daysParam = params.get("days") ?? "1";
  const days: Days = WINDOWS.some((w) => w.value === daysParam) ? (daysParam as Days) : "1";

  const { health, stages, state, overdue, queries, problems } = usePipeline();
  const alerts = useAlerts();
  const jobs = useFailedJobs(Number(days));

  const go = (next: Tab, search = "", replace = false) =>
    navigate(`${next === "problems" ? "/health" : `/health/${next}`}${search}`, { replace });
  useTabKeys(TABS.length, (i) => go(TABS[i]!));
  // A tab a Problems row opened goes back to Problems on Escape, as every row's page does.
  useCommand("shell.escape", () => navigate(-1), Boolean((location.state as { back?: string } | null)?.back));

  const h = health.data;
  const groups = groupJobs(jobs.data?.failed ?? [], overdue);
  // The worker is not a stage of the pipeline: its queue and its schedule are facts beside it.
  const facts: StripFact[] = [
    { label: "queued", value: h?.jobs.pending, to: "/health/jobs" },
    {
      label: "overdue",
      value: h ? overdue.length : undefined,
      tone: overdue.length ? "bad" : undefined,
      to: "/health/jobs",
    },
  ];
  // A stage query that failed leaves its square hollow, so the strip cannot say "Healthy".
  const unknown = queries.find((q) => q.isLoadingError);
  // A failed refresh keeps the last answer on screen, with the time of the oldest.
  const stale = queries.filter((q) => q.isRefetchError);
  const asOf = stale.length ? new Date(Math.min(...stale.map((q) => q.dataUpdatedAt))).toISOString() : null;
  const openStore = () =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.set("store", "1");
      return out;
    });
  const pick = (step: Step) => {
    const to = stages.find((s) => s.key === step.key)?.to;
    if (to) navigate(to);
    else openStore();
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Health"
        strip={
          <Strip
            state={state}
            facts={facts}
            loading={queries.some((q) => q.isPending)}
            error={unknown?.error}
            onRetry={() => void Promise.all(queries.filter((q) => q.isError).map((q) => q.refetch()))}
            asOf={asOf}
            vizWide
            viz={<Steps variant="stage" label="Pipeline" steps={stages} onPick={pick} />}
          />
        }
      />
      <Tabs
        id="health"
        label="Health"
        value={tab}
        onChange={(next) => go(next, next === "jobs" && days !== "1" ? `?days=${days}` : "")}
        tabs={[
          { value: "problems", label: "Problems", count: health.data && alerts.data ? problems.length : null },
          { value: "crew", label: "Crew", count: ROLES.length },
          { value: "jobs", label: "Jobs", count: health.data && jobs.data ? groups.length : null },
          { value: "spend", label: "Spend" },
        ]}
      />
      <TabPanel id="health" value={tab}>
        <Card>
          {tab === "problems" ? (
            <Problems
              rows={problems}
              onStore={openStore}
              loading={health.isPending || alerts.isPending}
              error={health.isLoadingError ? health.error : alerts.isLoadingError ? alerts.error : undefined}
              onRetry={() => void Promise.all([health.refetch(), alerts.refetch()])}
            />
          ) : tab === "crew" ? (
            <Crew />
          ) : tab === "jobs" ? (
            <Jobs
              groups={groups}
              days={days}
              onDays={(d) => go("jobs", d === "1" ? "" : `?days=${d}`, true)}
              loading={jobs.isPending || health.isPending}
              error={jobs.isLoadingError ? jobs.error : health.isLoadingError ? health.error : undefined}
              onRetry={() => void Promise.all([jobs.refetch(), health.refetch()])}
            />
          ) : (
            <Spend />
          )}
        </Card>
      </TabPanel>
      {params.get("store") && h ? (
        <StoreDialog
          health={h}
          onClose={() => closeParams(["store"], navigate)}
        />
      ) : null}
    </div>
  );
}
