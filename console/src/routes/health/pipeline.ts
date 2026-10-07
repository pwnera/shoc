/**
 * The pipeline's stages and its one state word, read by Health's strip and by
 * the top bar's pill, so the shell signal can never disagree with its home.
 * A source's word is Connections' (a push source with no recent push is
 * not late), so the kernel's own `ok` flag is not read here.
 *
 * Capabilities used: health.status, ops.alerts, llm.show, source.list,
 * health.sources, playbook.runs and action.list; presence adds a model failure
 * the live stream saw first.
 */
import type { Step } from "@/components/ui/steps";
import { age, num } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePresence } from "@/lib/presence";
import { useActionLog, useAlerts, useHealth, useLlm, useRuns } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import { useSourceState } from "../connections/state";
import { problemsOf, type Problem } from "./model";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const DIALECT: Record<string, string> = {
  postgres: "Postgres",
  databricks: "Databricks",
  snowflake: "Snowflake",
  redshift: "Redshift",
  bigquery: "BigQuery",
};
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/* `to` is the stage's owner (the store's own facts open on Health instead); `down` is the state word when it alone failed. */
export type Stage = Step & { to?: string; down?: string };
export type PipelineState = { tone: "good" | "warn" | "bad"; word: string };

/** A bad Problems row's state word, by its component. */
const DOWN: Record<Problem["component"], string> = { worker: "Jobs failing", model: "Crew down", spend: "Over budget", store: "Down" };

export function usePipeline() {
  const health = useHealth();
  const alerts = useAlerts();
  const llm = useLlm();
  const runs = useRuns({ limit: 200 });
  const delivery = useSourceState();
  const actions = useActionLog();
  const presence = usePresence();
  const now = useNow();

  const h = health.data;
  const modelDown = presence.down || (alerts.data?.alerts ?? []).some((a) => a.kind === "llm.failing");
  const within = (iso: string | null | undefined, ms: number) => Boolean(iso && now - Date.parse(iso) < ms);
  // A stage the queries cannot tell about reads "todo" (a hollow square), never good.
  const known = (q: { data?: unknown }, state: () => Step["state"]): Step["state"] => (q.data ? state() : "todo");
  const words = delivery.configured.map((row) => ({ source: row.source, word: delivery.state(row) }));
  const troubled = words.filter((w) => w.word === "failing" || w.word === "late");
  const failingSources = troubled.filter((w) => w.word === "failing").length;
  const failedRuns = (runs.data?.runs ?? []).filter(
    (r) => r.state === "failed" && within(r.finished_at ?? r.updated_at ?? r.started_at, DAY),
  );
  const failedPages = (actions.data?.rows ?? []).filter((a) => a.type === "notify.page" && a.state === "failed" && within(a.created_at, DAY));
  const overdue = h?.jobs.overdue_schedules ?? [];
  const stages: Stage[] = [
    {
      key: "sources",
      label: "Sources",
      to: "/connections",
      state: known(
        { data: delivery.list.data && delivery.health.data },
        () => (failingSources ? "failed" : troubled.length ? "waiting" : "done"),
      ),
      down: plural(failingSources, "Source failing", "Sources failing"),
      tip: troubled.map((w) => `${sourceName(w.source)} ${w.word}`).join(", ") || undefined,
    },
    {
      key: "ingest",
      label: "Ingest",
      to: "/explore",
      state: known(health, () => (within(h?.store.latest_event, HOUR) ? "done" : "waiting")),
      tip: h?.store.latest_event ? `last event ${age(h.store.latest_event, now)} ago` : undefined,
    },
    {
      key: "store",
      label: "Store",
      state: known(health, () => (h?.store.ok ? "done" : "failed")),
      tip: h ? `${num(h.store.event_count)} events · ${DIALECT[h.store.dialect] ?? h.store.dialect}` : undefined,
    },
    {
      key: "detect",
      label: "Detect",
      to: "/detection?state=failing",
      state: known(health, () => (h && h.rules.failing > 0 ? "failed" : "done")),
      down: plural(h?.rules.failing ?? 0, "Rule failing", "Rules failing"),
      tip: h?.rules.failing ? `${num(h.rules.failing)} rules failing` : undefined,
    },
    {
      key: "crew",
      label: "Crew",
      to: "/health/crew",
      // Down comes from Ops and presence, not llm.show: a failing llm.show still shows a model that is down.
      state: modelDown ? "failed" : alerts.data ? "done" : "todo",
      down: "Crew down",
      tip: llm.data ? llm.data.model || "no model" : undefined,
    },
    {
      key: "playbooks",
      label: "Playbooks",
      to: "/response?tab=playbooks&run=failed",
      state: known(runs, () => (failedRuns.length ? "failed" : "done")),
      down: plural(failedRuns.length, "Playbook failed", "Playbooks failed"),
      tip: failedRuns.length ? `${num(failedRuns.length)} runs failed in 24h` : undefined,
    },
    {
      key: "notify",
      label: "Notify",
      to: "/response?tab=pages",
      state: known(actions, () => (failedPages.length ? "failed" : "done")),
      down: plural(failedPages.length, "Page failed", "Pages failed"),
      tip: failedPages.length ? `${num(failedPages.length)} pages failed in 24h` : undefined,
    },
  ];
  const queries = [health, alerts, runs, actions, delivery.list, delivery.health];
  // The Problems tab's rows: the state word answers for the worst of them, so it never says Healthy over a listed problem.
  const problems = problemsOf(alerts.data?.alerts ?? [], h);
  const down = [
    ...new Set([
      ...stages.filter((s) => s.state === "failed").map((s) => s.down ?? "Failing"),
      ...(overdue.length ? ["Worker stalled"] : []),
      ...problems.filter((p) => p.tone === "bad" && !p.key.startsWith("overdue:")).map((p) => DOWN[p.component]),
    ]),
  ];
  // Undefined until health.status and ops.alerts answer; a stage query that failed leaves its square hollow, never "Healthy".
  const state: PipelineState | undefined = !h || alerts.isPending
    ? undefined
    : !h.store.ok
      ? { tone: "bad", word: "Down" }
      : down.length
        ? { tone: "bad", word: down.length === 1 ? down[0]! : "Failing" }
        : stages.some((s) => s.state === "waiting") || problems.length
          ? { tone: "warn", word: "Degraded" }
          : { tone: "good", word: "Healthy" };
  return { health, stages, state, overdue, queries, problems };
}
