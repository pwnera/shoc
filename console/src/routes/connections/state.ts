/**
 * What every part of Connections reads: the connected list and its health, how
 * each source delivers and the one word for its state, each product's volume
 * mark, the quality rows silent and then worst first, and the dialog's views.
 */
import type { StatusTone } from "@/components/ui/status";
import type { Step } from "@/components/ui/steps";
import { num } from "@/lib/format";
import {
  useAlerts,
  useProductVolume,
  useQuality,
  useSourceHealth,
  useSourceList,
} from "@/lib/queries";
import { deliveryState, modeOf, shownVolume, type ShownVolume } from "@/lib/sources";
import type { ConfiguredSource, Onboarding } from "@/types";

/* A product's views: its Logs side's, then its Response side's (`RESPONSE`). */
export const VIEWS = ["delivery", "settings", "onboarding", "footprint", "response", "credential", "grant"] as const;
export type View = (typeof VIEWS)[number];

/*
 * Each word `deliveryState` says and its tone, problems first, so the list
 * answers "is every source delivering" before any scroll.
 */
const TONE: Record<string, StatusTone> = {
  failing: "bad",
  late: "warn",
  "no credential": "warn",
  waiting: "idle",
  "no recent push": "idle",
  paused: "idle",
  delivering: "good",
};
const ORDER = Object.keys(TONE);

export function useSourceState() {
  const list = useSourceList();
  const health = useSourceHealth();
  const push = { only: list.data?.push_only ?? [], also: list.data?.also_push ?? [] };
  // Late is judged against the source's own cadence, which only health.sources knows.
  const late = new Set(
    (health.data?.sources ?? []).filter((row) => row.stale).map((row) => row.source),
  );
  // Ops' `source.failing` alert, by configured source: the row reads failing and its dialog shows the detail.
  const alerts = useAlerts();
  const failing = new Map(
    (alerts.data?.alerts ?? [])
      .filter((a) => a.kind === "source.failing")
      .map((a) => [a.subject, a.detail]),
  );
  const state = (row: ConfiguredSource) => deliveryState(row, push, late, failing.has(row.source));
  const stale = [list, health].filter((q) => q.isRefetchError);
  const configured = [...(list.data?.configured ?? [])].sort(
    (a, b) => ORDER.indexOf(state(a)) - ORDER.indexOf(state(b)) || a.source.localeCompare(b.source),
  );
  return {
    list,
    health,
    push,
    state,
    mode: (row: ConfiguredSource) => modeOf(row, push),
    alert: (row: ConfiguredSource) => failing.get(row.source),
    configured,
    // The words wait for Ops too: a source.failing alert still on its way must not read as delivering.
    pending: list.isPending || health.isPending || alerts.isPending,
    // Only a first load that failed is an error: a failed refresh keeps the rows, as of the older answer.
    error: list.isLoadingError ? list.error : health.isLoadingError ? health.error : undefined,
    asOf: stale.length
      ? new Date(Math.min(...stale.map((q) => q.dataUpdatedAt))).toISOString()
      : null,
  };
}

/** A connector or setting name in words: "google_workspace" → "google workspace". */
export const words = (name: string) => name.replace(/_/g, " ");

/** The status tone of a delivery word; anything unknown is idle. */
export const deliveryTone = (word: string): StatusTone => TONE[word] ?? "idle";

/** The worst of a product's delivery words, "no logs" when it has no source. */
export const worstDelivery = (words: string[]) =>
  [...words].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b))[0] ?? "no logs";

export const SCORE_MARKS = [
  { at: 0.5, label: "poor" },
  { at: 0.8, label: "good" },
];

/** "24h 0 · usual 1.2k/day". */
export function volumeText(v: ShownVolume): string {
  const usual =
    v.usual >= 1000
      ? `${(v.usual / 1000).toFixed(1).replace(/\.0$/, "")}k`
      : num(Math.round(v.usual * 10) / 10);
  return `24h ${num(v.day)} · usual ${usual}/day`;
}

/** Volume per product with the mark Sources shows (`shownVolume`): `of(product)`. */
export function useVolume() {
  const volume = useProductVolume();
  const model = useSourceState();
  const sources = model.configured.map((row) => ({ source: row.source, mode: model.mode(row) }));
  const of = (product: string) => {
    const v = volume.data?.[product];
    return v && shownVolume(product, v, sources);
  };
  return { ...volume, of };
}

/** A silent product first, where the strip's "silent" lands, then the lowest score. */
export function useQualityRows() {
  const quality = useQuality(30);
  const volume = useVolume();
  const silent = (product: string) => (volume.of(product)?.mark === "silent" ? 0 : 1);
  const rows = [...(quality.data?.sources ?? [])].sort(
    (a, b) => silent(a.product) - silent(b.product) || a.score - b.score,
  );
  return { quality, volume, rows };
}

const STEPS: Onboarding["step"][] = ["discover", "credentials", "map", "prove", "done"];

export function onboardingSteps(step: Onboarding["step"] | undefined): Step[] {
  const at = step ? STEPS.indexOf(step) : -1;
  return STEPS.map((s, i) => ({
    key: s,
    label: s,
    state: i < at || step === "done" ? "done" : i === at ? "current" : "todo",
  }));
}
