/**
 * The reads the shell itself draws from: the shared logs (one cache key each,
 * so the shell, Overview and the screens never fetch the same rows twice),
 * health, ops alerts and sources for the rail and the top bar, the palette's
 * lists and search, cited events, the capability list and who is signed in. Apart from
 * `queries.ts`, which re-exports every one, so the main chunk carries these
 * and each screen's chunk the rest.
 */
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { call, callData } from "./api";
import { streamState } from "./stream";
import type {
  Action,
  Answer,
  CapabilityDoc,
  Case,
  ConfiguredSource,
  EventRow,
  Me,
  Onboarding,
  OpsAlert,
  Playbook,
  Rule,
  RuleHealth,
  SourceNeeds,
  SystemHealth,
} from "@/types";

/** Refetched every 30s while the tab is visible. */
export const LIVE = { refetchInterval: 30_000 } as const;

/**
 * What the event stream already refreshes (`lib/live.ts` invalidates these keys
 * on every event that changes them): polled, and refetched when the tab comes
 * back, only while the stream is not live.
 */
export const FOLLOWED = {
  refetchInterval: () => (streamState() === "live" ? false : 30_000),
  refetchOnWindowFocus: () => streamState() !== "live",
} as const;

/** Polled every 30s on the screens that show it live (Sources, Health), else only while the stream is down. */
const ON_SOURCES = {
  refetchInterval: () =>
    /^\/(sources|health)(\/|$)/.test(window.location.pathname) || streamState() !== "live" ? 30_000 : false,
} as const;

/** Actions, 500 at most: the kernel's cap, so counts read "500+" there (section 7 item 15). */
export const ACTION_CAP = 500;

/** Cases, 200 at most: the kernel's cap (section 7 item 16). */
export const CASE_CAP = 200;

export type ActionPage = { rows: Action[]; count: number; waiting_for_approval: number };

function useActions(input: { state?: string; case_uid?: string; limit?: number } = {}, enabled = true) {
  const asked = { limit: ACTION_CAP, ...input };
  return useQuery({
    enabled,
    queryKey: ["action.list", asked],
    queryFn: () => callData<ActionPage>("action.list", asked),
    ...FOLLOWED,
  });
}

/** Every action, newest first: Overview's handover, Response, the expired approvals. */
export const useActionLog = () => useActions();

/** Proposals only, so none hides behind 500 newer actions: the inbox's approvals. */
export const useProposals = () => useActions({ state: "proposed" });

/** One case's actions; nothing until the uid is known, never the whole log. */
export const useCaseActions = (caseUid: string | undefined) => useActions({ case_uid: caseUid ?? "" }, Boolean(caseUid));

function useCases(input: { state?: string; verdict?: string; limit?: number; unacknowledged?: boolean } = {}) {
  const asked = { limit: CASE_CAP, ...input };
  return useQuery({
    queryKey: ["case.list", asked],
    queryFn: () => callData<{ rows: Case[]; count: number }>("case.list", asked),
    ...FOLLOWED,
  });
}

/** Every case the kernel returns: one cache key for the shell, Overview, Cases and Measurement. */
export const useCaseLog = () => useCases();

/** Closed cases whose containment never ran and nobody acknowledged, so none hides behind newer cases (D152). */
export const useUnacknowledged = () => useCases({ unacknowledged: true });

export function useHealth() {
  return useQuery({
    queryKey: ["health.status"],
    queryFn: () => callData<SystemHealth>("health.status"),
    ...LIVE,
  });
}

export function useAlerts() {
  return useQuery({
    queryKey: ["ops.alerts"],
    queryFn: () => callData<{ alerts: OpsAlert[]; count: number }>("ops.alerts"),
    ...FOLLOWED,
  });
}

export function useEvents(uids: string[], raw = false) {
  return useQuery({
    enabled: uids.length > 0,
    queryKey: ["events.query", uids, raw],
    // A stored event never changes.
    staleTime: Infinity,
    queryFn: () =>
      callData<{ rows: EventRow[]; count: number }>("events.query", {
        event_uids: uids,
        limit: uids.length,
        include_raw: raw,
      }),
  });
}

/** `search`, which never calls a model: the palette's query, from three characters. */
export function useSearch(input: { question: string; since?: string; limit?: number }) {
  const asked = { question: input.question.trim(), since: input.since ?? "-7d", limit: input.limit ?? 8 };
  return useQuery({
    enabled: asked.question.length >= 3,
    queryKey: ["search", asked],
    queryFn: ({ signal }) => call<Answer>("search", asked, signal),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

const RULES = {
  queryKey: ["rule.list"],
  queryFn: () => callData<{ rules: Rule[]; count: number }>("rule.list"),
  staleTime: 5 * 60_000,
};

export function useRules() {
  return useQuery(RULES);
}

/** Each rule's health: seconds of warehouse time, so kept five minutes; the stream invalidates it on findings. */
export const ruleHealthQuery = (only: "all" | "noisy" | "silent" | "failing") => ({
  queryKey: ["health.rules", only],
  queryFn: () => callData<{ rules: RuleHealth[]; ok: boolean }>("health.rules", { only }),
  staleTime: 5 * 60_000,
  refetchOnWindowFocus: false,
});

/**
 * Mounted once by the shell: the rule list (Postgres, cheap) loads while the
 * browser is idle after the first screen. Rule health reads the event store,
 * so it warms only on intent (`useWarmRuleHealth`), never on every load.
 */
export function usePrefetchRules(): void {
  const client = useQueryClient();
  useEffect(() => {
    const warm = () => void client.prefetchQuery(RULES);
    if (typeof requestIdleCallback === "function") {
      const handle = requestIdleCallback(warm, { timeout: 10_000 });
      return () => cancelIdleCallback(handle);
    }
    const timer = setTimeout(warm, 3000);
    return () => clearTimeout(timer);
  }, [client]);
}

/** Warm each rule's health when the reader points at a screen that shows it (Detection, Coverage, Response). */
export function useWarmRuleHealth(): () => void {
  const client = useQueryClient();
  return () => void client.prefetchQuery(ruleHealthQuery("all"));
}

export function usePlaybooks(caseUid = "", enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["playbook.list", caseUid],
    queryFn: () =>
      callData<{
        playbooks: Playbook[];
        count: number;
        near_misses: { playbook_id: string; title: string; misses: string[] }[];
      }>("playbook.list", caseUid ? { case_uid: caseUid } : {}),
    staleTime: 5 * 60_000,
  });
}

/** `source.list`, refetched every 30s with `health.sources` while Sources or Health shows it. */
export function useSourceList() {
  return useQuery({
    queryKey: ["source.list"],
    queryFn: () =>
      callData<{
        configured: ConfiguredSource[];
        available: string[];
        push_only: string[];
        also_push: string[];
        mappings: string[];
        needs: Record<string, SourceNeeds>;
        onboarding: Onboarding[];
      }>("source.list"),
    ...ON_SOURCES,
  });
}

/** Who this browser is signed in as (the account menu); a role change shows on the next read. */
export function useMe(enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["user.me"],
    queryFn: () => callData<Me>("user.me"),
    staleTime: 60_000,
  });
}

export function useCapabilities(area = "", principal = "", enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["capability.list", area, principal],
    queryFn: () =>
      callData<{ capabilities: CapabilityDoc[]; count: number; version: string }>(
        "capability.list",
        { ...(area ? { area } : {}), ...(principal ? { principal } : {}) },
      ),
    staleTime: 10 * 60_000,
  });
}
