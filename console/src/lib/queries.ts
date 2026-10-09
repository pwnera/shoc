/**
 * One hook per capability the console uses. The shell's own reads live in
 * `reads.ts` and are re-exported here, so the main chunk carries only those.
 *
 * Keeping them together makes the console's whole dependency on shoc readable
 * in one place, and makes it obvious when a screen wants something the API
 * does not offer yet, which is a signal to add a capability rather than a
 * workaround.
 *
 * Hooks of actions whose result is worth a number raise their own toast, so a
 * long run still reports after the reader moved on; the same hooks, and every
 * act a screen fires and forgets, raise their own failure toast (`failed`). Acts behind a confirm or a form leave the error to
 * it, shown in place. A screen's own `toastError` on the same error is dropped.
 */
import {
  keepPreviousData,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { call, callData } from "./api";
import { FOLLOWED, LIVE, ruleHealthQuery, type ActionPage } from "./reads";
import { toast, toastError, go } from "./toast";
import { clock, count, num, percent } from "./format";
import { DISPOSITIONS, verdictLabel } from "./labels";
import type {
  CredentialList,
  CredentialState,
  Action,
  AuditRow,
  BacklogItem,
  Case,
  CaseHistoryRow,
  CaseRecord,
  Disposition,
  ApiToken,
  Issued,
  SsoSettings,
  User,
  CostReport,
  Digest,
  DetectRun,
  DetectionWork,
  Exposure,
  ExposureAnswer,
  FailedJob,
  Finding,
  FindingRecord,
  GraphEdge,
  GraphNode,
  GraphRefreshResult,
  HuntBacklogItem,
  HuntDaily,
  HuntMetrics,
  HuntPack,
  HuntReadiness,
  HuntRun,
  HuntSuggestion,
  IdentityResolution,
  IndicatorAddResult,
  IntelList,
  IntelReport,
  InvestigateResult,
  LlmConfig,
  Lookup,
  MappingTest,
  Memory,
  Metrics,
  OnboardResult,
  EventGroup,
  EventRow,
  OcsfEvent,
  OwnIdentity,
  PlaybookRun,
  PlaybookRunDetail,
  PolicyView,
  QueuedReport,
  PlatformLookupAnswer,
  PlatformLookupDef,
  Posture,
  OpenspaceMessage,
  ReportEnvelope,
  RuleTestResult,
  AssetIdentity,
  Backtest,
  SnapshotRow,
  SourceHealth,
  SourceQuality,
  SlackView,
  SourceSample,
  StreamTail,
  Summary,
  Suppression,
  SyncResult,
  TimelineResult,
} from "@/types";

export type { Answer } from "@/types";
export { useStreamStatus } from "./stream";
export {
  ACTION_CAP,
  CASE_CAP,
  useActionLog,
  useAlerts,
  useCapabilities,
  useCaseActions,
  useCaseLog,
  useEvents,
  useHealth,
  useMe,
  usePlaybooks,
  useProposals,
  useRules,
  useSearch,
  useSourceList,
  useUnacknowledged,
} from "./reads";

/**
 * A warehouse query or a large answer: kept five minutes and never refetched
 * because the window regained focus, so an alt-tab costs no warehouse time.
 * The stream and the mutations still invalidate it.
 */
const HEAVY = { staleTime: 5 * 60_000, refetchOnWindowFocus: false } as const;

/* -- health ---------------------------------------------------------------- */

/** `health.sources`, refetched with `source.list` every 30s while the tab is visible. */
export function useSourceHealth() {
  return useQuery({
    queryKey: ["health.sources"],
    queryFn: () => callData<{ sources: SourceHealth[]; ok: boolean }>("health.sources"),
    ...LIVE,
  });
}

export function useRuleHealth(only: "all" | "noisy" | "silent" | "failing" = "all") {
  return useQuery(ruleHealthQuery(only));
}

export function useCost(days = 30) {
  return useQuery({
    queryKey: ["health.cost", days],
    queryFn: () => callData<CostReport>("health.cost", { days }),
    ...HEAVY,
  });
}

export function useFailedJobs(days = 7) {
  return useQuery({
    queryKey: ["health.jobs", days],
    queryFn: () => callData<{ failed: FailedJob[] }>("health.jobs", { days }),
    ...LIVE,
  });
}

export function useLlm() {
  return useQuery({
    queryKey: ["llm.show"],
    queryFn: () => callData<LlmConfig>("llm.show"),
    staleTime: 5 * 60_000,
  });
}

/** The head of the stream: `latest_seq` of `stream.tail {limit: 1}`. */
async function head(signal?: AbortSignal): Promise<number> {
  return (await callData<StreamTail>("stream.tail", { limit: 1 }, signal)).latest_seq;
}

/**
 * The crew's recent messages for Health › Crew: the last 2,000 events'
 * openspace messages, read forward in pages of 500 (four at most).
 */
export function useCrewWindow(enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["stream.tail", "crew"],
    queryFn: async ({ signal }) => {
      let since = Math.max(0, (await head(signal)) - 2000);
      const events: StreamTail["events"] = [];
      for (let page = 0; page < 4; page++) {
        const tail = await callData<StreamTail>(
          "stream.tail",
          { types: ["openspace.message"], since_seq: since, limit: 500 },
          signal,
        );
        events.push(...tail.events);
        if (tail.events.length < 500 || tail.last_seq <= since) break;
        since = tail.last_seq;
      }
      return { events };
    },
    ...HEAVY,
  });
}

/* -- cases ----------------------------------------------------------------- */

export function useCase(caseUid: string | undefined) {
  return useQuery({
    enabled: Boolean(caseUid),
    queryKey: ["case.get", caseUid],
    queryFn: () => callData<CaseRecord>("case.get", { case_uid: caseUid }),
    ...FOLLOWED,
  });
}

/** The case's events from `timeline.build`: cited ones and their neighbours, 500 at most. */
export function useTimeline(caseUid: string | undefined) {
  return useQuery({
    enabled: Boolean(caseUid),
    queryKey: ["timeline.build", caseUid],
    queryFn: () => callData<TimelineResult>("timeline.build", { case_uid: caseUid, limit: 500 }),
    ...FOLLOWED,
  });
}

/** Pull one entity's events into the case's timeline; they join it marked "extended". */
export function useExtendTimeline() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: { case_uid: string; value: string }) => callData<TimelineResult>("timeline.extend", input),
    onSuccess: (more, input) =>
      client.setQueryData<TimelineResult>(["timeline.build", input.case_uid], (was) => {
        if (!was) return was;
        const known = new Set(was.events.map((e) => e.event_uid));
        const added = more.events.filter((e) => !known.has(e.event_uid)).map((e) => ({ ...e, extended: true }));
        const events = [...was.events, ...added].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
        return { ...was, events, count: events.length };
      }),
  });
}

/** Earlier cases that share an entity with this one: the case graph's ghost nodes. */
export function useCaseHistory(caseUid: string | undefined) {
  return useQuery({
    enabled: Boolean(caseUid),
    queryKey: ["case.history", caseUid],
    queryFn: () =>
      callData<{ case_uid: string; cases: CaseHistoryRow[]; count: number }>("case.history", {
        case_uid: caseUid,
        limit: 20,
      }),
    staleTime: 5 * 60_000,
  });
}

/* -- findings and events ---------------------------------------------------- */

/**
 * `finding.list`. With `live`, a new finding refreshes it after a quiet spell
 * (a counter that must stay current, as the handover's); without, it waits
 * for the reader, as the Findings list does behind its "N new" pill.
 */
export function useFindings(
  input: {
    since?: string;
    severity?: string;
    status?: string;
    rule_id?: string;
    entity?: string;
    limit?: number;
  } = {},
  opts: { live?: boolean } = {},
) {
  const asked = Object.fromEntries(Object.entries({ since: "-7d", ...input }).filter(([, v]) => v !== "" && v !== undefined));
  return useQuery({
    queryKey: ["finding.list", asked],
    queryFn: () => callData<{ rows: Finding[]; count: number }>("finding.list", asked),
    placeholderData: keepPreviousData,
    ...(opts.live ? { meta: { live: true }, ...FOLLOWED } : {}),
  });
}

/** The explorer's search. `enabled` keeps it off until the operator asks. */
export function useEventSearch(input: Record<string, unknown>, enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["events.query", "explore", input],
    // The signal: a superseded run (a new query, a pivot, a brush) is cancelled, not left spending warehouse time.
    queryFn: ({ signal }) =>
      callData<{ rows: EventRow[]; count: number; truncated: boolean; sql: string }>(
        "events.query",
        input,
        signal,
      ),
    // "Load more" keeps the rows on screen while the longer page arrives.
    placeholderData: keepPreviousData,
    ...HEAVY,
  });
}

/**
 * `events.summarize`, 300 buckets unless asked otherwise: the kernel keeps 50
 * by default, oldest first, which drops a short window's newest minutes.
 */
export function useEventSummary(input: Record<string, unknown>, enabled = true) {
  const asked = { limit: 300, ...input };
  return useQuery({
    enabled,
    queryKey: ["events.summarize", asked],
    queryFn: ({ signal }) => callData<Summary>("events.summarize", asked, signal),
    placeholderData: keepPreviousData,
    ...HEAVY,
  });
}

/** The five commonest values of each pinned field over the whole match, not the loaded rows. */
export function useFieldTops(query: { q?: string; since?: string; until?: string }, fields: string[], enabled = true) {
  return useQueries({
    queries: fields.map((by) => {
      const asked = { ...query, by, limit: 5 };
      return {
        enabled,
        queryKey: ["events.summarize", asked],
        queryFn: ({ signal }: { signal: AbortSignal }) => callData<Summary>("events.summarize", asked, signal),
        placeholderData: keepPreviousData,
        ...HEAVY,
      };
    }),
  });
}


/* -- playbooks -------------------------------------------------------------- */

/** Runs, newest first: one case's, or the last `limit` across cases. */
export function useRuns({ caseUid = "", limit = 50 }: { caseUid?: string; limit?: number } = {}) {
  return useQuery({
    queryKey: ["playbook.runs", caseUid || "all", limit],
    queryFn: () =>
      callData<{ runs: PlaybookRun[]; count: number }>("playbook.runs", {
        limit,
        ...(caseUid ? { case_uid: caseUid } : {}),
      }),
    ...FOLLOWED,
  });
}

export function useIndicators(type = "", contains = "", limit = 50) {
  return useQuery({
    queryKey: ["intel.list", type, contains, limit],
    queryFn: () =>
      callData<IntelList>("intel.list", {
        limit,
        ...(type ? { type } : {}),
        ...(contains ? { contains } : {}),
      }),
    placeholderData: keepPreviousData,
  });
}

export function useHuntSuggestions(limit = 50) {
  return useQuery({
    queryKey: ["hunt.suggest", limit],
    queryFn: () => callData<{ suggestions: HuntSuggestion[]; count: number }>("hunt.suggest", { limit }),
  });
}

/** `policy.show`, as its envelope (callers read `.data.data`); `lib/policy.ts` `ruleOf` reads one action's rule. */
export function usePolicy(enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["policy.show"],
    queryFn: () => call<PolicyView>("policy.show"),
    staleTime: 5 * 60_000,
  });
}

/* -- things the operator does --------------------------------------------- */

/**
 * A write that refreshes `keys` when it lands. `failed` raises a critical
 * toast from the hook, so a failure is reported even after the screen that
 * asked has unmounted; leave it out where a confirm or a form shows the error.
 */
function useRefreshing<TInput, TOutput>(
  capability: string,
  keys: string[],
  build: (input: TInput) => Record<string, unknown>,
  after?: (data: TOutput, input: TInput, client: QueryClient) => void,
  opts: { failed?: string | ((input: TInput) => string); gcTime?: number } = {},
) {
  const client = useQueryClient();
  const { failed } = opts;
  return useMutation({
    mutationFn: (input: TInput) => call<TOutput>(capability, build(input)),
    onSuccess: (envelope, input) => {
      for (const key of keys) void client.invalidateQueries({ queryKey: [key] });
      after?.(envelope.data, input, client);
    },
    ...(failed ? { onError: (error: Error, input: TInput) => toastError(error, typeof failed === "string" ? failed : failed(input)) } : {}),
    ...(opts.gcTime !== undefined ? { gcTime: opts.gcTime } : {}),
  });
}

type Decision = string | { action_uid: string; note?: string };
const decision = (input: Decision) => (typeof input === "string" ? { action_uid: input } : { ...input });

/**
 * Approve or reject, optimistically: the action leaves every action list at
 * once and comes back, with a critical toast, if the call fails. ApprovalCard
 * is the only call site of both.
 */
function useDecide(capability: "action.approve" | "action.reject", what: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: Decision) => call<Action>(capability, decision(input)),
    onMutate: async (input) => {
      const uid = decision(input).action_uid;
      const next = capability === "action.approve" ? "approved" : "rejected";
      await client.cancelQueries({ queryKey: ["action.list"] });
      const before = client.getQueriesData<ActionPage>({ queryKey: ["action.list"] });
      for (const [key, page] of before) {
        if (!page) continue;
        // The proposals list loses the row; every other list shows its new state.
        const proposals = (key[1] as { state?: string } | undefined)?.state === "proposed";
        const rows = proposals
          ? page.rows.filter((a) => a.action_uid !== uid)
          : page.rows.map((a) => (a.action_uid === uid ? { ...a, state: next as Action["state"] } : a));
        client.setQueryData<ActionPage>(key, { ...page, rows });
      }
      return { before };
    },
    onError: (error, _input, context) => {
      for (const [key, page] of context?.before ?? []) client.setQueryData(key, page);
      toastError(error, what);
    },
    onSettled: () => {
      for (const key of ["action.list", "playbook.runs", "case.get"]) void client.invalidateQueries({ queryKey: [key] });
    },
  });
}

export const useApprove = () => useDecide("action.approve", "Approve failed");
export const useRejectAction = () => useDecide("action.reject", "Reject failed");

/** Undo one action, with an optional note. ActionDialog calls it, one mutation per open dialog. */
export function useUndo() {
  return useRefreshing<Decision, { action_uid: string; ok: boolean; detail: string; state: string }>(
    "action.undo",
    ["action.list", "case.get", "playbook.runs"],
    decision,
  );
}

/** Run an approved action no run picked up, with its own dry-run flag: the capability defaults to true. */
export function useRunAction() {
  return useRefreshing<
    Pick<Action, "action_uid" | "dry_run">,
    { action_uid: string; ok: boolean; detail: string; state: string; dry_run: boolean }
  >(
    "action.run",
    ["action.list", "case.get", "playbook.runs"],
    (a) => ({ action_uid: a.action_uid, dry_run: a.dry_run }),
    undefined,
    { failed: "Run failed" },
  );
}

export function useResumeRun() {
  return useRefreshing<string, PlaybookRun>(
    "playbook.resume",
    ["playbook.runs", "action.list", "case.get", "playbook.get"],
    (run_uid) => ({ run_uid }),
    undefined,
    { failed: "Resume failed" },
  );
}

/** Send the crew back to a case now.
 *
 * This is a convenience, not the mechanism: the worker sends the crew at every
 * open case that has something new, and nothing here waits for the button. The
 * refreshed keys include `action.list` because a run can propose containment,
 * and the policy may have already run it.
 */
export function useInvestigate() {
  return useRefreshing<string, InvestigateResult>(
    "case.investigate",
    ["case.get", "case.list", "action.list", "timeline.build"],
    (case_uid) => ({ case_uid }),
    (d) =>
      toast({
        tone: "crew",
        group: d.case_uid,
        text: [
          count(d.rounds, "round"),
          `${verdictLabel(d.verdict).word} ${percent(d.confidence)}`,
          `${num(d.tokens)} tokens`,
          d.stopped_because ? `stopped: ${d.stopped_because.replace(/_/g, " ")}` : "",
        ]
          .filter(Boolean)
          .join(" · "),
      }),
    { failed: "Re-investigate failed" },
  );
}

export function useSetCaseState() {
  return useRefreshing<{ case_uid: string; state: string; note?: string }, Case>(
    "case.set_state",
    ["case.get", "case.list"],
    (input) => ({ ...input }),
    undefined,
    { failed: (input) => (input.state === "closed" ? "Close failed" : "Move failed") },
  );
}

/** Say a person has seen that the case closed without its containment (D152). */
export function useAcknowledgeCase() {
  return useRefreshing<{ case_uid: string }, { case_uid: string; acknowledged_at: string }>(
    "case.acknowledge",
    ["case.get", "case.list"],
    (input) => ({ ...input }),
    () => toast({ tone: "ok", text: "Acknowledged" }),
    { failed: "Acknowledge failed" },
  );
}

/**
 * Close as a person, with a disposition and a reason the crew learns from.
 * `remember_days` matters only for benign_expected and false_positive: the
 * kernel writes a memory for those two, and reads 0 as 90.
 */
export function useCloseCase() {
  return useRefreshing<
    { case_uid: string; disposition: Disposition; reason: string; remember_days?: number },
    { case_uid: string; state: string; verdict: string; rejected_actions: number; memory_id?: string }
  >("case.close", ["case.get", "case.list", "action.list", "memory.search"], (input) => ({ ...input }), (d, input) =>
    toast({
      tone: "ok",
      text: [
        `Closed as ${DISPOSITIONS[input.disposition]}`,
        d.rejected_actions ? count(d.rejected_actions, "action rejected", "actions rejected") : "",
      ]
        .filter(Boolean)
        .join(" · "),
      ...(d.memory_id
        ? { action: { label: "Memory", to: "/memory?tab=corrections", run: () => go("/memory?tab=corrections") } }
        : {}),
    }),
  );
}

/** Steer the crew: a person's message into the case, to the whole crew or one role. */
export function useInject() {
  return useRefreshing<{ case_uid: string; body: string; to?: string }, OpenspaceMessage>(
    "openspace.post",
    ["case.get"],
    (input) => ({ ...input, kind: "inject" }),
  );
}

export function useRunHunt() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: { value: string; days: number; field?: string }) =>
      call<{ matches: number; events: OcsfEvent[]; findings: string[]; hunt_uid: string }>(
        "hunt.run",
        input,
      ),
    onSuccess: () => client.invalidateQueries({ queryKey: ["finding.list"] }),
  });
}

export function useTestRule() {
  return useMutation({
    mutationFn: (input: { rule_id: string; since: string }) => call<RuleTestResult>("rule.test", input),
  });
}

/** Replay a rule over past days, against the ceiling a merge must stay under. */
export function useBacktest() {
  return useMutation({
    mutationFn: (input: { rule_id: string; days: number }) => callData<Backtest>("rule.backtest", input),
  });
}

/** One run with its steps, fetched when RunDialog opens; no polling (the stream refreshes it). */
export function usePlaybookRun(runUid: string | undefined) {
  return useQuery({
    enabled: Boolean(runUid),
    queryKey: ["playbook.get", runUid],
    queryFn: () => callData<PlaybookRunDetail>("playbook.get", { run_uid: runUid }),
  });
}

/* -- intel ---------------------------------------------------------------- */

export function useIntelReports(contains = "") {
  return useQuery({
    queryKey: ["intel.reports", contains],
    queryFn: () =>
      callData<{ rows: IntelReport[]; count: number }>("intel.reports", {
        limit: 100,
        ...(contains ? { contains } : {}),
      }),
    placeholderData: keepPreviousData,
  });
}

/** What the CTI role queued and did not read (RFC 0029): every unread state, newest change first. */
export function useIntelQueue(contains = "") {
  return useQuery({
    queryKey: ["intel.reports", "queue", contains],
    queryFn: () =>
      callData<{ rows: QueuedReport[]; count: number }>("intel.reports", {
        state: "queue",
        limit: 100,
        ...(contains ? { contains } : {}),
      }),
    placeholderData: keepPreviousData,
  });
}

/** Look a value up across the intel sources; Refresh, which asks every source again, updates the same cache. */
export function useLookup() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: { value: string; type?: string; refresh?: boolean }) =>
      call<Lookup>("intel.lookup", { ...input }),
    onSuccess: (envelope, input) => client.setQueryData(["intel.lookup", input.value, input.type ?? ""], envelope.data),
  });
}

/** EntityDialog's Intel view: the one home of `intel.lookup`. */
export function useLookupOf(value: string, type = "", enabled = true) {
  return useQuery({
    enabled: enabled && Boolean(value),
    queryKey: ["intel.lookup", value, type],
    queryFn: () => callData<Lookup>("intel.lookup", { value, ...(type ? { type } : {}) }),
    staleTime: 10 * 60_000,
  });
}

export function useDigest() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: { url?: string; text?: string; title?: string; retro_hunt?: boolean }) =>
      call<Digest>("intel.digest", { ...input }),
    onSuccess: (envelope) => {
      void client.invalidateQueries({ queryKey: ["intel.reports"] });
      void client.invalidateQueries({ queryKey: ["intel.list"] });
      const d = envelope.data;
      toast({ tone: "crew", text: `Read · ${count(d.indicators_stored, "indicator")} · ${num(d.tokens)} tokens` });
    },
    onError: (error) => toastError(error, "Reading failed"),
  });
}

export function useRefreshIntel() {
  return useRefreshing<
    string | undefined,
    { indicators_new: number; expired_removed: number }
  >(
    "intel.refresh",
    ["intel.list", "intel.reports", "finding.list"],
    (feed) => ({ ...(feed ? { feed } : {}) }),
    (d) => toast({ tone: "ok", text: `${num(d.indicators_new)} new · ${num(d.expired_removed)} expired` }),
    { failed: "Refresh failed" },
  );
}

/**
 * Switch a feed on or off. `intel.configure` overwrites the parser and the
 * settings with defaults when they are left out, which would wipe a list or
 * RSS feed's URL, so both are required and go back as `intel.list` gave them.
 */
export function useConfigureFeed() {
  return useRefreshing<
    { feed: string; enabled: boolean; parser: string; settings: Record<string, unknown> },
    { feed: string; enabled: boolean; parser: string }
  >("intel.configure", ["intel.list"], (input) => ({ ...input }));
}

/** Add a report source: a preset by name, or an RSS or Atom feed by URL. */
export function useAddReportSource() {
  return useRefreshing<
    { preset: string } | { feed: string; parser: "rss"; settings: { url: string } },
    { feed: string; enabled: boolean; parser: string }
  >("intel.configure", ["intel.list"], (input) => ({ ...input }));
}

/**
 * Save, disable or remove a lookup source that needs an account. The key is
 * write-only: left out, the stored one stays. Every save sends `per_day`, and
 * `commercial_licence` where the free tier is non-commercial, since the
 * settings are replaced whole.
 */
export function useConfigureLookup() {
  return useRefreshing<
    {
      lookup: string;
      secret?: Record<string, string>;
      settings?: { per_day: number; commercial_licence?: boolean };
      enabled?: boolean;
      remove?: boolean;
    },
    { feed: string; enabled: boolean; removed: boolean }
  >("intel.configure", ["intel.list"], (input) => ({ ...input }));
}

/** Add indicators by value; the kernel types each one and says which it refused. */
export function useAddIndicators() {
  return useRefreshing<
    {
      values: string[];
      severity?: string;
      confidence?: number;
      days?: number;
      description?: string;
      retro_hunt?: boolean;
    },
    IndicatorAddResult
  >("intel.add", ["intel.list", "finding.list"], (input) => ({ ...input }), (d) =>
    toast({
      tone: d.rejected.length ? "neutral" : "ok",
      text: [
        `${num(d.stored_new)} added`,
        d.rejected.length ? `${num(d.rejected.length)} refused` : "",
        d.retro_hunt?.hits ? `${num(d.retro_hunt.hits)} seen in our logs` : "",
      ]
        .filter(Boolean)
        .join(" · "),
    }),
    { failed: "Adding failed" },
  );
}

/**
 * Remove indicators by value, a source's indicators, or everything a report
 * stored. The kernel matches the three with OR, so send one of them only:
 * `{values, source}` withdraws the whole feed (a kernel follow-up).
 */
export function useRemoveIntel() {
  return useRefreshing<{ values?: string[]; source?: string; report_uid?: string }, { removed: number }>(
    "intel.remove",
    ["intel.list", "intel.reports"],
    (input) => ({ ...input }),
    undefined,
    { failed: "Remove failed" },
  );
}

/* -- posture and the graph ------------------------------------------------ */

/** The latest survey: a read, so no window (a read ignores `days` once a survey exists). */
export function usePosture() {
  return useQuery({
    queryKey: ["posture.get", {}],
    queryFn: () => call<Posture>("posture.get", {}),
    staleTime: 60_000,
  });
}

/** Survey again now, over the survey's own window. */
export function useResurvey() {
  return useRefreshing<number | undefined, Posture>(
    "posture.get",
    ["posture.get", "surface.list", "snapshot.list"],
    (days) => ({ refresh: true, days: days ?? 30 }),
    (d) => toast({ tone: "ok", text: d.taken_at ? `Surveyed · ${clock(d.taken_at)}` : "Survey started" }),
    { failed: "Survey failed" },
  );
}

/** Entities as the events describe them, 500 at most (the kernel's cap). */
export function useSurface({ kind = "", exposedOnly = false, limit = 500 }: { kind?: string; exposedOnly?: boolean; limit?: number } = {}) {
  return useQuery({
    queryKey: ["surface.list", kind, exposedOnly, limit],
    queryFn: () =>
      callData<{ entities: Exposure[]; count: number; caveat: string }>("surface.list", {
        limit,
        exposed_only: exposedOnly,
        ...(kind ? { kind } : {}),
      }),
    ...HEAVY,
  });
}

/** What each source's own API lists, 1,000 at most (the kernel's cap). */
export function useSnapshots(input: { kind?: string; source?: string; limit?: number } = {}) {
  const asked = { limit: 1000, ...input };
  return useQuery({
    queryKey: ["snapshot.list", asked],
    queryFn: () => callData<{ rows: SnapshotRow[]; count: number; truncated: boolean }>("snapshot.list", asked),
    ...HEAVY,
  });
}

/** EntityDialog's overview: one entity's exposure. */
export function useExposureOf(entity: string, enabled = true) {
  return useQuery({
    enabled: enabled && Boolean(entity),
    queryKey: ["posture.exposure", entity],
    queryFn: () => callData<ExposureAnswer & { present?: boolean }>("posture.exposure", { entity }),
  });
}

export function useAssetIdentify(target: string, enabled = true) {
  return useQuery({
    enabled: enabled && Boolean(target),
    queryKey: ["asset.identify", target],
    queryFn: () => callData<AssetIdentity>("asset.identify", { target }),
  });
}

export function useIdentityResolve(identity: string, enabled = true) {
  return useQuery({
    enabled: enabled && Boolean(identity),
    queryKey: ["identity.resolve", identity],
    queryFn: () => callData<IdentityResolution>("identity.resolve", { identity }),
  });
}

export function usePlatformLookups(enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["platform.lookups"],
    queryFn: () => callData<{ lookups: PlatformLookupDef[] }>("platform.lookups", {}),
    staleTime: 10 * 60_000,
  });
}

/** Ask a connected platform for live state; audited, because it calls the vendor. */
export function usePlatformLookup() {
  return useMutation({
    mutationFn: (input: { lookup: string; params: Record<string, unknown> }) =>
      callData<PlatformLookupAnswer>("platform.lookup", input),
  });
}

export function useNeighbours(node: string, hops = 2) {
  return useQuery({
    enabled: Boolean(node),
    queryKey: ["graph.neighbours", node, hops],
    queryFn: () =>
      callData<{ root: string; nodes: GraphNode[]; edges: GraphEdge[]; hops: number }>(
        "graph.neighbours",
        { node, hops },
      ),
  });
}

export function useRefreshGraph() {
  return useRefreshing<number, GraphRefreshResult>(
    "graph.refresh",
    ["graph.neighbours", "hunt.suggest"],
    (days) => ({ days }),
    (d) =>
      toast({
        tone: "ok",
        text: `${num(d.nodes)} nodes · ${num(d.edges)} edges${d.truncated ? ` · from the newest ${num(d.limit)} events` : ""}`,
      }),
    { failed: "Rebuild failed" },
  );
}

/* -- hunting -------------------------------------------------------------- */

export function useHuntResults(packId = "", days = 7, limit = 200) {
  return useQuery({
    queryKey: ["hunt.results", packId, days, limit],
    queryFn: () =>
      callData<{
        runs: HuntRun[];
        count: number;
        metrics: HuntMetrics;
        readiness: HuntReadiness[];
      }>("hunt.results", {
        days,
        limit,
        ...(packId ? { pack_id: packId } : {}),
      }),
    ...HEAVY,
  });
}

export function useHuntBacklog(state = "open") {
  return useQuery({
    queryKey: ["hunt.backlog", state],
    queryFn: () => callData<{ items: HuntBacklogItem[]; count: number }>("hunt.backlog", { state }),
  });
}

/** A person ends a hunt item or reopens it, as `useDecideBacklog` does a detection one. */
export function useDecideHunt() {
  return useRefreshing<{ item_uid: string; state: string; reason: string }, { item_uid: string; state: string }>(
    "hunt.decide",
    ["hunt.backlog"],
    (input) => ({ ...input }),
  );
}

/**
 * Run every due pack, as the schedule does (`limit: 0`). The toast comes from
 * here, not from the button, so a run of several minutes still reports after
 * the reader leaves Hunts.
 */
export function useRunDailyHunts() {
  return useRefreshing<void, HuntDaily>(
    "hunt.daily",
    ["hunt.results", "hunt.backlog", "finding.list"],
    () => ({ limit: 0 }),
    (d) => {
      const suspicious = d.outcomes.suspicious ?? 0;
      toast({
        tone: suspicious ? "crew" : "ok",
        text: [count(d.chosen.length, "pack"), suspicious ? `${suspicious} suspicious` : "", `${num(d.tokens)} tokens`]
          .filter(Boolean)
          .join(" · "),
        action: { label: "Open", to: "/hunts", run: () => go("/hunts") },
      });
    },
    { failed: "Hunts failed" },
  );
}

export function useRunPack() {
  return useRefreshing<string, HuntPack>(
    "hunt.pack",
    ["hunt.results", "finding.list"],
    (pack_id) => ({ pack_id }),
    undefined,
    { failed: "Pack run failed" },
  );
}

/** A report's suggested hunt into the Hunts backlog: the one home of `hunt.propose`. */
export function useProposeHunt() {
  return useRefreshing<
    { title: string; hypothesis?: string; why_now?: string; attack?: string[]; would_confirm?: string; data_needed?: string },
    { item_uid: string }
  >("hunt.propose", ["hunt.backlog"], (input) => ({ ...input }), () =>
    toast({
      tone: "ok",
      text: "Proposed",
      action: { label: "Backlog", to: "/hunts?tab=backlog", run: () => go("/hunts?tab=backlog") },
    }),
    { failed: "Propose failed" },
  );
}

/* -- detection engineering ------------------------------------------------ */

export function useDetectionBacklog(state = "open") {
  return useQuery({
    queryKey: ["detection.backlog", state],
    queryFn: () =>
      callData<{
        items: BacklogItem[];
        count: number;
        by_intake: Record<string, number>;
        not_observable: number;
      }>("detection.backlog", { run: false, state, limit: 200 }),
  });
}

export function useDecideBacklog() {
  return useRefreshing<{ item_uid: string; state: string; reason: string }, { item_uid: string; state: string }>(
    "detection.decide",
    ["detection.backlog"],
    (input) => ({ ...input }),
  );
}

export type MergeCapability = "detection.merge" | "hunt.merge" | "playbook.merge";

/** What a merge changes; a dry run changes nothing, and refreshing then costs a read. */
const MERGED: Record<MergeCapability, string[]> = {
  "detection.merge": ["rule.list", "detection.backlog", "health.rules", "playbook.list"],
  "hunt.merge": ["hunt.results", "hunt.backlog"],
  "playbook.merge": ["playbook.list", "rule.list"],
};

/** Check (`dry_run`) or merge a rule, a hunt pack or a playbook; the dialog shows a refusal itself. */
export function useMerge(capability: MergeCapability) {
  return useRefreshing<Record<string, unknown>, Record<string, unknown>>(
    capability,
    [],
    (input) => input,
    (_data, input, client) => {
      if (!input.dry_run) for (const key of MERGED[capability]) void client.invalidateQueries({ queryKey: [key] });
    },
  );
}

/** Let the Detection Engineer work the backlog now. */
export function useWorkBacklog() {
  return useRefreshing<number | void, DetectionWork>(
    "detection.work",
    ["detection.backlog", "rule.list", "health.rules", "suppression.list"],
    (limit) => ({ limit: typeof limit === "number" ? limit : 5 }),
    (d) =>
      toast({
        tone: "crew",
        text: [
          count(d.worked, "item"),
          ...Object.entries(d.outcomes ?? {}).map(([what, n]) => `${n} ${what.replace(/_/g, " ")}`),
          `${num(d.tokens)} tokens`,
        ].join(" · "),
      }),
    { failed: "Work failed" },
  );
}

/** Revert a rule the Detection Engineer merged, with the reason a person gives. */
export function useRevertRule() {
  return useRefreshing<{ rule_id: string; reason: string }, { rule_id: string; state: string }>(
    "detection.revert",
    ["rule.list", "detection.backlog", "health.rules", "playbook.list"],
    (input) => ({ ...input }),
  );
}

/** Take back a hunt pack merged here, with the reason a person gives. */
export function useRevertPack() {
  return useRefreshing<{ pack_id: string; reason: string }, { pack_id: string; state: string }>(
    "hunt.revert",
    ["hunt.results", "hunt.backlog"],
    (input) => ({ ...input }),
  );
}

/** Take back a playbook merged here; its rules go back to the playbooks that had them. */
export function useRevertPlaybook() {
  return useRefreshing<
    { playbook_id: string; reason: string },
    { playbook_id: string; state: string; answered_by: Record<string, string>; cancelled_runs: number }
  >("playbook.revert", ["playbook.list", "rule.list", "playbook.runs"], (input) => ({ ...input }));
}

export function useSuppressions(ruleId = "") {
  return useQuery({
    queryKey: ["suppression.list", ruleId],
    queryFn: () =>
      callData<{
        suppressions: Suppression[];
        count: number;
        expired: number;
      }>("suppression.list", ruleId ? { rule_id: ruleId } : {}),
  });
}

/** Run every rule (or one) now; the toast reads "182 rules · 3 findings · 1 case". */
export function useRunDetections() {
  return useRefreshing<{ rule_id?: string; lookback?: string }, DetectRun>(
    "detect.run",
    ["finding.list", "case.list", "health.rules"],
    (input) => ({ ...input }),
    (d) => {
      const errors = Object.keys(d.errors ?? {}).length;
      const first = d.cases_opened[0];
      toast({
        tone: errors ? "critical" : "ok",
        text: [
          count(d.rules_run, "rule"),
          count(d.findings_new, "finding"),
          d.cases_opened.length ? count(d.cases_opened.length, "case") : "",
          errors ? count(errors, "error") : "",
        ]
          .filter(Boolean)
          .join(" · "),
        ...(first ? { action: { label: "Open case", to: `/cases/${first}`, run: () => go(`/cases/${first}`) } } : {}),
      });
    },
    { failed: "Run failed" },
  );
}

export function useStartPlaybook() {
  return useRefreshing<{ playbook_id: string; case_uid: string; dry_run: boolean }, PlaybookRun>(
    "playbook.run",
    ["playbook.runs", "action.list", "case.get"],
    (input) => ({ ...input }),
    undefined,
    { failed: "Playbook failed" },
  );
}

export function useProposeAction() {
  return useRefreshing<
    { action: string; params: Record<string, unknown>; case_uid: string; rationale: string },
    Action
  >("action.propose", ["action.list", "case.get"], (input) => ({ ...input }), undefined, { failed: "Propose failed" });
}

export function useNotifySlack() {
  return useMutation({
    mutationFn: (case_uid: string) =>
      call<{ case_uid: string; posted: boolean; channel: string }>("slack.notify", { case_uid }),
    onSuccess: ({ data }) =>
      toast({ tone: data.posted ? "ok" : "neutral", text: data.posted ? `Posted to ${data.channel}` : "Slack isn't set up" }),
  });
}

/* -- findings ------------------------------------------------------------- */

export function useFinding(findingUid: string | undefined) {
  return useQuery({
    enabled: Boolean(findingUid),
    queryKey: ["finding.get", findingUid],
    queryFn: () => callData<FindingRecord>("finding.get", { finding_uid: findingUid }),
  });
}

export function useSetFindingStatus() {
  return useRefreshing<{ finding_uid: string; status: string; note?: string }, Finding>(
    "finding.set_status",
    ["finding.list", "finding.get", "case.get"],
    (input) => ({ ...input }),
  );
}

/* -- response credentials (RSP-4, RFC 0025) -------------------------------- */

export function useCredentials() {
  return useQuery({
    queryKey: ["credential.list"],
    queryFn: () => callData<CredentialList>("credential.list"),
  });
}

/** A blank secret field keeps the stored one; settings replace what is saved. Save makes one read with it. */
export function useConfigureCredential() {
  return useRefreshing<
    { provider: string; settings: Record<string, unknown>; secret: Record<string, string> },
    CredentialState
  >("credential.configure", ["credential.list", "source.list", "platform.lookups"], (input) => ({ ...input, verify: true }));
}

/** One read with a stored credential, as Save makes; the Response review shows what came back. */
export function useCheckCredential() {
  return useRefreshing<string, CredentialState>("credential.check", ["credential.list"], (provider) => ({ provider }), undefined, {
    failed: "Check failed",
  });
}

export function useRemoveCredential() {
  return useRefreshing<string, CredentialState>(
    "credential.remove",
    ["credential.list", "source.list", "platform.lookups"],
    (provider) => ({ provider }),
  );
}

/* -- the services shoc itself uses: its model and Slack ------------------- */

export function useSlack() {
  return useQuery({ queryKey: ["slack.show"], queryFn: () => callData<SlackView>("slack.show") });
}

/** Empty fields keep what is stored, the secrets included. */
export function useConfigureSlack() {
  return useRefreshing<
    { bot_token?: string; signing_secret?: string; channel?: string; approvers?: Record<string, string> },
    { channel: string; approvers: string[]; configured: boolean }
  >("slack.configure", ["slack.show"], (input) => ({ ...input }));
}

/** Empty fields keep what is stored, the key included. */
export function useConfigureLlm() {
  return useRefreshing<
    { provider?: string; model?: string; model_cheap?: string; base_url?: string; api_key?: string },
    LlmConfig
  >("llm.configure", ["llm.show", "health.status"], (input) => ({ ...input }));
}

/* -- sources -------------------------------------------------------------- */

export function useConnectSource() {
  // Reconfiguring sends the source's cadence and state back, which
  // source.configure would otherwise reset to its defaults.
  return useRefreshing<
    {
      source: string;
      settings: Record<string, unknown>;
      secret: Record<string, string>;
      interval_seconds?: number;
      enabled?: boolean;
      /** Check the credential against the vendor before saying it is saved. */
      verify?: boolean;
    },
    { source: string; verified: boolean | null; verify_error: string | null }
  >("source.configure", ["source.list", "health.sources"], (input) => ({ ...input }));
}

/** The key is returned when it is made or rotated, and never again. */
export function usePushKey() {
  return useRefreshing<
    { source: string; rotate?: boolean },
    { source: string; push_key: string; signature_header: string; timestamp_header: string }
  >("source.push_key", ["source.list"], (input) => ({ ...input }));
}

export function useRemoveSource() {
  return useRefreshing<string, { source: string }>(
    "source.remove",
    ["source.list", "health.sources"],
    (source) => ({ source }),
  );
}

/** Pull one source now. Each row calls its own hook, so one pull never disables another. */
export function useSyncSource() {
  return useRefreshing<string, SyncResult>(
    "source.sync",
    ["source.list", "health.sources", "health.status"],
    (source) => ({ source }),
    (d) =>
      d.error
        ? toast({ tone: "critical", text: `${d.source}: ${d.error}` })
        : toast({ tone: "ok", text: `${d.source} · ${num(d.fetched)} fetched · ${num(d.loaded)} loaded · ${count(d.pages, "page")}` }),
    { failed: (source) => `Pull ${source}` },
  );
}

export function useToggleSource() {
  // Settings go back as they are: source.configure replaces them, and a pause
  // must not wipe the org URL or region.
  return useRefreshing<
    {
      source: string;
      enabled: boolean;
      interval_seconds: number;
      settings: Record<string, unknown>;
    },
    { source: string; enabled: boolean }
  >("source.configure", ["source.list", "health.sources"], (input) => ({ ...input }));
}

/** One page from the vendor, as it arrives and as it maps. */
export function useSampleSource() {
  return useMutation({
    mutationFn: (source: string) => callData<SourceSample>("source.sample", { source, limit: 20 }),
  });
}

/** What the source's mapping can and cannot support, on demand. */
export function useMappingTest() {
  return useMutation({
    mutationFn: (source: string) => callData<MappingTest>("mapping.test", { source }),
  });
}

/** Let the Integrator work every source (or one). */
export function useOnboardSources() {
  return useRefreshing<string | void, OnboardResult>(
    "source.onboard",
    ["source.list", "health.sources"],
    (source) => (typeof source === "string" && source ? { source } : {}),
    (d) =>
      toast({
        tone: d.waiting.length ? "crew" : "ok",
        text: [
          `${num(d.onboarded.length)} onboarded`,
          d.waiting.length ? `${num(d.waiting.length)} waiting` : "",
          d.dark.length ? `${num(d.dark.length)} dark` : "",
          d.repaired.length ? `${num(d.repaired.length)} repaired` : "",
        ]
          .filter(Boolean)
          .join(" · "),
      }),
    { failed: "Onboarding" },
  );
}

export function useQuality(days = 30) {
  return useQuery({
    queryKey: ["health.quality", days],
    queryFn: () =>
      callData<{ sources: SourceQuality[]; worst: SourceQuality; notes: string[]; ok: boolean }>(
        "health.quality",
        { days },
      ),
    ...HEAVY,
  });
}

export type Volume = {
  /** Events in the last 24 hours. */
  day: number;
  /** The 30-day daily average. */
  usual: number;
  /** Silent: nothing in 24h while it usually delivers; low: under a quarter of the usual. */
  mark: "silent" | "low" | null;
};

/** Under five events a day, a day with nothing can be a weekend rather than a silence: such a product reads low. */
const SILENT_FLOOR = 5;

/** Pure, for the tests: each product's last day against its 30-day average, on Connections, Health and Coverage alike. */
export function volumes(
  month: { product: string; events: number }[] | undefined,
  days: number,
  today: EventGroup[] | undefined,
): Record<string, Volume> {
  const out: Record<string, Volume> = {};
  const lastDay = new Map((today ?? []).map((g) => [g.key, g.count]));
  for (const { product, events } of month ?? []) {
    const usual = events / Math.max(1, days);
    const day = lastDay.get(product) ?? 0;
    const mark =
      usual > 0 && day === 0 ? (usual < SILENT_FLOOR ? "low" : "silent") : usual > 0 && day < usual / 4 ? "low" : null;
    out[product] = { day, usual, mark };
  }
  return out;
}

/**
 * Volume per product, 24 hours against the 30-day average: the cached
 * `health.cost` volume Health and Coverage hold, and one `events.summarize`.
 */
export function useProductVolume() {
  const cost = useCost(30);
  const today = useEventSummary({ by: "metadata_product", since: "-24h", limit: 300 });
  return {
    data:
      cost.data && today.data
        ? volumes(cost.data.volume.by_product, cost.data.volume.days, today.data.rows)
        : undefined,
    isPending: cost.isPending || today.isPending,
    isError: cost.isError || today.isError,
    error: cost.error ?? today.error,
    refetch: () => Promise.all([cost.refetch(), today.refetch()]),
  };
}

/* -- shoc's own footprint (RFC 0021) -------------------------------------- */

export function useOwn() {
  return useQuery({
    queryKey: ["own.list"],
    queryFn: () => callData<{ rows: OwnIdentity[]; count: number }>("own.list"),
  });
}

export function useAddOwn() {
  return useRefreshing<
    { kind: OwnIdentity["kind"]; value: string; source?: string; note?: string; scope?: string },
    { kind: string; value: string }
  >("own.add", ["own.list"], (input) => ({ ...input }));
}

export function useRemoveOwn() {
  return useRefreshing<{ kind: string; value: string }, { kind: string; value: string }>(
    "own.remove",
    ["own.list"],
    (input) => ({ ...input }),
  );
}

/* -- measurement and the audit log ---------------------------------------- */

export function useMetrics(days = 30) {
  return useQuery({
    queryKey: ["metrics.get", days],
    queryFn: () => call<Metrics>("metrics.get", { days }),
    ...HEAVY,
  });
}

/** The audit log, 200 rows by default; `head` verifies the chain from that hash. */
export function useAudit(input: number | { limit?: number; head?: string } = {}) {
  const asked = typeof input === "number" ? { limit: input } : { limit: 200, ...input };
  return useQuery({
    queryKey: ["health.audit", asked],
    queryFn: () =>
      callData<{
        chain_ok: boolean;
        rows_verified: number;
        detail: string;
        head: string;
        recent: AuditRow[];
      }>("health.audit", asked),
    ...HEAVY,
  });
}

/** Build a weekly or board report once, on demand, for the print view. Never `shift` or `exception`. */
export function useReportExport() {
  return useMutation({
    mutationFn: (kind: "weekly" | "exec") => callData<ReportEnvelope>("report.get", { kind }),
  });
}

/** Send a report to Slack now (admin token). */
export function useSendReport() {
  return useMutation({
    mutationFn: (kind: "weekly" | "exec") =>
      callData<{ report_uid: string; held: number; slack_error: string }>("report.send", { kind }),
    onSuccess: (d) =>
      d.slack_error
        ? toast({ tone: "critical", text: `Not sent: ${d.slack_error}` })
        : toast({ tone: "ok", text: d.held ? `Sent · ${num(d.held)} held` : "Sent" }),
  });
}

/* -- memory --------------------------------------------------------------- */

/** Memory, 100 rows at most: the kernel's cap, so counts read "100+" there. */
export const MEMORY_CAP = 100;

export function useMemory(query = "") {
  return useQuery({
    queryKey: ["memory.search", query],
    queryFn: () =>
      callData<{ rows: Memory[]; count: number }>("memory.search", { query, limit: MEMORY_CAP }),
    placeholderData: keepPreviousData,
  });
}

/** Remember a fact; the kernel takes an empty subject when none is given. */
export function useAddFact() {
  return useRefreshing<
    { body: string; subject?: string; kind: string; expires_at?: string },
    { memory_id: string }
  >("memory.add_fact", ["memory.search"], (input) => ({ ...input }), undefined, { failed: "Saving failed" });
}

/* -- the registry describing itself --------------------------------------- */

/* -- tokens (RFC 0019) ---------------------------------------------------- */

export function useTokens() {
  return useQuery({
    queryKey: ["token.list"],
    queryFn: () => callData<{ tokens: ApiToken[] }>("token.list"),
  });
}

/** The new token comes back once; `gcTime: 0` drops it from the mutation cache as soon as nothing shows it. */
export function useCreateToken() {
  return useRefreshing<
    { who: string; role: string; expires_days: number },
    { token_id: string; token: string; who: string }
  >("token.create", ["token.list"], (input) => ({ ...input }), undefined, { gcTime: 0 });
}

export function useRevokeToken() {
  return useRefreshing<string, { token_id: string }>("token.revoke", ["token.list"], (id) => ({
    token_id: id,
  }));
}

/* -- people and SSO (RFC 0028) -------------------------------------------- */

/** Everyone, disabled people included: the People tab shows their state. */
export function useUsers() {
  return useQuery({
    queryKey: ["user.list"],
    queryFn: () => callData<{ users: User[] }>("user.list", { disabled: true }),
  });
}

/** The link comes back once, like a token: `gcTime: 0` drops it from the mutation cache. */
export function useInviteUser() {
  return useRefreshing<{ email: string; role: string }, Issued>("user.invite", ["user.list"], (input) => ({ ...input }), undefined, {
    gcTime: 0,
  });
}

export function useResetUser() {
  return useRefreshing<string, Issued>("user.reset", ["user.list"], (email) => ({ email }), undefined, { gcTime: 0 });
}

/** A role change or disabling; fields left out stay as they are. */
export function useUpdateUser() {
  return useRefreshing<{ email: string; role?: string; disabled?: boolean }, User>(
    "user.update",
    ["user.list", "user.me", "token.list"],
    (input) => ({ ...input }),
  );
}

export function useSso(enabled = true) {
  return useQuery({ enabled, queryKey: ["sso.show"], queryFn: () => callData<SsoSettings>("sso.show") });
}

export function useConfigureSso() {
  return useRefreshing<
    { issuer?: string; client_id?: string; client_secret?: string; domains?: string[]; clear?: boolean },
    SsoSettings
  >("sso.configure", ["sso.show", "user.list"], (input) => ({ ...input }));
}
