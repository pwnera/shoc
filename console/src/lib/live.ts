/**
 * The event stream, followed for as long as the console is open. It keeps the
 * screens fresh without polling: each event type refreshes exactly the queries
 * it changes (the table in `invalidations`), feeds the crew presence store, and
 * raises a toast for the few events worth interrupting someone who is looking.
 *
 * Capabilities used: stream.tail, and the SSE endpoint behind it.
 */
import { useEffect, useRef, useSyncExternalStore } from "react";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";
import { ApiError, callData, useSignedOut } from "./api";
import { deny, pause, subscribe, useStreamState, type StreamEvent } from "./stream";
import { bare } from "./entity";
import { actionLabel } from "./labels";
import { forgetUndo, go, toast, undoUntil, update, withParam } from "./toast";
import { left, shortId } from "./format";
import { notePresence, resetPresence, seedPresence } from "./presence";
import type { Action } from "@/types";

/**
 * A refresh after a quiet spell. `live` limits it to the queries that asked to
 * follow the stream (`meta: { live: true }`): the findings list on screen waits
 * behind its "N new" pill instead, while a counter elsewhere stays current.
 */
export type Later = { key: QueryKey; ms: number; live?: boolean };

/** What one event makes stale: refreshed at once, or after a quiet spell when events come in bursts. */
export function invalidations(event: StreamEvent): { now: QueryKey[]; later: Later[] } {
  const S = event.subject;
  const C = typeof event.payload.case_uid === "string" ? event.payload.case_uid : "";
  const onCase: QueryKey[] = C ? [["case.get", C]] : [];
  const [area, name] = event.type.split(".", 2);
  const type = event.type;

  if (area === "case")
    return {
      now: [["case.list"], ["case.get", S]],
      later: type === "case.updated" ? [{ key: ["timeline.build", S], ms: 5_000 }] : [],
    };
  if (type === "openspace.message") return { now: [["case.get", S]], later: [] };
  if (type === "action.proposed") return { now: [["action.list"], ...onCase], later: [] };
  if (area === "action") return { now: [["action.list"], ...onCase, ["playbook.runs"]], later: [] };
  if (area === "playbook") return { now: [["playbook.runs"], ["playbook.get", S], ["action.list"]], later: [] };
  if (type === "finding.new")
    return {
      now: [["health.status"], ["finding.get", S]],
      later: [
        { key: ["health.rules"], ms: 30_000 },
        { key: ["finding.list"], ms: 15_000, live: true },
      ],
    };
  if (type === "source.needs_credentials") return { now: [["source.list"], ["health.status"]], later: [] };
  if (area !== "health") return { now: [], later: [] };

  // health.<kind>.<what>
  switch (name) {
    case "source":
      return type === "health.source.quality"
        ? { now: [["health.quality"], ["ops.alerts"]], later: [] }
        : { now: [["health.sources"], ["ops.alerts"], ["health.status"]], later: [] };
    case "rule":
      return { now: [["health.rules"], ["ops.alerts"], ["health.status"]], later: [] };
    case "jobs":
      return { now: [["health.jobs"], ["ops.alerts"], ["health.status"]], later: [] };
    case "cost":
      return { now: [["ops.alerts"], ["health.cost"]], later: [] };
    case "action":
      return { now: [["ops.alerts"], ["action.list"]], later: [] };
    case "hunt":
      return { now: [["ops.alerts"], ["hunt.results"]], later: [] };
    case "audit":
      return { now: [["health.audit"], ["ops.alerts"]], later: [] };
    default:
      // llm, case, approval: the alert list is what changed.
      return { now: [["ops.alerts"]], later: [] };
  }
}

/** Where an event leads: toasts, time-bar marks and the crew pulse all link here. `?…` opens over the current screen. */
export function eventHref(event: StreamEvent): string {
  const S = encodeURIComponent(event.subject);
  const C = typeof event.payload.case_uid === "string" ? event.payload.case_uid : "";
  const type = event.type;
  if (type.startsWith("case.")) return `/cases/${S}`;
  if (type === "openspace.message") return `/cases/${S}?tab=discussion`;
  if (type === "action.proposed") return `?decide=${S}`;
  if (type.startsWith("action.")) return `?action=${S}`;
  if (type.startsWith("playbook.")) return C ? `/cases/${C}` : "/response?tab=playbooks";
  if (type === "finding.new") return `/findings/${S}`;
  if (type === "source.needs_credentials")
    return `/connections?source=${encodeURIComponent(event.subject.split(",")[0] ?? "")}&view=settings`;
  if (type === "health.source.quality") return `/connections?tab=quality&product=${S}`;
  if (type.startsWith("health.source.")) return `/connections?source=${S}`;
  if (type.startsWith("health.rule.")) return `/detection/rules/${S}`;
  if (type === "health.jobs.failed") return "/health/jobs";
  if (type === "health.llm.failing") return "/health/crew";
  if (type.startsWith("health.cost.")) return "/health/spend";
  if (type === "health.case.stalled") return `/cases/${S}`;
  if (type === "health.action.stuck") return `?action=${S}`;
  if (type === "health.hunt.gap") return `/hunts?pack=${S}`;
  if (type === "health.approval.waiting") return "/";
  if (type === "health.audit.broken") return "/access?tab=audit";
  if (type === "report.ready") return "/measurement";
  return "/";
}

/** A `?a=1&b=2` href merged into the screen the reader is on now; a path as it is. */
function resolve(href: string): string {
  if (!href.startsWith("?")) return href;
  const [first, ...rest] = [...new URLSearchParams(href.slice(1))];
  if (!first) return href;
  return withParam(first[0], first[1], Object.fromEntries(rest));
}

/** A toast button: a link for the toaster to render (`?…` is relative to the screen), and a click resolved when it happens. */
const button = (label: string, href: string) => ({ label, to: href, run: () => go(resolve(href)) });

/* -- findings that arrived while a list was on screen ----------------------- */

let fresh = 0;
const freshListeners = new Set<() => void>();
function setFresh(n: number) {
  fresh = n;
  for (const l of freshListeners) l();
}

/** New findings since the list was last refreshed, for its "N new" pill, and a reset for the pill's click. */
export function useNewFindings(): [number, () => void] {
  const n = useSyncExternalStore(
    (l) => (freshListeners.add(l), () => freshListeners.delete(l)),
    () => fresh,
  );
  return [n, () => setFresh(0)];
}

/* -- toasts ----------------------------------------------------------------- */

function cachedAction(client: QueryClient, uid: string): Action | undefined {
  for (const [, data] of client.getQueriesData<{ rows?: Action[] }>({ queryKey: ["action.list"] })) {
    const row = data?.rows?.find((a) => a.action_uid === uid);
    if (row) return row;
  }
  return undefined;
}

/** The toast table of section 3.5. `refreshed` settles once the event's queries refetched. */
export function announce(event: StreamEvent, client: QueryClient, refreshed: Promise<unknown>) {
  const p = event.payload;
  const S = event.subject;
  const C = typeof p.case_uid === "string" ? p.case_uid : "";
  const label = actionLabel(String(p.type ?? cachedAction(client, S)?.type ?? ""));
  const onCase = C ? { label: shortId(C), title: C, to: `/cases/${C}` } : undefined;
  const open = (href: string) => button("Open", href);
  const who = cachedAction(client, S)?.requested_by;
  const common = { at: event.created_at, ...(C ? { group: C } : {}), ...(who ? { who } : {}) };

  switch (event.type) {
    case "action.proposed": {
      if (p.state !== "proposed") return;
      const id = toast({
        ...common,
        tone: "crew",
        ...(onCase ? { subject: onCase } : {}),
        text: `${label} waits`,
        action: button("Review", `?decide=${encodeURIComponent(S)}`),
      });
      void refreshed.then(() => {
        const row = cachedAction(client, S);
        const due = left(row?.decide_by);
        update(id, { text: due ? `${label} waits · ${due}` : `${label} waits`, ...(row ? { who: row.requested_by } : {}) });
      });
      return;
    }
    case "action.executed": {
      if (!p.ok) {
        toast({ ...common, tone: "critical", ...(onCase ? { subject: onCase } : {}), text: `${label} failed`, action: open(`?action=${S}`) });
        return;
      }
      const undoable = Boolean(p.reversible) && !p.dry_run;
      const undo = `?action=${encodeURIComponent(S)}&do=undo`;
      const id = toast({
        ...common,
        tone: "ok",
        ...(onCase ? { subject: onCase } : {}),
        text: `${label} ${p.dry_run ? "planned" : "done"}`,
        merged: (n) => `${n} actions done`,
        ...(undoable ? { undo: S, action: button("Undo", undo) } : {}),
      });
      if (undoable)
        void refreshed.then(() => {
          const row = cachedAction(client, S);
          const ttl = Number(row?.params?.ttl_minutes ?? 0);
          const from = row?.executed_at ?? event.created_at;
          const until = ttl ? new Date(Date.parse(from) + ttl * 60_000).toISOString() : "";
          if (until) undoUntil(S, until);
          const rest = until ? left(until) : "";
          if (rest) update(id, { action: button(`Undo · ${rest}`, undo) });
        });
      return;
    }
    case "action.rolled_back":
      if (p.ok) forgetUndo(S);
      else
        toast({ ...common, tone: "critical", ...(onCase ? { subject: onCase } : {}), text: "Undo failed", action: open(`?action=${S}`) });
      return;
    case "case.opened":
      if (p.severity === "critical")
        toast({
          at: event.created_at,
          tone: "critical",
          subject: { label: shortId(S), title: S, to: `/cases/${S}` },
          text: p.entity ? `Critical case on ${bare(String(p.entity))}` : "Critical case",
          action: open(`/cases/${S}`),
        });
      return;
    case "case.severity_changed":
      if (p.to === "critical")
        toast({
          at: event.created_at,
          tone: "critical",
          subject: { label: shortId(S), title: S, to: `/cases/${S}` },
          text: "Raised to critical",
          action: open(`/cases/${S}`),
        });
      return;
    case "case.budget_exhausted":
      if (p.severity === "high" || p.severity === "critical")
        toast({
          at: event.created_at,
          tone: "crew",
          group: S,
          subject: { label: shortId(S), title: S, to: `/cases/${S}` },
          text: "Crew stopped · budget",
          action: open(`/cases/${S}`),
        });
      return;
    // One failing condition is one toast however often it repeats: its group bumps the count.
    case "health.llm.failing":
      toast({ at: event.created_at, tone: "critical", group: "llm", text: "Crew can't reach its model", action: open("/health/crew") });
      return;
    case "health.audit.broken":
      toast({ at: event.created_at, tone: "critical", group: "audit", text: "Audit chain broken", action: open("/access?tab=audit") });
      return;
  }
}

/* -- the subscription ------------------------------------------------------- */

/** How long the "now" refreshes of a burst gather before one refetch each. */
const TICK = 300;

/**
 * Apply one event: refresh what it changed on the next tick, the bursty ones
 * after a quiet spell. A burst of events asks for each query once per tick, and
 * a fetch already in flight is reused rather than cancelled and sent again.
 */
function useApply() {
  const client = useQueryClient();
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const batch = useRef<{ keys: Map<string, QueryKey>; done: Promise<unknown>; timer: ReturnType<typeof setTimeout> } | null>(null);
  useEffect(() => {
    const pending = timers.current;
    const queued = batch;
    return () => {
      for (const t of pending.values()) clearTimeout(t);
      pending.clear();
      if (queued.current) clearTimeout(queued.current.timer);
      queued.current = null;
    };
  }, []);
  return (event: StreamEvent): Promise<unknown> => {
    const { now, later } = invalidations(event);
    for (const { key, ms, live } of later) {
      const id = JSON.stringify(key);
      clearTimeout(timers.current.get(id));
      timers.current.set(
        id,
        setTimeout(() => {
          timers.current.delete(id);
          void client.invalidateQueries(
            { queryKey: key, ...(live ? { predicate: (query) => query.meta?.live === true } : {}) },
            { cancelRefetch: false },
          );
        }, ms),
      );
    }
    if (!batch.current) {
      const keys = new Map<string, QueryKey>();
      let settle: (value: unknown) => void = () => {};
      const done = new Promise<unknown>((resolve) => (settle = resolve));
      const flush = () => {
        batch.current = null;
        settle(Promise.all([...keys.values()].map((key) => client.invalidateQueries({ queryKey: key }, { cancelRefetch: false }))));
      };
      batch.current = { keys, done, timer: setTimeout(flush, TICK) };
    }
    for (const key of now) batch.current.keys.set(JSON.stringify(key), key);
    return batch.current.done;
  };
}

/** An event from well before this connection opened is history being replayed, not news (clocks may differ by minutes). */
const HISTORY = 5 * 60_000;

/** Follow the stream; true while it is connected and delivering. Mounted once, by the shell. */
export function useLive(): boolean {
  const client = useQueryClient();
  const apply = useApply();
  const applyRef = useRef(apply);
  useEffect(() => {
    applyRef.current = apply;
  });
  const signedOut = useSignedOut();
  const wasSignedOut = useRef(signedOut);

  useEffect(() => {
    // Signing in again: every answer on screen may be stale.
    if (wasSignedOut.current && !signedOut) void client.invalidateQueries();
    wasSignedOut.current = signedOut;
    if (signedOut) return;
    const controller = new AbortController();
    const { signal } = controller;
    async function run() {
      // Start at the head of the stream: only what happens from now on is news. Without
      // the head the stream would replay the whole history, so it waits and asks again.
      let head: number | null = null;
      for (let attempt = 0; head === null; attempt++) {
        try {
          head = (await callData<{ latest_seq: number }>("stream.tail", { limit: 1 }, signal)).latest_seq;
        } catch (error) {
          if (signal.aborted) return;
          // An ended session or a missing scope will be refused again.
          if (error instanceof ApiError && error.isAuth) return deny(error);
          await pause(attempt, signal);
          if (signal.aborted) return;
        }
      }
      const since = head;
      const started = Date.now();
      resetPresence();
      void seedPresence(since);
      await subscribe({
        since,
        signal,
        onEvent: (event) => {
          if (event.seq <= since) return;
          const refreshed = applyRef.current(event);
          // History the server replayed refreshes what it changed but interrupts nobody.
          if (Date.parse(event.created_at) < started - HISTORY) return;
          notePresence(event);
          if (event.type === "finding.new") setFresh(fresh + 1);
          announce(event, client, refreshed);
        },
      });
    }
    void run();
    return () => controller.abort();
  }, [client, signedOut]);

  return useStreamState().state === "live";
}
