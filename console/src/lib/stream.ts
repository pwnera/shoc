/**
 * The event stream, over `fetch` rather than `EventSource`.
 *
 * `EventSource` hides why a connection was refused, and the console must tell
 * an ended session from a missing scope. Reading the response body as a
 * stream gives the same server-sent events with the status in hand; the
 * session cookie goes with it like any same-origin request.
 *
 * A dropped connection waits before it retries, longer each time (with jitter,
 * at most 30s), so a restarting server is not hammered. An ended session (a
 * 401, or the kernel's `event: signed_out`, sent when its 30-second re-check
 * fails) stops the stream and raises the signed-out banner instead of retrying
 * for ever; a caller without `stream:read` stops it quietly (the screens still
 * poll).
 */
import { useSyncExternalStore } from "react";
import { ApiError, markSignedOut } from "./api";
import { useNow } from "./now";

export type StreamEvent = {
  seq: number;
  type: string;
  subject: string;
  payload: Record<string, unknown>;
  created_at: string;
};

const base = import.meta.env.VITE_SHOC_URL ?? "";

/** What the top bar's health pill and the "live updates paused" banner read. */
export type StreamState = {
  state: "connecting" | "live" | "retrying" | "denied";
  /** When the next attempt runs, while retrying. */
  retryAt?: number;
  /** Since when the stream has not been live; unset while live. */
  downSince?: number;
};

let status: StreamState = { state: "connecting", downSince: Date.now() };
const listeners = new Set<() => void>();
let wake: (() => void) | undefined;

function setStatus(next: StreamState) {
  status = next;
  for (const l of listeners) l();
}

/** The state now, outside React: a query's poll asks whether the stream already keeps it fresh. */
export const streamState = (): StreamState["state"] => status.state;

export function useStreamState(): StreamState {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => status,
  );
}

/** How long the stream may be down before the shell says live updates are paused. */
export const PAUSED_AFTER = 120_000;

export type StreamStatus = {
  /** "offline" is retrying for more than two minutes. */
  state: "connecting" | "live" | "retrying" | "offline" | "denied";
  downSince?: number;
};

/** The stream's state as the shell words it, re-read on the shared tick. */
export function useStreamStatus(): StreamStatus {
  const s = useStreamState();
  const now = Math.max(useNow(), Date.now());
  const long = s.downSince !== undefined && now - s.downSince > PAUSED_AFTER;
  const state = (s.state === "retrying" || s.state === "connecting") && long ? "offline" : s.state;
  return { state, ...(s.downSince !== undefined ? { downSince: s.downSince } : {}) };
}

/** Skip the rest of the wait and reconnect now ("Retry now"). */
export function retryNow() {
  wake?.();
}

/** The wait before attempt `n` (from 0): about 1s, 2s, 4s…, ±30% at random, never more than 30s. */
export function backoff(n: number, random = Math.random): number {
  return Math.min(30_000, Math.round(1_000 * 2 ** Math.min(n, 15) * (0.7 + 0.6 * random())));
}

/** The `data:` lines of one server-sent event, with or without the space after the colon. */
export function dataOf(chunk: string): string {
  return chunk
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(line.startsWith("data: ") ? 6 : 5))
    .join("\n");
}

export type StreamOptions = {
  since?: number;
  types?: string[];
  onEvent: (event: StreamEvent) => void;
  /** Called each time the connection opens, before any event arrives. */
  onOpen?: () => void;
  onError?: (error: unknown) => void;
  signal: AbortSignal;
};

/** The stream will not answer this caller: an ended session raises the banner, a missing scope only stops. */
export function deny(error: unknown) {
  setStatus({ state: "denied", downSince: status.downSince ?? Date.now() });
  if (error instanceof ApiError && error.isSignedOut) markSignedOut();
}

/** Wait before attempt `attempt` while saying so ("retrying in 12s"); "Retry now" and an abort end it early. */
export async function pause(attempt: number, signal: AbortSignal): Promise<void> {
  const wait = backoff(attempt);
  setStatus({ state: "retrying", retryAt: Date.now() + wait, downSince: status.downSince ?? Date.now() });
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, wait);
    wake = () => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", () => wake?.(), { once: true });
  });
  wake = undefined;
  if (!signal.aborted) setStatus({ ...status, state: "connecting" });
}

/** Silence after which a "live" stream is taken for dead: several missed 2s keep-alives. */
const SILENT = 15_000;

class Refused extends Error {
  constructor(readonly problem: ApiError) {
    super(problem.message);
  }
}

export async function subscribe({
  since = 0,
  types = [],
  onEvent,
  onOpen,
  onError,
  signal,
}: StreamOptions): Promise<void> {
  const query = new URLSearchParams();
  if (since) query.set("since", String(since));
  if (types.length) query.set("types", types.join(","));
  let attempt = 0;

  while (!signal.aborted) {
    /*
     * The kernel sends a keep-alive every 2s. A connection silent for 15s is
     * half-open (a sleep, a network change, a dropped NAT entry) and would read
     * as live for minutes: it is dropped and reconnected from `since`. Coming
     * back to the tab with nothing heard for 10s does the same at once.
     */
    const conn = new AbortController();
    const stop = () => conn.abort();
    signal.addEventListener("abort", stop, { once: true });
    let heard = Date.now();
    const watch = setInterval(() => Date.now() - heard > SILENT && conn.abort(), 5_000);
    const back = () => document.visibilityState === "visible" && Date.now() - heard > 10_000 && conn.abort();
    document.addEventListener("visibilitychange", back);
    try {
      const response = await fetch(`${base}/v1/stream?${query.toString()}`, { signal: conn.signal });
      if (response.status === 401 || response.status === 403) {
        // The body says which refusal it is: an ended session, or a caller without the scope.
        const text = await response.text().catch(() => "");
        let message = `stream: ${response.status}`;
        let code = "denied";
        try {
          const error = (JSON.parse(text) as { error?: { code?: string; message?: string } }).error;
          message = error?.message ?? message;
          code = error?.code ?? code;
        } catch {
          /* not JSON: the status alone */
        }
        throw new Refused(new ApiError(response.status, code, message));
      }
      if (!response.ok || !response.body) throw new Error(`stream: ${response.status}`);
      setStatus({ state: "live" });
      attempt = 0;
      onOpen?.();

      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      while (!signal.aborted) {
        const { done, value } = await reader.read();
        if (done) break;
        heard = Date.now();
        buffer += value.replace(/\r\n/g, "\n");
        // Server-sent events are separated by a blank line.
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() ?? "";
        for (const chunk of chunks) {
          if (/^event: ?signed_out$/m.test(chunk)) throw new Refused(new ApiError(401, "signed_out", "signed out"));
          const data = dataOf(chunk);
          if (!data) continue;
          try {
            const event = JSON.parse(data) as StreamEvent;
            query.set("since", String(event.seq));
            onEvent(event);
          } catch {
            /* a keep-alive comment, or a partial frame */
          }
        }
      }
      if (signal.aborted) return;
      throw new Error("stream closed");
    } catch (error) {
      if (signal.aborted) return;
      if (error instanceof Refused) {
        deny(error.problem);
        onError?.(error.problem);
        return;
      }
      onError?.(error);
      // The server restarts, the laptop sleeps. Wait, then pick up from `since`.
      await pause(attempt++, signal);
    } finally {
      clearInterval(watch);
      document.removeEventListener("visibilitychange", back);
      signal.removeEventListener("abort", stop);
    }
  }
}
