import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StreamEvent } from "@/lib/stream";

vi.mock("@/lib/api", async (original) => ({ ...(await original<typeof import("@/lib/api")>()), markSignedOut: vi.fn() }));

const ev = (seq: number): StreamEvent => ({ seq, type: "case.updated", subject: "C1", payload: {}, created_at: "2026-10-03T12:00:00Z" });
const frame = (seq: number) => `data: ${JSON.stringify(ev(seq))}\n\n`;

/** A 200 whose body hands out `chunks` one read at a time, then ends (`end`) or stays silent until its connection is aborted. */
function body(signal: AbortSignal, chunks: string[], end = false): Response {
  const read = () =>
    new Promise<{ done: boolean; value?: string }>((resolve, reject) => {
      const gone = () => reject(new DOMException("aborted", "AbortError"));
      if (signal.aborted) return gone();
      const next = chunks.shift();
      if (next !== undefined) return resolve({ done: false, value: next });
      if (end) return resolve({ done: true });
      signal.addEventListener("abort", gone, { once: true });
    });
  return { status: 200, ok: true, body: { pipeThrough: () => ({ getReader: () => ({ read }) }) } } as unknown as Response;
}

let opened: { url: string; signal: AbortSignal }[] = [];

/** Answer the n-th connection (from 1) with `answer`. */
function serve(answer: (n: number, signal: AbortSignal) => Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const signal = init.signal as AbortSignal;
      opened.push({ url, signal });
      return answer(opened.length, signal);
    }),
  );
}

/** The stream module with its state as on a fresh load, and the banner it raises. */
async function fresh() {
  vi.resetModules();
  const api = await import("@/lib/api");
  return { ...(await import("@/lib/stream")), markSignedOut: vi.mocked(api.markSignedOut) };
}

describe("the stream reader (API-2)", () => {
  beforeEach(() => {
    opened = [];
    // markSignedOut is one mock for the whole file: a call one test expects must not count in the next.
    vi.clearAllMocks();
    vi.useFakeTimers();
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    // jsdom has no stream piping: the fake body hands out text already decoded.
    vi.stubGlobal("TextDecoderStream", class {});
  });
  afterEach(() => {
    Reflect.deleteProperty(document, "visibilityState");
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("delivers a frame split across reads once", async () => {
    const { subscribe } = await fresh();
    const whole = frame(5);
    // Cut inside the JSON and between the two newlines that end the frame.
    serve((_, signal) => body(signal, [whole.slice(0, 20), whole.slice(20, -1), whole.slice(-1)]));
    const seen: number[] = [];
    const stop = new AbortController();
    const done = subscribe({ onEvent: (e) => seen.push(e.seq), signal: stop.signal });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(seen).toEqual([5]);
    stop.abort();
    await done;
  });

  it("stops on `event: signed_out` and raises the signed-out banner", async () => {
    const { subscribe, streamState, markSignedOut } = await fresh();
    serve((_, signal) => body(signal, ["event: signed_out\ndata: {}\n\n"]));
    const done = subscribe({ onEvent: () => {}, signal: new AbortController().signal });
    await vi.advanceTimersByTimeAsync(60_000);
    await done;
    expect(opened).toHaveLength(1);
    expect(streamState()).toBe("denied");
    expect(markSignedOut).toHaveBeenCalledOnce();
  });

  it("stops quietly on a 403: a missing scope is no ended session", async () => {
    const { subscribe, streamState, markSignedOut } = await fresh();
    const refusal = JSON.stringify({ error: { code: "denied", message: "stream.tail: caller lacks scope 'stream:read'" } });
    serve(() => ({ status: 403, ok: false, text: async () => refusal }) as unknown as Response);
    const done = subscribe({ onEvent: () => {}, signal: new AbortController().signal });
    await vi.advanceTimersByTimeAsync(60_000);
    await done;
    expect(opened).toHaveLength(1);
    expect(streamState()).toBe("denied");
    expect(markSignedOut).not.toHaveBeenCalled();
  });

  it("reconnects after a close from the last event it saw", async () => {
    const { subscribe } = await fresh();
    serve((n, signal) => (n === 1 ? body(signal, [frame(7)], true) : body(signal, [])));
    const stop = new AbortController();
    const done = subscribe({ onEvent: () => {}, signal: stop.signal });
    await vi.advanceTimersByTimeAsync(2_000); // the first retry waits at most 1.3s
    expect(opened.map((o) => o.url)).toEqual(["/v1/stream?", "/v1/stream?since=7"]);
    stop.abort();
    await done;
  });

  it("drops a connection silent for 15s and opens another", async () => {
    const { subscribe, streamState } = await fresh();
    serve((_, signal) => body(signal, []));
    const stop = new AbortController();
    const done = subscribe({ onEvent: () => {}, signal: stop.signal });
    await vi.advanceTimersByTimeAsync(14_000);
    expect(streamState()).toBe("live");
    expect(opened[0]!.signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(7_000); // the watch looks every 5s
    expect(opened[0]!.signal.aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(opened).toHaveLength(2);
    stop.abort();
    await done;
  });
});
