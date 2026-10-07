/**
 * The only way this console talks to shoc.
 *
 * Every capability is `POST /v1/<area>/<name>` and every answer is the same
 * envelope: `{ data, summary, citations }`. There is no console-only endpoint:
 * if a screen needs something, shoc grows a capability and every other client
 * gets it too. The one other path is the kernel's sign-in (`/auth/*`, RFC
 * 0028), which any browser client uses: it sets an HttpOnly session cookie
 * that the browser sends with every call, so this page holds no credential.
 */
import { useSyncExternalStore } from "react";

export type Envelope<T> = {
  data: T;
  summary: string;
  citations: string[];
};

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Every reason a gate refused a merge (`gate_refused`), one per entry. */
    readonly reasons: string[] = [],
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** A sign-in or permission problem the operator can fix, rather than a bug. */
  get isAuth(): boolean {
    return this.status === 401 || this.status === 403 || this.code === "denied";
  }

  /**
   * The browser is not signed in: its session ended (401 `signed_out`), or it
   * sent no credential at all, which is how an expired cookie arrives (401
   * `unauthenticated`). A missing scope (403) is not this.
   */
  get isSignedOut(): boolean {
    return this.status === 401;
  }

  /** shoc could not be reached at all. */
  get isNetwork(): boolean {
    return this.code === "network";
  }
}

const base = import.meta.env.VITE_SHOC_URL ?? "";

/** Where shoc answers, as a client outside this page writes it. */
export const apiBase = base || window.location.origin;

/** The host alone, for "Can't reach 192.0.2.10:8080". */
export const apiHost = apiBase.replace(/^\w+:\/\//, "");

/* -- the signed-out banner -------------------------------------------------- */

let signedOut = false;
const listeners = new Set<() => void>();

/**
 * The session ended: the shell raises "Signed out" until the browser signs in
 * again, and every call fails at once without going out, since it would be
 * refused again; a pending panel settles to its "—" rather than a skeleton.
 * Signing in refetches what is on screen (`lib/live.ts`).
 */
export function markSignedOut() {
  if (signedOut) return;
  signedOut = true;
  for (const l of listeners) l();
}

export function clearSignedOut() {
  if (!signedOut) return;
  signedOut = false;
  for (const l of listeners) l();
}

/** One user.me past the short-circuit: signed in again in another tab, it lowers the banner and answers true. */
export async function recheck(): Promise<boolean> {
  try {
    const response = await fetch(path("user.me"), { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    if (!response.ok) return false;
  } catch {
    return false;
  }
  clearSignedOut();
  return true;
}

export function useSignedOut(): boolean {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => signedOut,
  );
}

/* -- the unreachable banner ------------------------------------------------- */

let unreachable = false;
const downListeners = new Set<() => void>();

/** The shell raises "Can't reach shoc" while health.status fails at the network: each panel's own error then reads "—". */
export function setUnreachable(next: boolean) {
  if (unreachable === next) return;
  unreachable = next;
  for (const l of downListeners) l();
}

export function useUnreachable(): boolean {
  return useSyncExternalStore(
    (l) => (downListeners.add(l), () => downListeners.delete(l)),
    () => unreachable,
  );
}

/** An error whose Retry belongs to a banner, not the panel: signed out, a missing scope, or shoc unreachable while the shell says so. */
export const bannered = (error: unknown, down: boolean) => error instanceof ApiError && (error.isAuth || (down && error.isNetwork));

/* -- calls ------------------------------------------------------------------ */

function path(capability: string): string {
  return `${base}/v1/${capability.split(".").join("/")}`;
}

/*
 * How long a call may take before the console calls it failed, so a hung
 * kernel reaches the screen's error and Retry rather than a skeleton for the
 * hour the proxy waits. Capabilities that do real work (the crew, the
 * warehouse, a vendor's API) get the proxy's own 150s.
 */
const DEADLINE = 30_000;
const SLOW_DEADLINE = 150_000;
const SLOW = new Set([
  "ask",
  "events.query",
  "events.summarize",
  "rule.test",
  "rule.backtest",
  "health.rules",
  "hunt.run",
  "hunt.daily",
  "detect.run",
  "detection.work",
  "report.get",
  "report.send",
  "metrics.export",
  "search",
  "timeline.build",
  "timeline.extend",
  "graph.refresh",
  "case.investigate",
  "case.recheck",
  "playbook.run",
  "action.run",
  "action.approve",
  "action.undo",
  "source.sync",
  "source.onboard",
  "source.sample",
  "source.configure",
  "mapping.test",
  "intel.refresh",
  "posture.get",
  "posture.exposure",
  "config.apply",
  // The gate replays fixtures and backtests history.
  "detection.merge",
  "hunt.merge",
]);

/** The proxy's own failure pages: shoc is down behind it, whatever the body says. */
const UNREACHABLE = new Set([0, 502, 503, 504]);

/** Call one capability; a refusal that means the session ended raises the signed-out banner. */
export async function call<T = unknown>(
  capability: string,
  input: Record<string, unknown> = {},
  signal?: AbortSignal,
): Promise<Envelope<T>> {
  if (signedOut) throw new ApiError(401, "signed_out", "signed out");
  const deadline = typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(SLOW.has(capability) ? SLOW_DEADLINE : DEADLINE) : undefined;
  const both = signal && deadline && typeof AbortSignal.any === "function" ? AbortSignal.any([signal, deadline]) : (signal ?? deadline);
  const late = () => Boolean(deadline?.aborted && !signal?.aborted);
  let response: Response;
  let text: string;
  try {
    response = await fetch(path(capability), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: both,
    });
    text = await response.text();
  } catch (error) {
    if (late()) throw new ApiError(0, "network", "shoc took too long");
    if (signal?.aborted || (error as Error)?.name === "AbortError") throw error;
    throw new ApiError(0, "network", `Can't reach ${apiHost}`);
  }

  try {
    return answer(response, text, `${capability} failed`) as Envelope<T>;
  } catch (problem) {
    if (problem instanceof ApiError && problem.isSignedOut) markSignedOut();
    throw problem;
  }
}

/** The JSON a call answered, or the ApiError its failure means. */
function answer(response: Response, text: string, failed: string): unknown {
  // A body that is not JSON is a proxy's page (nginx's 502) or the app's index.html: never shown as a message.
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    if (UNREACHABLE.has(response.status)) throw new ApiError(response.status, "network", `Can't reach ${apiHost}`);
    throw new ApiError(response.status, "bad_response", `shoc answered ${response.status}`);
  }
  if (response.ok) return body;
  const error = (body as { error?: { code?: string; message?: string; reasons?: string[] } })?.error;
  if (UNREACHABLE.has(response.status) && (!error || error.code === "unreachable"))
    throw new ApiError(response.status, "network", `Can't reach ${apiHost}`);
  throw new ApiError(
    response.status,
    error?.code ?? "error",
    error?.message ?? `${failed} with ${response.status}`,
    Array.isArray(error?.reasons) ? error.reasons.map(String) : [],
  );
}

/** `data` alone, for the common case. */
export async function callData<T>(
  capability: string,
  input: Record<string, unknown> = {},
  signal?: AbortSignal,
): Promise<T> {
  return (await call<T>(capability, input, signal)).data;
}

/**
 * One of the kernel's sign-in routes, `POST /auth/<path>` (RFC 0028): the
 * answer's JSON, or an ApiError carrying the route's own code (`bad_credentials`,
 * `bad_code`, `link_expired`, `slow_down`…). It never raises the banner: a
 * wrong password is the login page's to say.
 */
export async function auth<T = unknown>(path: string, body: Record<string, unknown> = {}): Promise<T> {
  let response: Response;
  let text: string;
  try {
    response = await fetch(`${base}/auth/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    text = await response.text();
  } catch {
    throw new ApiError(0, "network", `Can't reach ${apiHost}`);
  }
  return answer(response, text, `/auth/${path} failed`) as T;
}

/** An error in the gate's plain words: signed out, unreachable, or not allowed. */
export function explain(error: unknown): string {
  if (!(error instanceof ApiError)) return error instanceof Error ? error.message : String(error);
  if (error.isNetwork) return error.message;
  if (error.isSignedOut) return "Signed out";
  if (error.isAuth) return "Not allowed";
  return error.message;
}

export async function health(): Promise<boolean> {
  try {
    const response = await fetch(`${base}/healthz`);
    return response.ok;
  } catch {
    return false;
  }
}
