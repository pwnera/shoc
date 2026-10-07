import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { groupJobs, problemsOf, roleRows, spendBuckets } from "@/routes/health/model";
import { jobWord } from "@/lib/labels";
import { Measurement } from "@/routes/Measurement";
import { Health } from "@/routes/Health";
import { Connections } from "@/routes/Connections";
import { runCommand } from "@/lib/commands";
import type { SystemHealth } from "@/types";

const health = (over: Partial<SystemHealth> = {}): SystemHealth => ({
  ok: true,
  store: { dialect: "postgres", ok: true, event_count: 10, latest_event: null },
  sources: [],
  rules: { tracked: 1, failing: 0, fires: 0 },
  jobs: { pending: 0, running: 0, failed: 0, failed_recently: 0, overdue_schedules: [] },
  findings: { total: 0, open: 0, high: 0 },
  ...over,
});

describe("Health's rows", () => {
  it("keeps only the platform's own problems, the failing ones first", () => {
    const rows = problemsOf(
      [
        { kind: "source.quality", subject: "GitHub Audit Log", detail: "prose", severity: "high" },
        { kind: "rule.noisy", subject: "aws_x", detail: "prose", severity: "high" },
        { kind: "case.stalled", subject: "CASE-1", detail: "prose", severity: "high" },
        { kind: "cost.unpriced", subject: "model-x", detail: "prose", severity: "medium" },
        { kind: "llm.failing", subject: "model-x", detail: "prose", severity: "high" },
      ],
      health({
        store: { dialect: "postgres", ok: false, event_count: 0, latest_event: null },
        jobs: { pending: 1, running: 0, failed: 0, failed_recently: 0, overdue_schedules: ["detect.run"] },
      }),
    );
    expect(rows.map((r) => `${r.component} ${r.subject} ${r.word}`)).toEqual([
      "store postgres unreachable",
      "worker detection overdue",
      "model model-x failing",
      "spend model-x no price",
    ]);
    expect(rows.map((r) => r.to)).toEqual([undefined, "/health/jobs", "/health/crew", "/health/spend"]);
  });

  it("groups failed jobs by kind and error class, overdue schedules first", () => {
    const groups = groupJobs(
      [
        { kind: "intel.refresh", error: "ConfigError: unknown feed (have: a, b)", jobs: 4, last_at: "2026-09-29T19:00:00Z" },
        { kind: "intel.refresh", error: "ConfigError: unknown feed (have: a)", jobs: 9, last_at: "2026-09-28T19:00:00Z" },
        { kind: "source.sync", error: "TimeoutError: slow", jobs: 1, last_at: "2026-09-30T10:00:00Z" },
      ],
      ["hunt.daily"],
    );
    expect(groups.map((g) => `${g.kind} ${g.cls} ${g.jobs}`)).toEqual([
      "hunt.daily overdue 0",
      "source.sync TimeoutError 1",
      "intel.refresh ConfigError 13",
    ]);
    expect(groups[2]!.errors).toHaveLength(2);
    expect(groups[2]!.last_at).toBe("2026-09-29T19:00:00Z");
  });

  it("names job kinds in words, and an unknown kind by its parts", () => {
    expect(["hunt.daily", "detect.run", "source.sync", "intel.refresh"].map(jobWord)).toEqual([
      "daily hunts",
      "detection",
      "source pulls",
      "feed pulls",
    ]);
    expect(jobWord("brand_new.kind")).toBe("brand new kind");
  });

  it("draws one bucket a day with a part per model", () => {
    const now = Date.parse("2026-10-03T12:00:00Z");
    const buckets = spendBuckets(
      [
        { day: "2026-10-03", model: "a", calls: 1, tokens_in: 10, tokens_out: 5, usd: 0.5 },
        { day: "2026-10-02", model: "b", calls: 1, tokens_in: 20, tokens_out: 0, usd: 0 },
      ],
      3,
      now,
    );
    expect(buckets.map((b) => b.key)).toEqual(["2026-10-01", "2026-10-02", "2026-10-03"]);
    expect(buckets[2]!.parts.find((p) => p.label === "a")!.value).toBe(0.5);
    const tokens = spendBuckets([{ day: "2026-10-02", model: "b", calls: 1, tokens_in: 20, tokens_out: 1, usd: 0 }], 3, now, "tokens");
    expect(tokens[1]!.parts[0]!.value).toBe(21);
  });

  it("says each role is working, down, silent, failing its calls or idle", () => {
    const message = (agent: string, at: string) => ({
      seq: 1,
      type: "openspace.message",
      subject: "CASE-1",
      payload: { agent, kind: "evidence" },
      created_at: at,
    });
    const rows = roleRows(
      [message("Investigator", "2026-10-03T10:00:00Z"), message("Orchestrator", "2026-10-03T11:00:00Z")],
      [{ seq: 2, ts: "2026-10-03T12:00:00Z", principal_kind: "agent", principal_id: "Hunter", capability: "events.query", error: "boom", hash: "h" }],
      new Set(["Manager"]),
      false,
    );
    const by = Object.fromEntries(rows.map((r) => [r.role.name, r]));
    expect(by.Manager!.state).toBe("working");
    expect(by.Investigator!.state).toBe("idle");
    expect(by.Investigator!.last).toBe("2026-10-03T11:00:00Z");
    expect(by.Challenger!.state).toBe("silent");
    expect(by.Hunter!.state).toBe("errors");
    expect(by.Sentinel!.last).toBeNull();
    expect(roleRows([], [], new Set(), true).find((r) => r.role.name === "Integrator")!.state).toBe("idle");
    expect(roleRows([], [], new Set(), true).find((r) => r.role.name === "Ops")!.state).toBe("down");
  });
});

const ANSWERS: Record<string, unknown> = {
  "metrics/get": {
    days: 30,
    by_incident_type: { credential: { cases: 2, mttd_minutes: 10, time_to_triage_minutes: 0, time_to_contain_minutes: 60, mttr_minutes: 600 } },
    dispositions: { malicious: 1, benign_expected: 1 },
    false_positive_rate: 0,
    false_positives_by_rule: [],
    spend_usd: 0,
  },
  "case/list": { rows: [], count: 0 },
  "health/status": health(),
  "ops/alerts": {
    alerts: [{ kind: "cost.unpriced", subject: "model-x", detail: "prose that never shows", severity: "medium" }],
    count: 1,
  },
  "llm/show": { provider: "p", model: "m", model_cheap: "", base_url: "", key: "set", stored: [], spend_usd_per_day: 0, hunt_tokens_per_day: 0 },
  "health/jobs": { failed: [] },
  "playbook/runs": { runs: [], count: 0 },
  "action/list": { rows: [], count: 0, waiting_for_approval: 0 },
  "source/list": {
    configured: [
      {
        source: "okta",
        enabled: true,
        settings: {},
        interval_seconds: 300,
        has_secret: true,
        last_run_at: "2026-10-04T10:00:00Z",
        last_ok_at: "2026-10-04T10:00:00Z",
        last_error: null,
        events_seen: 5,
      },
    ],
    available: ["okta"],
    push_only: [],
    also_push: [],
    mappings: [],
    needs: {},
    onboarding: [],
  },
  "health/sources": { sources: [], ok: true },
  "health/cost": {
    spend: { rows: [], usd_total: 0, usd_today: 0, tokens: 0, days: 30 },
    volume: { events: 0, days: 30, by_product: [] },
  },
  "events/summarize": { rows: [] },
  "own/list": { rows: [], count: 0 },
  "rule/list": { rules: [], count: 0 },
  "credential/list": { configured: [], needs: [], providers: {} },
};

let calls: string[] = [];
/* Paths that answer 500, and alerts in place of the default ones, per test. */
let failing: string[] = [];
let answers: Record<string, unknown> = {};

function show(element: React.ReactNode, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>{element}</MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

describe("the platform screens", () => {
  beforeEach(() => {
    calls = [];
    failing = [];
    answers = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input).replace(/^.*\/v1\//, "");
        calls.push(path);
        if (failing.includes(path)) return new Response(JSON.stringify({ error: "boom" }), { status: 500 });
        const data = answers[path] ?? ANSWERS[path] ?? {};
        return new Response(JSON.stringify({ data, summary: "", citations: [] }), { status: 200 });
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("builds no report when Measurement loads or regains focus", async () => {
    show(<Measurement />, "/measurement");
    expect(await screen.findByText("credential")).toBeInTheDocument();
    await act(async () => {
      window.dispatchEvent(new Event("focus"));
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(calls).toContain("metrics/get");
    expect(calls.some((c) => c.startsWith("report/"))).toBe(false);
  });

  it("opens /health/jobs on the Jobs tab, 24 hours, with no Retry", async () => {
    show(<Health />, "/health/jobs");
    expect(await screen.findByText("No failed jobs in 24h")).toBeInTheDocument();
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("Jobs");
    expect(screen.getByRole("radio", { checked: true })).toHaveTextContent("24h");
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  });

  it("names the measures as the table and the verdicts do", async () => {
    show(<Measurement />, "/measurement");
    expect(await screen.findByText("to resolve", { selector: ".sh-strip__label" })).toBeInTheDocument();
    expect(screen.getByText("rule was wrong", { selector: ".sh-strip__label" })).toBeInTheDocument();
    expect(screen.queryByText("MTTR")).not.toBeInTheDocument();
  });

  it("says what failed, in the bad tone", async () => {
    answers = {
      "ops/alerts": { alerts: [{ kind: "llm.failing", subject: "m", detail: "", severity: "high" }], count: 1 },
    };
    show(<Health />, "/health");
    const word = await screen.findByText("Crew down");
    expect(word.closest(".sh-strip__state")).toHaveAttribute("data-tone", "bad");
  });

  it("names a failed page as the state, not only failing", async () => {
    const page = { action_uid: "ACT-1", type: "notify.page", state: "failed", created_at: new Date().toISOString() };
    answers = { "action/list": { rows: [page], count: 1, waiting_for_approval: 0 } };
    show(<Health />, "/health");
    const word = await screen.findByText("Page failed");
    expect(word.closest(".sh-strip__state")).toHaveAttribute("data-tone", "bad");
  });

  it("can't tell when a stage's query fails, and offers Retry", async () => {
    failing = ["playbook/runs", "llm/show"];
    show(<Health />, "/health");
    expect(await screen.findByText("Can't tell")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });

  it("keeps the shown rows when a refresh fails, and says when they are from", async () => {
    const client = show(<Health />, "/health");
    expect(await screen.findByText("model-x")).toBeInTheDocument();
    failing = ["health/status", "ops/alerts"];
    await act(() => client.refetchQueries());
    expect(await screen.findByText(/^as of /)).toBeInTheDocument();
    expect(screen.getByText("model-x")).toBeInTheDocument();
    expect(screen.queryByText("Can't tell")).not.toBeInTheDocument();
  });

  it("goes back to Problems on Escape from the tab a row opened", async () => {
    show(<Health />, "/health");
    fireEvent.click(await screen.findByText("model-x"));
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("Spend");
    act(() => void runCommand("shell.escape"));
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("Problems");
  });

  it("starts no Integrator run from a link: ?do= stops at the confirm", async () => {
    show(<Connections />, "/connections?do=sources.onboard-all");
    expect(await screen.findByText("Okta")).toBeInTheDocument();
    expect(screen.getByText("delivering", { selector: ".sh-status" })).toBeInTheDocument();
    expect(calls).not.toContain("source/onboard");
  });

  it("links a source to the credential that acts on it, or to connect one", async () => {
    const row = (ANSWERS["source/list"] as { configured: Record<string, unknown>[] }).configured[0];
    answers["source/list"] = {
      ...(ANSWERS["source/list"] as object),
      configured: [{ ...row, response: [{ provider: "okta", credentials: [], missing: ["acme.okta.com"] }] }],
    };
    show(<Connections />, "/connections?source=okta");
    const link = await screen.findByRole("link", { name: "Connect Okta", hidden: true });
    expect(link).toHaveAttribute("href", "/connections?vendor=okta&view=credential");
  });

  it("keeps the connected sources when a refresh fails", async () => {
    const client = show(<Connections />, "/connections");
    expect(await screen.findByText("Okta")).toBeInTheDocument();
    failing = ["source/list", "health/sources"];
    await act(() => client.refetchQueries());
    expect(await screen.findByText(/^as of /)).toBeInTheDocument();
    expect(screen.getByText("Okta")).toBeInTheDocument();
    expect(screen.queryByText("Can't tell")).not.toBeInTheDocument();
  });

  it("lists only platform problems, without the kernel's prose", async () => {
    show(<Health />, "/health");
    expect(await screen.findByText("model-x")).toBeInTheDocument();
    expect(screen.getByText("· no price")).toBeInTheDocument();
    expect(screen.queryByText("prose that never shows")).not.toBeInTheDocument();
  });
});
