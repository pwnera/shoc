import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import { focusManager, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Overview } from "@/routes/Overview";
import { actionCounters, caseCounters, findingCounter, handoverMarks } from "@/routes/overview/handover";
import { begin } from "@/lib/since";
import type { Action, Case, Finding } from "@/types";

const hour = 3_600_000;
const day = 24 * hour;
const at = (offset: number) => new Date(Date.now() + offset).toISOString();

function kase(uid: string, over: Partial<Case> = {}): Case {
  return {
    case_uid: uid,
    title: `case ${uid}`,
    severity: "high",
    state: "analysis",
    verdict: "suspicious",
    confidence: 0.6,
    entity_key: "user:deploy-ci",
    summary: "",
    finding_uids: [],
    attack: [],
    rounds: 1,
    tokens_used: 0,
    opened_at: at(-2 * hour),
    updated_at: at(-hour),
    closed_at: null,
    ...over,
  };
}

function action(uid: string, over: Partial<Action> = {}): Action {
  return {
    action_uid: uid,
    case_uid: "CASE-1",
    type: "aws.disable_access_key",
    target: "AKIAIOSFODNN7EXAMPLE",
    params: {},
    autonomy: "L2",
    state: "proposed",
    reversible: true,
    dry_run: true,
    rationale: "",
    requested_by: "IR Commander",
    approved_by: null,
    result: {},
    created_at: at(-hour),
    ...over,
  };
}

function finding(uid: string, over: Partial<Finding> = {}): Finding {
  return {
    finding_uid: uid,
    rule_id: "aws_access_denied_burst",
    title: "Access denied burst",
    severity: "high",
    confidence: 0.7,
    status: "new",
    entity_key: "user:deploy-ci",
    first_seen: at(-hour),
    last_seen: at(-hour),
    event_count: 3,
    event_uids: [],
    attack: [],
    evidence: {},
    ...over,
  };
}

type Answers = Record<string, unknown>;

const BASE: Answers = {
  "action.list": { rows: [], count: 0, waiting_for_approval: 0 },
  "case.list": { rows: [], count: 0 },
  "source.list": { configured: [], available: [], push_only: [], also_push: [], mappings: [], needs: {}, onboarding: [] },
  "ops.alerts": { alerts: [], count: 0 },
  "health.status": { ok: true, store: { ok: true }, jobs: { overdue_schedules: [] } },
  "finding.list": { rows: [], count: 0 },
  "policy.show": { defaults: {}, actions: {}, available_actions: [], action_params: {} },
};

/** Answer each capability from `answers`; an Error answers 500, a function sees the input. */
function serve(answers: Answers) {
  const all = { ...BASE, ...answers };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const name = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      const input = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      const answer = all[name];
      if (answer instanceof Error)
        return new Response(JSON.stringify({ error: { code: "error", message: answer.message } }), { status: 500 });
      const data = typeof answer === "function" ? (answer as (i: typeof input) => unknown)(input) : (answer ?? {});
      return new Response(JSON.stringify({ data, summary: "", citations: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
}

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <Overview />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const heading = () => screen.getByRole("heading", { level: 1 });

describe("the Overview heading", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("says nothing needs you only once every list answered", async () => {
    serve({});
    show();
    expect(heading()).toHaveTextContent("Checking…");
    expect(await screen.findByRole("heading", { level: 1, name: /Nothing needs you/ })).toBeInTheDocument();
    // The inbox's empty row does not say it a second time.
    expect(screen.getAllByText(/Nothing needs you/)).toHaveLength(1);
  });

  it("reads Can't tell with an error row and Retry when action.list fails, never an all clear", async () => {
    serve({ "action.list": new Error("the store did not answer") });
    show();
    expect(await screen.findByRole("heading", { level: 1, name: /Can't tell/ })).toBeInTheDocument();
    expect(screen.getByText("Approvals")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThan(0);
    expect(screen.queryByText("Nothing needs you")).toBeNull();
    // The handover's action counters read "—", never 0.
    expect(screen.getByText("paged").previousSibling).toHaveTextContent("—");
  });

  it("keeps the inbox and its heading when a refresh fails, and says how old they are", async () => {
    const decided = action("A1", { state: "done", approved_by: "human:jane", approved_at: at(-3 * day) });
    serve({ "action.list": (input: { state?: string }) => ({ rows: input.state === "proposed" ? [] : [decided], count: 1 }) });
    show();
    expect(await screen.findByText("Last decision 3d ago")).toBeInTheDocument();
    serve({ "action.list": new Error("store exploded") });
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    expect(await screen.findByText(/^as of /)).toBeInTheDocument();
    expect(screen.getByText("Last decision 3d ago")).toBeInTheDocument();
    expect(heading()).toHaveTextContent("Nothing needs you");
    expect(screen.queryByText("store exploded")).toBeNull();
    act(() => focusManager.setFocused(undefined));
  });

  it("reads Crew down when the model is failing, with no crew-down row in the inbox", async () => {
    serve({
      "ops.alerts": { alerts: [{ kind: "llm.failing", subject: "anthropic", detail: "401", severity: "high" }], count: 1 },
    });
    show();
    expect(await screen.findByRole("link", { name: "Crew down" })).toHaveAttribute("href", "/health/crew");
    expect(screen.queryByRole("row")).toBeNull();
    // The heading still answers the screen's question once every list did.
    await waitFor(() => expect(heading()).toHaveTextContent("Crew down · nothing needs you"));
  });

  it("counts the decisions and draws an approval with its deadline and fallback, not its facts", async () => {
    const proposals = [
      action("ACT-1", { decide_by: at(2 * hour), fallback: "okta.revoke_sessions" }),
      action("ACT-2", { case_uid: null, type: "okta.suspend_user", target: "user:jane", decide_by: at(hour) }),
    ];
    serve({
      "action.list": (input: { state?: string }) => ({ rows: input.state === "proposed" ? proposals : [], count: 2 }),
      "case.list": { rows: [kase("CASE-1", { severity: "critical" })], count: 1 },
    });
    show();
    expect(await screen.findByRole("heading", { level: 1, name: /2 need you/ })).toBeInTheDocument();
    // Rows open, so the inbox is a grid, as every table whose rows open is.
    const grid = screen.getByRole("grid", { name: "Needs you" });
    expect(grid).toHaveAccessibleDescription("Enter opens the row");
    const rows = within(grid).getAllByRole("row");
    expect(rows).toHaveLength(2);
    // Critical first, whatever the deadlines say.
    expect(within(rows[0]!).getByText("Disable AWS key")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("→ Sign Okta user out")).toBeInTheDocument();
    expect(within(rows[0]!).getByRole("timer")).toBeInTheDocument();
    expect(within(rows[0]!).queryByText("dry run")).toBeNull();
    expect(within(rows[0]!).queryByText(/reversible/)).toBeNull();
  });
});

describe("since you left", () => {
  const since = at(-day);

  it("counts what the crew did and links each counter to the list that reproduces it", () => {
    const cases = [
      kase("A", { opened_at: at(-hour) }),
      kase("B", { opened_at: at(-3 * day), state: "closed", closed_at: at(-2 * hour), closed_by: "crew" }),
      kase("C", { opened_at: at(-3 * day), state: "closed", closed_at: at(-2 * hour), closed_by: "human" }),
    ];
    const [opened, closed] = caseCounters(cases, since, 200);
    expect(opened).toMatchObject({ n: 1, more: false, to: `/cases?since=${encodeURIComponent(since)}` });
    expect(closed).toMatchObject({ n: 1, to: `/cases?tab=closed&since=${encodeURIComponent(since)}&by=crew` });
  });

  it("marks ran as dry when every run was a dry run, and leaves pages and approved runs out of it", () => {
    const actions = [
      action("R1", { state: "done", executed_at: at(-hour), dry_run: true }),
      action("R2", { state: "done", executed_at: at(-hour), dry_run: true, approved_by: "human:jane" }),
      action("P1", { state: "done", type: "notify.page", created_at: at(-hour) }),
      action("X1", { state: "rejected", approved_by: "unattended", updated_at: at(-hour) }),
      action("U1", { state: "rolled_back", updated_at: at(-3 * day) }),
    ];
    const byId = Object.fromEntries(actionCounters(actions, since, 500).map((c) => [c.id, c]));
    expect(byId.ran).toMatchObject({ n: 1, dry: true });
    expect(byId.paged).toMatchObject({ n: 1, to: `/response?tab=pages&since=${encodeURIComponent(since)}` });
    expect(byId.expired).toMatchObject({ n: 1 });
    expect(byId.undone).toMatchObject({ n: 0 });
  });

  it("says 200+ when the capped log stops short of the window", () => {
    const rows = Array.from({ length: 200 }, (_, i) => kase(`K${i}`, { opened_at: at(-hour), updated_at: at(-hour) }));
    expect(caseCounters(rows, since, 200)[0]).toMatchObject({ n: 200, more: true });
    const reaching = [...rows.slice(1), kase("old", { opened_at: at(-9 * day), updated_at: at(-9 * day) })];
    expect(caseCounters(reaching, since, 200)[0]).toMatchObject({ n: 199, more: false });
  });

  it("leaves shoc's own findings and set-aside ones out of the count and the marks", () => {
    const rows = [finding("F1"), finding("F2", { status: "self" }), finding("F3", { status: "suppressed", severity: "low" })];
    expect(findingCounter(rows, since, 500)).toMatchObject({ n: 1, mix: { high: 1, low: 0 } });
    expect(handoverMarks({ since, findings: rows }).map((m) => m.key)).toEqual(["f:F1"]);
  });

  it("opens a mark's case, or the action dialog when it has none", () => {
    const marks = handoverMarks({
      since,
      actions: [
        action("A1", { state: "done", executed_at: at(-hour) }),
        action("A2", { state: "failed", case_uid: null, executed_at: at(-hour) }),
      ],
    });
    expect(marks.map((m) => [m.tone, m.to])).toEqual([
      ["good", "/cases/CASE-1"],
      ["bad", "?action=A2"],
    ]);
  });

  it("reaches back three weeks when the viewer was away three weeks", () => {
    const now = Date.now();
    const visit = begin({ since: now - 22 * day, last: now - 21 * day }, now);
    const window = new Date(visit.since).toISOString();
    const [opened] = caseCounters([kase("A", { opened_at: at(-14 * day) })], window, 200);
    expect(opened!.n).toBe(1);
  });
});
