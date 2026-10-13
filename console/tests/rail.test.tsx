import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Rail } from "@/components/Rail";

const proposal = (uid: string) => ({
  action_uid: uid,
  case_uid: "CASE-1",
  type: "aws.disable_access_key",
  target: "AKIAIOSFODNN7EXAMPLE",
  params: {},
  autonomy: "L2",
  state: "proposed",
  reversible: true,
  dry_run: false,
  rationale: "",
  requested_by: "IR Commander",
  approved_by: null,
  result: {},
  created_at: new Date().toISOString(),
});

const ANSWERS: Record<string, unknown> = {
  "source.list": { configured: [], available: [], push_only: [], also_push: [], mappings: [], needs: {}, onboarding: [] },
  "ops.alerts": { alerts: [], count: 0 },
  "health.status": { ok: true, store: { ok: true }, jobs: { overdue_schedules: [] } },
};

function show(collapsed: boolean, cases: unknown[] = []) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const name = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      const input = init?.body ? (JSON.parse(String(init.body)) as { state?: string }) : {};
      const data =
        name === "action.list"
          ? { rows: input.state === "proposed" ? [proposal("A1"), proposal("A2")] : [], count: 2, waiting_for_approval: 2 }
          : name === "case.list"
            ? { rows: cases, count: cases.length }
            : (ANSWERS[name] ?? {});
      return new Response(JSON.stringify({ data, summary: "", citations: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <Rail collapsed={collapsed} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the rail", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("keeps the inbox count when collapsed, as a crew dot a screen reader hears", async () => {
    show(true);
    const dot = await screen.findByRole("img", { name: "2 need you" });
    expect(dot).toHaveAttribute("data-tone", "crew");
    expect(screen.getByRole("link", { name: /Overview.*2 need you/ })).toBeInTheDocument();
  });

  it("shows the number itself when open, with no dot", async () => {
    show(false);
    expect(await screen.findByText("2", { selector: "span[aria-hidden]" })).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: "2 need you" })).toBeNull();
    expect(screen.getByRole("link", { name: /Overview.*2 need you/ })).toBeInTheDocument();
  });

  it("opens the open critical cases from the Cases dot, the slice the Cases strip's critical fact sets", async () => {
    const open = { case_uid: "CASE-9", state: "analysis", severity: "critical", title: "t", opened_at: new Date().toISOString() };
    show(false, [open]);
    await screen.findByRole("img", { name: "Critical case open" });
    expect(screen.getByRole("link", { name: /^Cases/ })).toHaveAttribute("href", "/cases?severity=critical&state=open");
  });
});
