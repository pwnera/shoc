import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ExportDialog } from "@/routes/measurement/ExportDialog";
import type { HeldNotice, ReportBody, ReportEnvelope } from "@/types";

const notice = (group_key: string, count: number): HeldNotice => ({
  notice_uid: `N-${group_key}`,
  source: "ops",
  kind: "ops.alert",
  group_key,
  severity: "medium",
  case_uid: null,
  body: "held",
  created_at: "2026-10-01T00:00:00Z",
  count,
});

function show(body: ReportBody) {
  const report: ReportEnvelope = {
    report_uid: "R-1",
    kind: "weekly",
    period_start: "2026-09-24T00:00:00Z",
    period_end: "2026-10-01T00:00:00Z",
    summary: "",
    narrative: "",
    body,
  };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ExportDialog
          kind="weekly"
          query={{ data: report, error: null, isPending: false, isError: false }}
          onRetry={() => {}}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const heldTile = () => within(screen.getByRole("region", { name: "actions", hidden: true })).getByText("Held, no page").parentElement!;

describe("the report export", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ data: { rules: [] }, summary: "", citations: [] }), { status: 200 })),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("counts every held notice, not the groups report.get lists them in", () => {
    show({ held: [notice("a", 3), notice("b", 2)], actions: { rows: [], waiting_for_approval: 0 } });
    expect(heldTile()).toHaveTextContent("5");
  });

  it("keeps the number when the body says it as one", () => {
    show({ held: 4, actions: { rows: [], waiting_for_approval: 0 } });
    expect(heldTile()).toHaveTextContent("4");
  });
});
