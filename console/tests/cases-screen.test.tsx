import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Cases } from "@/routes/Cases";
import type { Case } from "@/types";

const hour = 3_600_000;
const day = 24 * hour;
const at = (offset: number) => new Date(Date.now() + offset).toISOString();

function kase(uid: string, over: Partial<Case> = {}): Case {
  return {
    case_uid: uid,
    title: `case ${uid}`,
    severity: "medium",
    state: "analysis",
    verdict: "unknown",
    confidence: 0,
    entity_key: "user:deploy-ci",
    summary: "",
    finding_uids: [],
    attack: [],
    rounds: 1,
    tokens_used: 0,
    opened_at: at(-3 * hour),
    updated_at: at(-hour),
    closed_at: null,
    ...over,
  };
}

const CASES = [
  kase("CASE-closed-attack", { state: "closed", verdict: "malicious", severity: "critical", closed_at: at(-2 * day), closed_by: "human" }),
  kase("CASE-closed-old", { state: "closed", verdict: "malicious", closed_at: at(-20 * day) }),
  kase("CASE-closed-fp", { state: "closed", verdict: "false_positive", closed_at: at(-day), closed_by: "crew" }),
  kase("CASE-open-high", { severity: "high", state: "containment", title: "Third-party app authorised" }),
  kase("CASE-open-critical", { severity: "critical", state: "triage", title: "Hunt: Leaked key in use", entity_key: "AKIAIOSFODNN7EXAMPLE" }),
];

function serve(cases: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const name = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      if (name === "case.list" && cases instanceof Error)
        return new Response(JSON.stringify({ error: { code: "error", message: cases.message } }), { status: 500 });
      const data =
        name === "case.list"
          ? { rows: cases, count: (cases as Case[]).length }
          : name === "action.list"
            ? { rows: [], count: 0, waiting_for_approval: 0 }
            : name === "ops.alerts"
              ? { alerts: [], count: 0 }
              : {};
      return new Response(JSON.stringify({ data, summary: "", citations: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
}

function show(path = "/cases", client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Cases />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const range = () => document.querySelector(".sh-pager__range")?.textContent;

/** 30 open cases, newest change first, then 30 closed ones. */
const MANY = [
  ...Array.from({ length: 30 }, (_, i) => kase(`CASE-open-${String(i).padStart(2, "0")}`, { updated_at: at(-(i + 1) * 60_000) })),
  ...Array.from({ length: 30 }, (_, i) =>
    kase(`CASE-shut-${String(i).padStart(2, "0")}`, { state: "closed", verdict: "malicious", closed_at: at(-(i + 1) * hour) }),
  ),
];

const rowKeys = () =>
  [...document.querySelectorAll("tbody tr[data-row-key]")].map((r) => r.getAttribute("data-row-key"));

describe("the Cases screen", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("opens on All, with open cases first, worst first", async () => {
    serve(CASES);
    show();
    await screen.findByText("Leaked key in use");
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["All5", "Investigating1", "Contained1", "Closed3"]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(rowKeys()).toEqual([
      "CASE-open-critical",
      "CASE-open-high",
      "CASE-closed-fp",
      "CASE-closed-attack",
      "CASE-closed-old",
    ]);
  });

  it("draws one badge per row, a disposition on closed rows, and a telescope for a hunt", async () => {
    serve(CASES);
    show();
    await screen.findByText("Leaked key in use");
    for (const tr of document.querySelectorAll("tbody tr[data-row-key]")) {
      expect(tr.querySelectorAll(".sh-badge")).toHaveLength(1);
      // One time, at every width: how long it has been open, or how long ago it closed.
      expect(tr.textContent).toMatch(/\d+[mhd]$/);
    }
    const critical = document.querySelector('tr[data-row-key="CASE-open-critical"]') as HTMLElement;
    expect(within(critical).getByText("critical")).toBeInTheDocument();
    expect(within(critical).getByRole("img", { name: "hunt" })).toBeInTheDocument();
    const fp = document.querySelector('tr[data-row-key="CASE-closed-fp"]') as HTMLElement;
    expect(within(fp).getByText("rule was wrong")).toBeInTheDocument();
    expect(within(fp).getByRole("img", { name: "Closed by the crew" })).toBeInTheDocument();
  });

  it("says Critical with no number when an open case is critical", async () => {
    serve(CASES);
    show();
    await screen.findByText("Leaked key in use");
    const state = document.querySelector(".sh-strip__state") as HTMLElement;
    expect(state).toHaveTextContent(/^Critical$/);
  });

  it("filters a closed, malicious slice since a time to exactly that slice", async () => {
    serve(CASES);
    show(`/cases?tab=closed&verdict=malicious&since=${encodeURIComponent(at(-7 * day))}`);
    await screen.findAllByText(/case CASE-closed-attack/);
    expect(rowKeys()).toEqual(["CASE-closed-attack"]);
  });

  it("lands on All with open cases only when a fact is pressed, so the list reproduces its number from any tab", async () => {
    serve(CASES);
    for (const from of ["/cases?tab=closed&by=human", "/cases?tab=contained&q=third"]) {
      const view = show(from);
      await screen.findByRole("button", { name: /^1\s*critical$/ });
      await userEvent.click(screen.getByRole("button", { name: /^1\s*critical$/ }));
      expect(screen.getAllByRole("tab")[0]).toHaveAttribute("aria-selected", "true");
      expect(rowKeys()).toEqual(["CASE-open-critical"]);
      expect(screen.getByRole("button", { name: /^1\s*critical$/ })).toHaveAttribute("aria-pressed", "true");
      view.unmount();
    }
  });

  it("lifts a pressed fact on a tab change, so Closed never inherits state open", async () => {
    serve(CASES);
    show();
    await userEvent.click(await screen.findByRole("button", { name: /^1\s*critical$/ }));
    expect(rowKeys()).toEqual(["CASE-open-critical"]);
    await userEvent.click(screen.getByRole("tab", { name: /Closed/ }));
    expect(rowKeys()).toEqual(["CASE-closed-fp", "CASE-closed-attack", "CASE-closed-old"]);
  });

  it("draws a fact that counts nothing as a plain fact, not a filter to an empty list", async () => {
    serve(CASES);
    show();
    expect(await screen.findByRole("button", { name: /^1\s*critical$/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /stalled/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /crew working/ })).toBeNull();
  });

  it("lands on the first page of a new tab or filter", async () => {
    serve(MANY);
    show();
    await screen.findByText("case CASE-open-00");
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(range()).toBe("26–50 of 60");
    await userEvent.click(screen.getByRole("tab", { name: /Closed/ }));
    expect(range()).toBe("1–25 of 30");
    await userEvent.click(screen.getByRole("tab", { name: /All/ }));
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    await userEvent.type(screen.getByPlaceholderText("Filter cases"), "case");
    await waitFor(() => expect(range()).toBe("1–25 of 60"));
  });

  it("holds page two's order when a case opens there, and sorts it in back on page one", async () => {
    const rows = [...MANY];
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    serve(rows);
    show("/cases", client);
    await screen.findByText("case CASE-open-00");
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    const before = rowKeys();
    rows.unshift(kase("CASE-arrived", { severity: "critical", state: "triage", opened_at: at(0), updated_at: at(0) }));
    await act(() => client.refetchQueries());
    await waitFor(() => expect(screen.getAllByRole("tab")[0]).toHaveTextContent("All61"));
    expect(rowKeys()).toEqual(before);
    await userEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(rowKeys()[0]).toBe("CASE-arrived");
  });

  it("draws no facts when no case is open, only the state", async () => {
    serve([kase("CASE-x", { state: "closed", severity: "critical", closed_at: at(-3 * hour) })]);
    show();
    await screen.findByText("case CASE-x");
    expect(document.querySelector(".sh-strip__state")).toHaveTextContent(/^No open cases$/);
    expect(document.querySelector(".sh-strip__facts")).toBeNull();
  });

  it("names the text in the box when a filtered list comes up empty", async () => {
    serve(CASES);
    show("/cases?tab=contained&severity=critical&q=nomatchxyz");
    const empty = await screen.findByText("No case matches");
    expect(empty.closest(".sh-empty")).toHaveTextContent("“nomatchxyz”");
  });

  it("names its columns", async () => {
    serve(CASES);
    show();
    await screen.findByText("Leaked key in use");
    expect(screen.getAllByRole("columnheader").map((th) => th.textContent)).toEqual(["Crew", "Severity", "Case"]);
  });

  it("reads Can't tell with tab counts unknown and Retry when case.list fails, never an empty queue", async () => {
    serve(new Error("the store did not answer"));
    show();
    expect(await screen.findByText("Can't tell")).toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["All—", "Investigating—", "Contained—", "Closed—"]);
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThan(0);
    expect(screen.queryByText("No cases yet")).toBeNull();
  });

  it("names an empty tab for what it holds", async () => {
    serve([kase("CASE-x", { state: "closed", closed_at: at(-3 * hour) })]);
    show("/cases?tab=investigating");
    expect(await screen.findByText("No open investigations")).toBeInTheDocument();
    expect(screen.getByText("last closed 3h ago")).toBeInTheDocument();
  });
});
