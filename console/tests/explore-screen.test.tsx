import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation, useNavigationType } from "react-router-dom";
import { Explore } from "@/routes/Explore";
import { buckets, kernelSince, rangeLabel, relativeMs, tidy, windowOf } from "@/routes/explore/query";

const ROWS = Array.from({ length: 100 }, (_, i) => ({
  event_uid: `e${i}`,
  time: new Date(Date.now() - i * 60_000).toISOString(),
  api_operation: `Op${i}`,
  actor_user_name: "deploy-ci",
  src_endpoint_ip: "203.0.113.55",
  status: i % 10 === 0 ? "Failure" : "Success",
  metadata_product: "AWS CloudTrail",
}));

const calls: { path: string; body: Record<string, unknown> }[] = [];

function serve() {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const path = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      calls.push({ path, body });
      if (String(body.q ?? "").includes("nosuch.field"))
        return Promise.resolve(
          new Response(JSON.stringify({ error: { code: "bad_query", message: "unknown field nosuch.field" } }), {
            status: 400,
            headers: { "content-type": "application/json" },
          }),
        );
      const data =
        path === "events.query"
          ? { rows: ROWS, count: 100, truncated: false, sql: "SELECT 1" }
          : body.by === "time"
            ? { by: "time", interval: "hour", rows: [{ key: new Date().toISOString(), count: 1707 }], total: 1707, sql: "" }
            : { by: body.by, interval: "", rows: [{ key: "deploy-ci", count: 1500 }], total: 1707, sql: "" };
      return Promise.resolve(
        new Response(JSON.stringify({ data, summary: "", citations: [] }), { status: 200, headers: { "content-type": "application/json" } }),
      );
    }),
  );
}

let where = "";
let how = "";
function Where() {
  const location = useLocation();
  where = `${location.pathname}${location.search}`;
  how = useNavigationType();
  return null;
}

function show(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/explore"
            element={
              <>
                <Explore />
                <Where />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.length = 0;
  try {
    localStorage.clear();
  } catch {
    /* none */
  }
  serve();
});
afterEach(() => vi.unstubAllGlobals());

describe("Explore's windows", () => {
  it("reads relative and absolute windows alike", () => {
    expect(relativeMs("7d")).toBe(7 * 86_400_000);
    expect(relativeMs("-15m")).toBe(900_000);
    expect(relativeMs("2026-10-01T00:00:00Z")).toBeNull();
    expect(tidy("-24h")).toBe("24h");
    expect(kernelSince("24h")).toBe("-24h");
    expect(kernelSince("2026-10-01T00:00:00Z")).toBe("2026-10-01T00:00:00Z");
    expect(windowOf("1h", "", 10_000_000)).toEqual({ from: 10_000_000 - 3_600_000, to: 10_000_000 });
  });

  it("labels a range on the 24-hour clock, with the end's day when it differs", () => {
    expect(rangeLabel("2026-10-02T10:00:00")).toBe("Fri 2 Oct 10:00");
    expect(rangeLabel("2026-10-02T10:00:00", "2026-10-02T14:30:00")).toBe("Fri 2 Oct 10:00 → 14:30");
    expect(rangeLabel("2026-10-02T10:00:00", "2026-10-03T10:00:00")).toBe("Fri 2 Oct 10:00 → Sat 3 Oct 10:00");
  });

  it("draws every bucket of the window and stacks failures under the rest", () => {
    const from = Date.parse("2026-10-01T10:00:00Z");
    const bars = buckets(
      [
        { key: "2026-10-01T10:00:00Z", count: 5 },
        { key: "2026-10-01T12:00:00Z", count: 3 },
      ],
      [{ key: "2026-10-01T12:00:00Z", count: 2 }],
      "hour",
      { from, to: from + 3 * 3_600_000 },
    );
    expect(bars).toHaveLength(3);
    expect(bars.map((b) => b.parts.map((p) => p.value))).toEqual([
      [0, 5],
      [0, 0],
      [2, 1],
    ]);
  });
});

describe("the Explore screen", () => {
  it("shows at most 50 rows, counts the whole match, and asks for 300 buckets", async () => {
    show("/explore?q=actor.user.name%3Ddeploy-ci&since=7d");
    expect(await screen.findByText("Op0")).toBeInTheDocument();
    expect(screen.getAllByRole("row").filter((r) => /Op\d+/.test(r.textContent ?? ""))).toHaveLength(50);
    expect(screen.getByText(/1–50/).parentElement).toHaveTextContent(/^1–50 of newest 100$/);
    // The match total has one home, the strip; the footer and the field rail read against it.
    await waitFor(() => expect(screen.getByText("matched").parentElement).toHaveTextContent("1,707"));
    expect(screen.queryByText(/of 1,707|1,707 matched/)).toBeNull();
    const summarize = calls.filter((c) => c.path === "events.summarize" && c.body.by === "time");
    expect(summarize.length).toBeGreaterThan(0);
    expect(summarize.every((c) => c.body.limit === 300 && c.body.since === "-7d")).toBe(true);
    expect(calls.find((c) => c.path === "events.query")!.body).toMatchObject({ q: "actor.user.name=deploy-ci", limit: 100 });
  });

  it("shows a refused query's reason with no retry, which could never succeed", async () => {
    show("/explore?q=nosuch.field%3Dx");
    expect((await screen.findAllByText("unknown field nosuch.field")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
  });

  it("turns a typed term into a chip and runs it into the URL", async () => {
    show("/explore");
    const box = await screen.findByLabelText("Query");
    fireEvent.change(box, { target: { value: "status!=Success " } });
    const search = screen.getByRole("search");
    expect(within(search).getByText("status")).toBeInTheDocument();
    fireEvent.submit(search);
    await waitFor(() => expect(where).toContain("q=status%21%3DSuccess"));
  });

  it("adds a field value to the running query once", async () => {
    show("/explore?q=deploy");
    const only = await screen.findAllByRole("button", { name: "Only deploy-ci" });
    // The second pinned field is actor.user.name (the first is the product).
    fireEvent.click(only[1]!);
    await waitFor(() => expect(new URLSearchParams(where.split("?")[1]).get("q")).toBe("deploy actor.user.name=deploy-ci"));
    expect(how).toBe("PUSH");
    fireEvent.click((await screen.findAllByRole("button", { name: "Only deploy-ci" }))[1]!);
    // The same query again replaces its entry, so Back never lands on a twin.
    await waitFor(() => expect(how).toBe("REPLACE"));
    expect(new URLSearchParams(where.split("?")[1]).get("q")).toBe("deploy actor.user.name=deploy-ci");
  });
});
