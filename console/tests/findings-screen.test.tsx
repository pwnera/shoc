import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation, useNavigationType, type InitialEntry } from "react-router-dom";
import { Findings } from "@/routes/Findings";
import { Finding } from "@/routes/Finding";
import { groupFindings, observed, sourceOf, stepOrder } from "@/routes/findings/group";
import { runCommand } from "@/lib/commands";
import type { Finding as FindingRow } from "@/types";

// New findings arrive through the stream; the test sets how many arrived.
let fresh = 0;
const resetFresh = vi.fn(() => {
  fresh = 0;
});
vi.mock("@/lib/live", async (load) => ({
  ...(await load<typeof import("@/lib/live")>()),
  useNewFindings: () => [fresh, resetFresh],
}));

const hour = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
// One instant for every default, so two findings made a millisecond apart never sort apart.
const TWO_HOURS_AGO = hour(2);

function finding(uid: string, over: Partial<FindingRow> = {}): FindingRow {
  return {
    finding_uid: uid,
    rule_id: "aws_root_login",
    title: "Root account signed in",
    severity: "high",
    confidence: 0.8,
    status: "new",
    entity_key: "user:root",
    first_seen: TWO_HOURS_AGO,
    last_seen: TWO_HOURS_AGO,
    event_count: 1,
    event_uids: ["e1"],
    attack: ["T1078"],
    evidence: {},
    ...over,
  };
}

const ROWS = [
  finding("F-1", { last_seen: hour(1) }),
  finding("F-2", { last_seen: hour(3), severity: "critical" }),
  finding("F-3", { rule_id: "gws_oauth", title: "OAuth app granted", entity_key: "alice@example.com", status: "self" }),
  finding("F-4", { rule_id: "okta_mfa_reset", title: "MFA reset", severity: "medium", status: "closed" }),
];

type Handler = (input: Record<string, unknown>) => { status?: number; data?: unknown; error?: string };
let handlers: Record<string, Handler> = {};
const calls: { path: string; body: Record<string, unknown> }[] = [];

function serve() {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const path = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      calls.push({ path, body });
      const answer = handlers[path]?.(body) ?? { data: { rows: [], count: 0 } };
      const status = answer.status ?? 200;
      const payload = status >= 400 ? { error: { code: "boom", message: answer.error ?? "failed" } } : { data: answer.data, summary: "", citations: [] };
      return Promise.resolve(new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } }));
    }),
  );
}

/** How the router got to where it is: "PUSH /findings", "POP /findings?since=24h". */
function Where() {
  const { pathname, search } = useLocation();
  return <output aria-label="where">{`${useNavigationType()} ${pathname}${search}`}</output>;
}

function show(path: string | InitialEntry[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const entries = typeof path === "string" ? [path] : path;
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}>
        <Routes>
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:findingUid" element={<Finding />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.length = 0;
  handlers = { "finding.list": () => ({ data: { rows: ROWS, count: ROWS.length } }) };
  serve();
});
afterEach(() => vi.unstubAllGlobals());

describe("findings as signals", () => {
  it("groups by rule and entity, worst severity, newest first", () => {
    const signals = groupFindings(ROWS);
    expect(signals.map((s) => s.key)).toEqual(["aws_root_login|user:root", "gws_oauth|alice@example.com", "okta_mfa_reset|user:root"]);
    expect(signals[0]!.severity).toBe("critical");
    expect(signals[0]!.findings.map((f) => f.finding_uid)).toEqual(["F-1", "F-2"]);
    expect(stepOrder(signals).slice(0, 2)).toEqual(["F-1", "F-2"]);
  });

  it("links a hunt's finding to its pack, an indicator hit to its indicator and a rule's to its page", () => {
    expect(sourceOf({ rule_id: "hunt:okta_first_login_country", evidence: {} }).href).toBe("/hunts?pack=okta_first_login_country");
    expect(sourceOf({ rule_id: "aws_root_login", evidence: {} }).href).toBe("/detection/rules/aws_root_login");
    const hit = sourceOf({ rule_id: "hunt:ip", evidence: { indicator: { type: "ip", value: "198.51.100.9" } } });
    expect(hit).toEqual({ label: "Indicator", href: "/intel?type=ip&q=198.51.100.9&ioc=198.51.100.9" });
  });

  it("reads an older hunt's observations as distinct fields", () => {
    const line = { summary: "actor.user.name=a@example.com, src_endpoint.location.country=United States, http.user_agent=x, y" };
    expect(observed([line, line])).toEqual([
      ["actor.user.name", "a@example.com"],
      ["src_endpoint.location.country", "United States"],
      ["http.user_agent", "x, y"],
    ]);
    expect(observed(undefined)).toEqual([]);
  });
});

describe("the Findings screen", () => {
  it("opens on Open, with grouped rows and set-aside findings out of the way", async () => {
    show("/findings");
    await screen.findByText("Root account signed in");
    const table = document.querySelector<HTMLElement>('table[aria-label="Findings"]')!;
    expect(within(table).getByText("×2")).toBeInTheDocument();
    expect(within(table).queryByText("OAuth app granted")).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Open/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /Set aside/ })).toHaveTextContent("1");
    // The tab counts findings, as every other screen does; the pager says how many rows hold them.
    expect(screen.getByRole("tab", { name: /Open/ })).toHaveTextContent(/^Open\s*2$/);
    expect(screen.getByText(/1–1/).parentElement).toHaveTextContent("1–1 of 1 group · 2 findings");
    // The strip's word is the tab's: "Open", in warn while a high or critical is.
    expect(document.querySelector(".sh-strip__state")).toHaveTextContent("Open");
    expect(document.querySelector(".sh-strip__state")).toHaveAttribute("data-tone", "warn");
    expect(within(table).getAllByRole("columnheader").map((th) => th.textContent)).toEqual(["Severity", "Finding"]);
    // The state word speaks for open findings only.
    fireEvent.click(screen.getByRole("tab", { name: /Set aside/ }));
    expect(document.querySelector(".sh-strip__state")).toBeNull();
  });

  it("counts the findings of the groups each severity fact shows, as the tabs do", async () => {
    show("/findings");
    await screen.findByText("Root account signed in");
    // One open group, critical at its worst: a high and a critical finding of one rule on one entity.
    expect(screen.getByRole("button", { name: /critical/ })).toHaveTextContent(/^2\s*critical$/);
    expect(screen.getByRole("button", { name: /high/ })).toHaveTextContent(/^0\s*high$/);
    fireEvent.click(screen.getByRole("button", { name: /high/ }));
    expect(await screen.findByText("No findings match")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Open/ })).toHaveTextContent(/^Open\s*0$/);
    fireEvent.click(screen.getByRole("button", { name: /critical/ }));
    expect(await screen.findByText("Root account signed in")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Open/ })).toHaveTextContent(/^Open\s*2$/);
  });

  it("trades a hunt's prefix for a telescope", async () => {
    handlers["finding.list"] = () => ({ data: { rows: [finding("F-5", { title: "Hunt: Somebody signs in from afar" })], count: 1 } });
    show("/findings");
    const row = (await screen.findByText("Somebody signs in from afar")).closest("tr")!;
    expect(within(row).getByRole("img", { name: "hunt" })).toBeInTheDocument();
    expect(screen.queryByText(/Hunt:/)).not.toBeInTheDocument();
  });

  it("keeps the rows on screen when a refresh fails, and says how old they are", async () => {
    show("/findings");
    await screen.findByText("Root account signed in");
    handlers["finding.list"] = () => ({ status: 500, error: "store down" });
    fresh = 2;
    fireEvent.click(screen.getByRole("tab", { name: /Handled/ }));
    fireEvent.click(screen.getByRole("tab", { name: /Open/ }));
    fireEvent.click(await screen.findByRole("button", { name: /2 new/ }));
    expect(await screen.findByText(/^as of /)).toBeInTheDocument();
    expect(screen.getByText("Root account signed in")).toBeInTheDocument();
    expect(screen.queryByText("store down")).not.toBeInTheDocument();
    fresh = 0;
  });

  it("sends the rule and the entity to the kernel, 500 at most", async () => {
    show("/findings?rule=aws_root_login&on=user%3Aroot&since=24h");
    await screen.findByText("Root account signed in");
    const asked = calls.find((c) => c.path === "finding.list")!.body;
    expect(asked).toMatchObject({ rule_id: "aws_root_login", entity: "user:root", since: "-24h", limit: 500 });
    expect(screen.getAllByText("aws_root_login").length).toBeGreaterThan(0);
  });

  it("holds new findings behind a pill until asked, then refetches", async () => {
    show("/findings");
    await screen.findByText("Root account signed in");
    const lists = () => calls.filter((c) => c.path === "finding.list").length;
    const before = lists();
    fresh = 2;
    fireEvent.click(screen.getByRole("tab", { name: /Handled/ }));
    fireEvent.click(screen.getByRole("tab", { name: /Open/ }));
    const pill = await screen.findByRole("button", { name: /2 new/ });
    expect(lists()).toBe(before);
    expect(screen.getByText("Root account signed in")).toBeInTheDocument();
    fireEvent.click(pill);
    expect(resetFresh).toHaveBeenCalled();
    await waitFor(() => expect(lists()).toBe(before + 1));
    fresh = 0;
  });

  it("never reads all clear when the list fails", async () => {
    handlers["finding.list"] = () => ({ status: 500, error: "store down" });
    show("/findings");
    expect(await screen.findByText("Can't tell")).toBeInTheDocument();
    expect(screen.queryByText("Nothing open")).not.toBeInTheDocument();
    expect(screen.getAllByText("store down").length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(1);
  });
});

describe("the finding page", () => {
  it("shows the match, the rule, and the case the Sentinel attached it to", async () => {
    const f = finding("F-9", {
      evidence: {
        kind: "match",
        sample: { actor_user_name: "root", src_endpoint_ip: "203.0.113.7", time: hour(2) },
        sentinel: { decision: "attach", case_uid: "CASE-abcdef123456", basis: "entity" },
      },
    });
    handlers["finding.get"] = () => ({ data: { finding: f, events: [], rule: {} } });
    show("/findings/F-9");
    expect(await screen.findByRole("heading", { level: 1, name: "Root account signed in" })).toBeInTheDocument();
    expect(screen.getByText("Actor")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /CASE-abcd/ })[0]).toHaveAttribute("href", "/cases/CASE-abcdef123456");
    expect(screen.getByRole("radiogroup", { name: "Status" })).toBeInTheDocument();
  });

  it("shows a set-aside status beside the control and no empty match card", async () => {
    const f = finding("F-8", { rule_id: "hunt:ip", status: "self", evidence: { kind: "hunt", pack_id: "ip" } });
    handlers["finding.get"] = () => ({ data: { finding: f, events: [], rule: {} } });
    handlers["finding.list"] = () => ({ data: { rows: [f], count: 1 } });
    show("/findings/F-8");
    const status = await screen.findByRole("radiogroup", { name: "Status" });
    // The status no segment sets leads the control, checked, so the control never shows nothing picked.
    expect(within(status).getByRole("radio", { name: "shoc's own" })).toHaveAttribute("aria-checked", "true");
    expect(screen.queryByRole("heading", { name: "Match" })).not.toBeInTheDocument();
    // Siblings leave the finding itself out.
    expect(await screen.findByText("none")).toBeInTheDocument();
  });

  it("shows a hunt's observed values with its verdict word, never its prose", async () => {
    const f = finding("F-7", {
      rule_id: "hunt:okta_first_login_country",
      evidence: {
        kind: "hunt",
        triage: "SUSPICIOUS: The logs show logins from a new country.",
        observations: [{ entity: "a@example.com", summary: "actor.user.name=a@example.com, src_endpoint.ip=203.0.113.7" }],
      },
    });
    handlers["finding.get"] = () => ({ data: { finding: f, events: [], rule: {} } });
    show("/findings/F-7");
    expect(await screen.findByRole("heading", { name: "Match" })).toBeInTheDocument();
    expect(screen.getByText("Source IP")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("suspicious")).toBeInTheDocument();
    expect(screen.queryByText(/The logs show/)).not.toBeInTheDocument();
  });

  it("goes back to the list that opened it on Escape, and to Findings otherwise", async () => {
    handlers["finding.get"] = () => ({ data: { finding: ROWS[0], events: [], rule: {} } });
    const opened = { pathname: "/findings/F-1", state: { uids: ["F-1", "F-2"], index: 0, back: "/findings?since=24h" } };
    const { unmount } = show(["/findings?since=24h", opened]);
    await screen.findByRole("heading", { level: 1, name: "Root account signed in" });
    act(() => void runCommand("shell.escape"));
    expect(await screen.findByLabelText("where")).toHaveTextContent("POP /findings?since=24h");
    unmount();

    show("/findings/F-1");
    await screen.findByRole("heading", { level: 1, name: "Root account signed in" });
    act(() => void runCommand("shell.escape"));
    await waitFor(() => expect(screen.getByLabelText("where")).toHaveTextContent("PUSH /findings"));
  });

  it("says so when the finding does not exist", async () => {
    handlers["finding.get"] = () => ({ status: 404, error: "no finding" });
    show("/findings/F-missing");
    expect(await screen.findByText("No finding F-miss…")).toBeInTheDocument();
  });
});
