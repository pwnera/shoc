import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation, useNavigate, type InitialEntry } from "react-router-dom";
import { Detection } from "@/routes/Detection";
import { Rule as RulePage } from "@/routes/Rule";
import { BacklogDialog } from "@/routes/detection/BacklogDialog";
import { byAttention, decisionOf, mergedRule, ruleHref, sameEntity, segmentOf, type RuleRow } from "@/routes/detection/state";
import { yaml, yamlText } from "@/routes/rule/yaml";
import type { BacklogItem, Rule, RuleHealth, Suppression } from "@/types";

function rule(id: string, severity: Rule["severity"] = "high", product = "aws"): Rule {
  return {
    id,
    title: `Title of ${id}`,
    severity,
    description: "",
    status: "stable",
    confidence: 0.6,
    attack: ["T1098.003"],
    logsource: { product },
    timeframe: "15m",
    group_by: [],
    count: "",
    entity: "actor.user.name",
    detection: { selection: { "api.operation": "CreateAccessKey" }, condition: "selection" },
    fields: [],
    created: null,
    updated: null,
  };
}

function health(rule_id: string, over: Partial<RuleHealth> = {}): RuleHealth {
  return {
    rule_id,
    findings_7d: 0,
    cases_7d: 0,
    suppressed_7d: 0,
    self_7d: 0,
    false_positives_7d: 0,
    closed_30d: {},
    tokens_30d: 0,
    last_fired: null,
    error: null,
    noisy: false,
    silent: true,
    silent_reason: "not_ingested",
    ...over,
  };
}

function item(over: Partial<BacklogItem> = {}): BacklogItem {
  return {
    item_uid: "DBL-1",
    rule_id: "",
    kind: "coverage",
    intake: "cti",
    title: "no rule maps to T1585",
    reason: "",
    priority: 4,
    observability: "partial",
    evidence: {},
    case_uid: "",
    state: "open",
    created_at: "2026-10-03T00:00:00Z",
    ...over,
  };
}

const RULES = [rule("quiet_one", "medium"), rule("broken", "low"), rule("live_one", "critical"), rule("blind", "high")];
const HEALTH = [
  health("quiet_one", { silent_reason: "quiet" }),
  health("broken", { error: "bad SQL", silent: false, silent_reason: "" }),
  health("live_one", {
    findings_7d: 3,
    silent: false,
    silent_reason: "",
    last_fired: "2026-10-03T10:00:00Z",
    closed_30d: { malicious: 2, needs_human: 1 },
  }),
  health("blind"),
];

const MUTED: Suppression = {
  suppression_uid: "SUP-1",
  rule_id: "live_one",
  entity: "user:jane@example.com",
  reason: "rotation job",
  created_by: "human:jane",
  created_at: "2026-10-01T00:00:00Z",
  expires_at: "2026-10-20T00:00:00Z",
  case_uid: "",
  state: "active",
};

let failHealth = false;
let backlog: Record<string, BacklogItem[]> = {};
let muted: Suppression[] = [];
let catalogue = RULES;
const answers: Record<string, (body: Record<string, unknown>) => unknown> = {
  "rule/list": () => ({ rules: catalogue, count: catalogue.length }),
  "health/rules": () => ({ rules: HEALTH, ok: true }),
  "detection/backlog": (body) => {
    const items = backlog[String(body.state ?? "open")] ?? [];
    return { items, count: items.length, by_intake: {}, not_observable: 0 };
  },
  "suppression/list": () => ({ suppressions: muted, count: muted.length, expired: 0 }),
  "hunt/results": () => ({ runs: [], count: 0, metrics: {}, readiness: [] }),
};

/** The URL, and the browser's Back, for the history tests. */
function Where() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <button type="button" data-testid="where" onClick={() => navigate(-1)}>
      {location.pathname + location.search}
    </button>
  );
}

function show(path: string | InitialEntry[] = "/detection") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const entries = typeof path === "string" ? [path] : path;
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}>
        <Routes>
          <Route path="/detection" element={<Detection />} />
          <Route path="/detection/rules/:ruleId" element={<RulePage />} />
          <Route path="*" element={null} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the Detection screen", () => {
  beforeEach(() => {
    failHealth = false;
    backlog = {};
    muted = [];
    catalogue = RULES;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        const name = String(url).replace(/^.*\/v1\//, "");
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
        if (name === "health/rules" && failHealth)
          return Promise.resolve(new Response(JSON.stringify({ error: { code: "error", message: "store down" } }), { status: 500 }));
        const data = answers[name]?.(body) ?? {};
        return Promise.resolve(new Response(JSON.stringify({ data, summary: "", citations: [] }), { status: 200 }));
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("splits every rule into one state, labels only the states that hold rules, and has no Health tab", async () => {
    show();
    const share = await screen.findByRole("group", { name: "Rules by state" });
    const segments = within(share).getAllByRole("button");
    const counts = segments.map((s) => Number(s.getAttribute("aria-label")!.split(" ")[0]));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(RULES.length);
    expect(counts.every((n) => n > 0)).toBe(true);
    expect(screen.getByText("Failing")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /Health/ })).not.toBeInTheDocument();
  });

  it("lists the rules that need a look first: failing, live, armed, no source", async () => {
    show();
    await screen.findByRole("group", { name: "Rules by state" });
    const rows = within(screen.getByRole("grid", { name: "Rules" })).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.getAttribute("data-row-key"))).toEqual(["broken", "live_one", "quiet_one", "blind"]);
  });

  it("filters to a state from the URL", async () => {
    show("/detection?state=live");
    await screen.findByRole("group", { name: "Rules by state" });
    const rows = within(screen.getByRole("grid", { name: "Rules" })).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.getAttribute("data-row-key"))).toEqual(["live_one"]);
  });

  it("never reads all clear when health.rules fails", async () => {
    failHealth = true;
    show();
    expect(await screen.findByText("Can't tell")).toBeInTheDocument();
    expect(screen.queryByText("Live")).not.toBeInTheDocument();
    expect(screen.queryByText("Blind")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole("row").length).toBe(RULES.length + 1));
    expect(screen.queryByText("never")).not.toBeInTheDocument();
  });

  it("partitions Changes into Open, Source gaps, Accepted and Closed, and says when nothing waits", async () => {
    show("/detection?tab=changes");
    const radios = await screen.findAllByRole("radio");
    expect(radios.map((r) => r.textContent?.replace(/\d+$/, ""))).toEqual(["Open", "Source gaps", "Accepted", "Closed"]);
    expect(await screen.findByText("No open changes")).toBeInTheDocument();
  });

  it("opens a backlog item from its link on the slice that holds it", async () => {
    backlog = { done: [item({ item_uid: "DBL-9", state: "done", title: "narrow the CI rule" })] };
    show("/detection?tab=changes&item=DBL-9");
    expect(await screen.findByRole("heading", { name: "narrow the CI rule", hidden: true })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("radio", { name: /Closed/ })).toHaveAttribute("aria-checked", "true"));
  });

  it("opens a suppression from ?suppression= with the reason once and the dated creation", async () => {
    muted = [MUTED];
    show("/detection?tab=suppressions&suppression=SUP-1");
    expect(await screen.findByText("rotation job")).toBeInTheDocument();
    expect(screen.getByText("Created", { exact: true })).toBeInTheDocument();
  });

  it("closes a popup it opened by going back, so Back never reopens it", async () => {
    muted = [MUTED];
    show("/detection?tab=suppressions");
    fireEvent.click(await screen.findByText("Title of live_one"));
    expect(screen.getByTestId("where")).toHaveTextContent("suppression=SUP-1");
    fireEvent.click(screen.getByRole("button", { name: "Close", hidden: true }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/detection\?tab=suppressions$/));
    fireEvent.click(screen.getByTestId("where"));
    await waitFor(() => expect(screen.queryByText("rotation job")).not.toBeInTheDocument());
    expect(screen.getByTestId("where")).toHaveTextContent(/^\/detection\?tab=suppressions$/);
  });

  it("closes a popup a link opened in place, so Back leaves for where the link was", async () => {
    muted = [MUTED];
    show(["/", "/detection?tab=suppressions&suppression=SUP-1"]);
    expect(await screen.findByText("rotation job")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close", hidden: true }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/detection\?tab=suppressions$/));
    fireEvent.click(screen.getByTestId("where"));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/$/));
  });

  it("comes back from a rule on the page that holds it, its row active", async () => {
    catalogue = [...RULES, ...Array.from({ length: 30 }, (_, i) => rule(`r${String(i).padStart(2, "0")}`, "low"))];
    show([{ pathname: "/detection", state: { row: "r27" } }]);
    await waitFor(() => expect(document.querySelector("[data-active]")).toHaveAttribute("data-row-key", "r27"));
    expect(screen.getByText(/^26–/)).toBeInTheDocument();
  });

  it("captions the rule's verdict share and keeps verdicts outside the four", async () => {
    show("/detection/rules/live_one");
    const share = await screen.findByRole("img", { name: /Closed cases in 30 days by verdict/ });
    expect(share.getAttribute("aria-label")).toMatch(/2 attack.*1 undecided/);
    expect(screen.getByText("verdicts 30d")).toBeInTheDocument();
    expect(within(share).queryAllByRole("button")).toHaveLength(0);
  });
});

describe("the backlog dialog", () => {
  const wrap = (ui: React.ReactElement) =>
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>{ui}</MemoryRouter>
      </QueryClientProvider>,
    );

  it("offers Revert only on a merged item with a rule", () => {
    const merged = item({ state: "done", evidence: { decision: "merged", rule_id: "narrowed_rule", because: "too loud" } });
    const { unmount } = wrap(<BacklogDialog item={merged} onClose={() => {}} />);
    expect(screen.getByRole("button", { name: "Revert", hidden: true })).toBeInTheDocument();
    expect(screen.getByText("too loud")).toBeInTheDocument();
    unmount();
    wrap(<BacklogDialog item={item({ state: "rejected", evidence: { decision: "source_gap" } })} onClose={() => {}} />);
    expect(screen.queryByRole("button", { name: "Revert", hidden: true })).not.toBeInTheDocument();
    expect(screen.getByText("source gap")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reopen", hidden: true })).toBeInTheDocument();
  });

  it("asks why before it rejects, and sends the reason with the decision", async () => {
    const decided: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (String(url).endsWith("/detection/decide")) decided.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return Promise.resolve(new Response(JSON.stringify({ data: { rows: [] }, summary: "", citations: [] })));
      }),
    );
    wrap(<BacklogDialog item={item()} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Reject", hidden: true }));
    const why = screen.getByRole("textbox", { name: "Reason", hidden: true });
    const go = within(why.closest("form")!).getByRole("button", { name: "Reject", hidden: true });
    expect(go).toBeDisabled();
    expect(decided).toEqual([]);
    fireEvent.change(why, { target: { value: "we run no Active Directory" } });
    fireEvent.click(go);
    await waitFor(() =>
      expect(decided).toEqual([{ item_uid: "DBL-1", state: "rejected", reason: "we run no Active Directory" }]),
    );
    vi.unstubAllGlobals();
  });

  it("says what the report saw, what would show it and whether we receive it, and who took a merged rule back", () => {
    const fromReport = item({
      evidence: { technique: "T1560.001", report_uid: "RPT-1" },
      context: {
        techniques: [{ id: "T1560.001", name: "Archive Collected Data: Archive via Utility" }],
        reports: [
          {
            report_uid: "RPT-1",
            title: "The First 24 Hours",
            relevance: "Ransomware crews hit companies this size through their VPN",
            said: [{ technique: "T1560.001", procedure: "WinRAR packed the file share before RClone sent it out" }],
          },
          { report_uid: "RPT-2", title: "Another write-up", relevance: "", said: [] },
        ],
        seen_in: [
          {
            kind: "process",
            label: "process starts",
            products: [{ source: "crowdstrike_fdr", product: "CrowdStrike Falcon Data Replicator" }],
            received: [],
          },
        ],
        rules: [{ id: "bulk_download", title: "Bulk download from a file share", live: false }],
        packs: [],
        cases: [{ case_uid: "CASE-1", title: "Archive on the file server" }],
      },
    });
    const { unmount } = wrap(<BacklogDialog item={fromReport} onClose={() => {}} />);
    expect(screen.getByText("No rule for Archive Collected Data: Archive via Utility")).toBeInTheDocument();
    expect(screen.getByText("WinRAR packed the file share before RClone sent it out")).toBeInTheDocument();
    expect(screen.getByText("Ransomware crews hit companies this size through their VPN")).toBeInTheDocument();
    expect(screen.getByText("not received")).toBeInTheDocument();
    const connect = screen.getAllByRole("link", { hidden: true }).find((a) => a.getAttribute("href") === "/connections?add=crowdstrike_fdr");
    expect(connect).toBeDefined();
    expect(screen.getByText("Bulk download from a file share")).toBeInTheDocument();
    expect(screen.getByText("Archive on the file server")).toBeInTheDocument();
    expect(screen.getByText("Another write-up")).toBeInTheDocument();
    unmount();
    const reverted = item({
      state: "done",
      evidence: {
        decision: "merged",
        rule_id: "narrowed_rule",
        because: "too loud",
        reverted: { by: "human:jane", because: "it hid a real login", at: "2026-10-05T00:00:00Z" },
      },
    });
    wrap(<BacklogDialog item={reverted} onClose={() => {}} />);
    expect(screen.queryByRole("button", { name: "Revert", hidden: true })).not.toBeInTheDocument();
    expect(screen.getByText("it hid a real login")).toBeInTheDocument();
    expect(screen.getByText("too loud")).toBeInTheDocument();
  });

  it("offers Merge only where a merge can answer, and says what the rule's health or the case holds", () => {
    const noisy = item({
      rule_id: "noisy_rule",
      kind: "defect",
      intake: "health",
      title: "noisy_rule: over its volume",
      evidence: { findings_7d: 42, dominant_entity: "user:svc-backup@example.com", share: 0.8 },
    });
    const { unmount } = wrap(<BacklogDialog item={noisy} onClose={() => {}} />);
    expect(screen.queryByRole("button", { name: "Merge", hidden: true })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { hidden: true })).toHaveTextContent("noisy_rule · noisy");
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("80%")).toBeInTheDocument();
    unmount();
    const closed = item({
      rule_id: "noisy_rule",
      kind: "defect",
      intake: "case",
      case_uid: "CASE-1",
      title: "noisy_rule: defect",
      evidence: { entity: "user:jane@example.com", finding_uids: ["FND-1", "FND-2"], closer: "human", reason: "the nightly backup job" },
    });
    wrap(<BacklogDialog item={closed} onClose={() => {}} />);
    expect(screen.getByRole("button", { name: "Merge", hidden: true })).toBeInTheDocument();
    expect(screen.getByText("the nightly backup job")).toBeInTheDocument();
    const findings = screen.getAllByRole("link", { hidden: true }).find((a) => a.getAttribute("href") === "/cases/CASE-1?tab=findings");
    expect(findings).toHaveTextContent("2");
  });

  it("quotes another report beside a link to it when no report raised the item, and leaves why it matters out", () => {
    const fromCrew = item({
      evidence: { technique: "T1105" },
      context: {
        techniques: [{ id: "T1105", name: "Ingress Tool Transfer" }],
        reports: [
          {
            report_uid: "RPT-7",
            title: "Living off the land",
            relevance: "Crews this size get hit this way",
            said: [{ technique: "T1105", procedure: "certutil fetched the payload" }],
          },
        ],
        seen_in: [],
        rules: [],
        packs: [],
        cases: [],
      },
    });
    wrap(<BacklogDialog item={fromCrew} onClose={() => {}} />);
    expect(screen.getByText("certutil fetched the payload")).toBeInTheDocument();
    expect(screen.queryByText("Crews this size get hit this way")).not.toBeInTheDocument();
    const links = screen.getAllByRole("link", { hidden: true }).filter((a) => a.getAttribute("href") === "/intel?tab=reports&report=RPT-7");
    // The quote's link, and "also in".
    expect(links).toHaveLength(2);
  });
});

describe("detection helpers", () => {
  it("puts each backlog item in one slice", () => {
    expect(segmentOf(item())).toBe("open");
    expect(segmentOf(item({ observability: "none" }))).toBe("gaps");
    expect(segmentOf(item({ state: "accepted" }))).toBe("accepted");
    expect(segmentOf(item({ state: "done" }))).toBe("closed");
    expect(segmentOf(item({ state: "rejected", observability: "none" }))).toBe("closed");
  });

  it("reads who decided and why, a later or a reopen as their own words, and the rule a merge made", () => {
    expect(decisionOf(item({ state: "rejected", evidence: { decision: "no_rule", because: "own credentials" } }))).toEqual({
      word: "no rule",
      because: "own credentials",
      by: "Detection Engineer",
    });
    expect(
      decisionOf(item({ state: "rejected", decided_by: "human:rettila", evidence: { decision: "rejected", because: "no AD here" } })),
    ).toEqual({ word: "rejected", because: "no AD here", by: "human:rettila" });
    expect(decisionOf(item({ evidence: { later: "needs a week of data" } }))).toEqual({
      word: "later",
      because: "needs a week of data",
      by: "Detection Engineer",
    });
    // Open again, the decision from before no longer holds.
    expect(decisionOf(item({ evidence: { decision: "source_gap", reopened: "okta now delivers" } }))).toEqual({
      word: "reopened",
      because: "okta now delivers",
      by: null,
    });
    expect(decisionOf(item())).toBeNull();
    expect(mergedRule(item({ evidence: { decision: "merged", rule_id: "r1" } }))).toBe("r1");
    expect(mergedRule(item({ evidence: { decision: "source_gap", rule_id: "r1" } }))).toBeNull();
    expect(mergedRule(item({ evidence: { decision: "merged", rule_id: "r1", reverted: { by: "shoc" } } }))).toBeNull();
  });

  it("sends hunt ids to Hunts and treats user: as the same entity", () => {
    expect(ruleHref("hunt:okta_first_login_country")).toBe("/hunts?pack=okta_first_login_country");
    expect(ruleHref("aws_root_login")).toBe("/detection/rules/aws_root_login");
    expect(sameEntity("user:Jane@acme.test")).toBe(sameEntity("jane@acme.test"));
  });

  it("orders by state, then severity", () => {
    const rows: RuleRow[] = [
      { ...rule("a", "low"), state: "armed" },
      { ...rule("b", "critical"), state: "no_source" },
      { ...rule("c", "critical"), state: "armed" },
    ];
    expect([...rows].sort(byAttention).map((r) => r.id)).toEqual(["c", "a", "b"]);
  });

  it("writes YAML with selection names, keys, modifiers and values told apart", () => {
    const lines = yaml({ selection: { "http_request.user_agent|contains": ["curl", "python"] }, condition: "selection" });
    expect(lines[0]!.find((t) => t.text === "selection")?.ink).toBe("name");
    expect(lines[1]!.find((t) => t.text === "|contains")?.ink).toBe("mod");
    expect(lines[1]!.filter((t) => t.ink === "value").map((t) => t.text)).toEqual(["curl", "python"]);
    expect(yamlText({ a: { b: [{ c: 1 }] } })).toBe("a:\n  b:\n    - c: 1");
  });
});
