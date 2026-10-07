import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Hunts } from "@/routes/Hunts";
import { Intel } from "@/routes/Intel";
import { IntelSources } from "@/routes/connections/IntelSources";
import { Memory } from "@/routes/Memory";
import { ReportDialog } from "@/routes/intel/ReportDialog";
import { byReadiness, byWeek, dayOf, outcomeBuckets, readyIn, weekOf } from "@/routes/hunts/runs";
import { coverage, logsourceOf, MAPPINGS, productsFor } from "@/routes/coverage/products";
import { byRisk, cellOf, flagOf, listedOnly } from "@/routes/posture/cells";
import { aboutKey, aboutOf, bodyOf, caseOf, originOf, tabOf } from "@/routes/memory/origin";
import { defang, entityKey, feedName, hostOf, isReportSource, lastPull } from "@/routes/intel/feeds";
import type { Exposure, HuntReadiness, HuntRun, IntelReport, Rule, RuleHealth, SnapshotRow } from "@/types";

const H = 3_600_000;

function run(over: Partial<HuntRun>): HuntRun {
  return {
    run_uid: "HUNT-1",
    pack_id: "p",
    ran_at: new Date().toISOString(),
    outcome: "clear",
    rows_returned: 0,
    chosen_because: "",
    triage: "",
    finding_uid: "",
    error: "",
    duration_ms: 5,
    query: "",
    query_params: {},
    ingested_from: null,
    ingested_to: null,
    ruled_out: [],
    unseen: [],
    ...over,
  };
}

function pack(over: Partial<HuntReadiness>): HuntReadiness {
  return { pack_id: "p", state: "not_applicable", reason: "", ready_at: null, sources: [], accounts: [], ...over };
}

function rule(id: string, product: string, service: string, attack: string[]): Rule {
  return { id, title: id, attack, logsource: { product, service } } as unknown as Rule;
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
    silent_reason: "quiet",
    ...over,
  };
}

function entity(name: string, over: Partial<Exposure> = {}): Exposure {
  return {
    entity: name,
    kind: name.split(":")[0]!,
    events: 1,
    exposed: false,
    privileged: false,
    stale: false,
    sources: [],
    countries: [],
    operations: [],
    event_uids: [],
    first_seen: null,
    last_seen: null,
    ...over,
  };
}

describe("hunt runs by day", () => {
  it("draws one bucket per day the window touches, outcomes on the status scale", () => {
    const now = Date.parse("2026-10-04T12:00:00");
    const buckets = outcomeBuckets(
      [
        run({ ran_at: new Date(now - H).toISOString(), outcome: "suspicious" }),
        run({ ran_at: new Date(now - 2 * H).toISOString(), outcome: "clear" }),
        run({ ran_at: new Date(now - 30 * H).toISOString(), outcome: "gap" }),
      ],
      7,
      now,
    );
    // A rolling 7 × 24h from noon touches eight days.
    expect(buckets).toHaveLength(8);
    const today = buckets.at(-1)!;
    expect(today.key).toBe(dayOf(new Date(now).toISOString()));
    expect(today.parts.find((p) => p.label === "suspicious")!.value).toBe(1);
    expect(today.parts.find((p) => p.label === "clear")!.value).toBe(1);
    expect(buckets.at(-2)!.parts.find((p) => p.label === "couldn't look")!.value).toBe(1);
    // Clear, the usual outcome, fades; what needs a look stands out.
    expect(today.parts.find((p) => p.label === "clear")!.tone).toBe("muted");
    expect(today.parts.find((p) => p.label === "suspicious")!.tone).toBe("warn");
    // Never a severity hue.
    const tones = new Set(buckets.flatMap((b) => b.parts.map((p) => p.tone)));
    for (const tone of ["critical", "high", "medium"]) expect(tones.has(tone)).toBe(false);
  });

  it("gives the window's oldest run a bar", () => {
    for (const days of [7, 30, 90]) {
      const keyOf = byWeek(days) ? weekOf : dayOf;
      for (const at of ["2026-10-04T01:29:00", "2026-10-04T23:30:00"]) {
        const now = Date.parse(at);
        const oldest = new Date(now - (days * 24 - 1) * H).toISOString();
        const buckets = outcomeBuckets([run({ ran_at: oldest, outcome: "suspicious" })], days, now);
        if (!byWeek(days)) expect(buckets).toHaveLength(days + 1);
        expect(buckets[0]!.key).toBe(keyOf(new Date(now - days * 24 * H).toISOString()));
        expect(Date.parse(buckets[0]!.from)).toBeLessThanOrEqual(now - days * 24 * H);
        const bar = buckets.find((b) => b.key === keyOf(oldest))!;
        expect(bar.parts.find((p) => p.label === "suspicious")!.value).toBe(1);
        expect(Date.parse(buckets.at(-1)!.to)).toBeGreaterThan(now);
      }
    }
  });

  it("draws 90 days as weeks from Monday, so each bar is wide enough to press", () => {
    // A Sunday.
    const now = Date.parse("2026-10-04T12:00:00");
    const buckets = outcomeBuckets([run({ ran_at: "2026-09-29T09:00:00", outcome: "suspicious" })], 90, now);
    expect(buckets).toHaveLength(13);
    for (const b of buckets) expect(new Date(b.from).getDay()).toBe(1);
    expect(weekOf("2026-10-04T23:00:00")).toBe("2026-09-28");
    expect(buckets.at(-1)!.key).toBe("2026-09-28");
    expect(buckets.at(-1)!.parts.find((p) => p.label === "suspicious")!.value).toBe(1);
    expect(byWeek(30)).toBe(false);
  });

  it("lists ready packs first, learning by the day each is ready", () => {
    const rows = [
      pack({ pack_id: "na", title: "a" }),
      pack({ pack_id: "late", state: "learning", ready_at: "2026-11-01T00:00:00Z" }),
      pack({ pack_id: "ready", state: "ready" }),
      pack({ pack_id: "soon", state: "learning", ready_at: "2026-10-10T00:00:00Z" }),
    ].sort(byReadiness);
    expect(rows.map((r) => r.pack_id)).toEqual(["ready", "soon", "late", "na"]);
    expect(readyIn(rows[1]!, Date.parse("2026-10-04T00:00:00Z"))).toBe("6d");
    expect(readyIn(rows[0]!, Date.now())).toBe("");
  });
});

describe("coverage", () => {
  it("looks a logsource up the way the kernel does: product/service, else the product alone", () => {
    expect(productsFor("aws", "cloudtrail")).toEqual(["AWS CloudTrail"]);
    expect(productsFor("aws", "")).toEqual(["AWS CloudTrail", "AWS GuardDuty"]);
    expect(productsFor("cloudflare", "audit")).toEqual(["Cloudflare Audit Log"]);
    expect(productsFor("okta", "system_log")).toEqual(["Okta System Log"]);
    expect(productsFor("nothing", "")).toEqual([]);
    expect(logsourceOf("Cloudflare Logpush")).toBe("cloudflare");
  });

  it("counts only rules that can fire, per arriving product and tactic, and marks ready packs", () => {
    const rules = [
      rule("live", "aws", "cloudtrail", ["T1078.004"]),
      rule("armed", "aws", "cloudtrail", ["T1098"]),
      rule("blind", "aws", "cloudtrail", ["T1078"]),
      rule("failing", "okta", "system_log", ["T1078"]),
      rule("elsewhere", "stripe", "", ["T1078"]),
    ];
    const byRule = new Map([
      ["live", health("live", { findings_7d: 3, silent: false, silent_reason: "" })],
      ["armed", health("armed")],
      ["blind", health("blind", { silent_reason: "not_ingested" })],
      ["failing", health("failing", { error: "boom" })],
      ["elsewhere", health("elsewhere")],
    ]);
    const cover = coverage(["AWS CloudTrail", "Okta System Log"], rules, byRule, [
      pack({ pack_id: "okta_pack", state: "ready", product: "okta", attack: ["T1078"] }),
    ]);
    expect(cover.working.get("AWS CloudTrail")).toBe(2);
    expect(cover.working.get("Okta System Log")).toBe(0);
    expect(cover.cells.get("AWS CloudTrail")!.get("initial-access")!.rules.map((r) => r.id)).toEqual(["live"]);
    expect(cover.cells.get("Okta System Log")!.get("initial-access")!.packs.map((p) => p.pack_id)).toEqual(["okta_pack"]);
    expect(cover.lit.has("persistence")).toBe(true);
    // A pack is not a live rule: Okta's tactics stay unlit by it.
    expect(cover.cells.get("Okta System Log")!.get("initial-access")!.rules).toEqual([]);
  });

  const MAPS = join(__dirname, "..", "..", "shoc", "ingest", "mappings");
  it.skipIf(!existsSync(MAPS) && !process.env.CI)("copies every kernel mapping's logsource keys", () => {
    const kernel: Record<string, string[]> = {};
    for (const file of readdirSync(MAPS).filter((f) => f.endsWith(".yaml"))) {
      const text = readFileSync(join(MAPS, file), "utf8");
      const name = /^\s+metadata_product:\s*(.+?)\s*$/m.exec(text)?.[1];
      if (!name) continue;
      const keys = /^logsource:\s*\[([^\]]*)\]/m.exec(text)?.[1];
      kernel[name] = keys ? keys.split(",").map((k) => k.trim().toLowerCase()) : [file.replace(/\.yaml$/, "")];
    }
    expect(MAPPINGS).toEqual(kernel);
  });
});

describe("posture", () => {
  it("puts each entity in one quadrant, and says only the flags a filter does not", () => {
    const both = entity("key:AKIA", { exposed: true, privileged: true, stale: true });
    expect(cellOf(both)).toBe("ep");
    expect(cellOf(entity("user:a", { privileged: true }))).toBe("np");
    expect(flagOf(both, {})).toBe("both");
    expect(flagOf(both, { stale: "yes" })).toBe("both");
    expect(flagOf(both, { cell: "ep" })).toBe("stale");
    expect(flagOf(both, { cell: "ep", stale: "yes" })).toBeNull();
    const sorted = [entity("ip:1", { events: 9 }), both, entity("user:b", { exposed: true })].sort(byRisk);
    expect(sorted.map((e) => e.entity)).toEqual(["key:AKIA", "user:b", "ip:1"]);
  });

  it("lists as listed only what a source lists and the events never named", () => {
    const snap = (entity: string, kind = "user"): SnapshotRow => ({
      source: "okta",
      entity,
      kind,
      attributes: {},
      last_active: null,
      taken_at: "2026-10-01T00:00:00Z",
    });
    const rows = listedOnly([snap("user:alice"), snap("bob"), snap("user:carol")], [entity("user:alice"), entity("user:bob")]);
    expect(rows.map((r) => r.entity)).toEqual(["user:carol"]);
  });
});

describe("memory and intel words", () => {
  it("draws a person, the crew or shoc, and files each kind under one tab", () => {
    expect(originOf("human")).toBe("human");
    expect(originOf("agent")).toBe("crew");
    expect(originOf("service")).toBe("system");
    expect(originOf("Surveyor")).toBe("crew");
    expect(tabOf("semantic")).toBe("facts");
    expect(tabOf("episodic")).toBe("notes");
    expect(tabOf("correction")).toBe("corrections");
  });

  it("says a subject once, and never draws a URL indicator as a link", () => {
    expect(bodyOf({ kind: "semantic", subject: "user:alice", body: "user:alice: on leave until May" })).toBe("on leave until May");
    expect(bodyOf({ kind: "semantic", subject: "user:alice", body: "Alice is on leave" })).toBe("Alice is on leave");
    // A correction's subject is its rule and resource, which its body opens with.
    expect(
      bodyOf({ kind: "correction", subject: "okta_admin_granted:jane@example.com", body: "okta_admin_granted on jane@example.com was benign_expected" }),
    ).toBe("was benign_expected");
    // The verdict id in words, and the case a note came from left to the dialog's link.
    expect(
      bodyOf({
        kind: "correction",
        subject: "r:jane@example.com",
        body: "r on jane@example.com between 2026-10-02 00:20 and 2026-10-02 01:20 UTC was benign_expected, said jane: its me",
      }),
    ).toBe("between 2026-10-02 00:20 and 2026-10-02 01:20 UTC: expected, said jane: its me");
    const note = { kind: "episodic", subject: "jane@example.com", body: "jane@example.com: its me (case CASE-0123456789abcdef0123, closed as expected activity)" };
    expect(bodyOf(note)).toBe("its me");
    expect(
      bodyOf({ kind: "episodic", subject: "user:jane", body: "user:jane: Newly exposed. (Surveyor, 2026-10-06)" }),
    ).toBe("Newly exposed.");
    expect(caseOf(note)).toEqual({ uid: "CASE-0123456789abcdef0123", closed: "expected" });
    expect(defang("url", "http://198.51.100.7:8080/bin.sh")).toBe("hxxp://198.51.100.7:8080/bin.sh");
    expect(defang("url", "https://cdn.example/x")).toBe("hxxps://cdn.example/x");
    expect(defang("domain", "http.example")).toBe("http.example");
  });

  it("reads a correction's subject as its rule and what it is about", () => {
    expect(aboutOf({ kind: "correction", subject: "okta_admin_granted:jane@example.com" })).toEqual({
      rule: "okta_admin_granted",
      rest: "jane@example.com",
    });
    expect(aboutOf({ kind: "correction", subject: "aws_root_login:" })).toEqual({ rule: "aws_root_login", rest: "" });
    expect(aboutOf({ kind: "semantic", subject: "user:alice" })).toEqual({ rule: "", rest: "user:alice" });
    // The person a rule fired on has the record the events keep, under user:.
    expect(aboutKey("okta_admin_granted", "jane@example.com")).toBe("user:jane@example.com");
    expect(aboutKey("aws_s3_public", "arn:aws:s3:::bucket")).toBe("resource:arn:aws:s3:::bucket");
    expect(aboutKey("", "user:alice")).toBe("user:alice");
    expect(aboutKey("rule", "not an entity")).toBeNull();
  });

  it("opens an entity by its typed key, never a guessed one", () => {
    expect(entityKey("203.0.113.7")).toBe("ip:203.0.113.7");
    expect(entityKey("https://cdn.example/x")).toBe("url:https://cdn.example/x");
    expect(entityKey("jane", "actor")).toBe("user:jane");
    expect(entityKey("jane@example.com", "actor")).toBe("user:jane@example.com");
    expect(entityKey("jane@example.com", "auto")).toBe("user:jane@example.com");
    expect(entityKey("jane@example.com")).toBe("email:jane@example.com");
    expect(entityKey("OAuth client", "auto")).toBeNull();
    expect(
      lastPull([
        { feed: "a", enabled: true, last_ok_at: "2026-10-01T00:00:00Z", last_error: null, indicators: 1 },
        { feed: "b", enabled: false, last_ok_at: "2026-10-03T00:00:00Z", last_error: null, indicators: 1 },
      ]),
    ).toBe("2026-10-01T00:00:00Z");
  });

  it("names report sources and lookups as their publishers do, and a feed URL by the host it calls", () => {
    expect(["the_dfir_report", "cert_fr_alerts", "abuse_ch", "urlscan"].map(feedName)).toEqual([
      "The DFIR Report",
      "CERT-FR alerts",
      "abuse.ch",
      "urlscan.io",
    ]);
    expect(hostOf("https://blog.example.com/feed")).toBe("blog.example.com");
    expect(hostOf("blog.example.com/feed")).toBe("");
    const feed = { feed: "dfir", enabled: true, last_ok_at: null, last_error: null, indicators: 0 };
    expect(isReportSource({ ...feed, parser: "rss" })).toBe(true);
    expect(isReportSource({ ...feed, feed: "abuse_ch_urlhaus" })).toBe(false);
  });
});

/* -- the screens, over a stubbed API --------------------------------------- */

type Calls = { name: string; body: Record<string, unknown> }[];

function stub(answers: Record<string, unknown>, calls: Calls) {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const name = new URL(url, "http://x").pathname.replace(/^\/v1\//, "").replace("/", ".");
      calls.push({ name, body: JSON.parse(String(init?.body ?? "{}")) });
      const data = answers[name];
      if (data === undefined)
        return Promise.resolve(new Response(JSON.stringify({ error: { message: "nope" } }), { status: 500 }));
      return Promise.resolve(new Response(JSON.stringify({ data, summary: "", citations: [] })));
    }),
  );
}

function show(ui: React.ReactNode, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the program screens", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("Hunts runs every due pack only behind a confirm", async () => {
    const calls: Calls = [];
    stub(
      {
        "hunt.results": {
          runs: [run({ pack_id: "p", outcome: "suspicious" })],
          count: 1,
          metrics: { days: 7, by_outcome: { suspicious: 1 }, readiness: {}, detections_proposed: 0, gaps_open: 0, gaps_closed: 0, packs_hunted: 1 },
          readiness: [pack({ pack_id: "p", state: "ready", title: "First API call" })],
        },
        "hunt.backlog": { items: [], count: 0 },
        "ops.alerts": { alerts: [], count: 0 },
        "hunt.daily": { chosen: [], runs: [], outcomes: {}, readiness: [], tokens: 0 },
      },
      calls,
    );
    show(<Hunts />, "/hunts");
    expect(await screen.findByText("First API call")).toBeInTheDocument();
    expect(screen.getAllByText("Suspicious").length).toBeGreaterThan(0);
    // The button opens a confirm (jsdom draws no popover), so a click alone runs nothing.
    const button = screen.getByRole("button", { name: /run today's hunts/i });
    expect(button).toHaveAttribute("aria-haspopup", "dialog");
    await userEvent.click(button);
    expect(calls.some((c) => c.name === "hunt.daily")).toBe(false);
  });

  it("a closed hypothesis says what the report saw, how it ended, by whom and why", async () => {
    const calls: Calls = [];
    stub(
      {
        "hunt.results": {
          runs: [],
          count: 0,
          metrics: { days: 7, by_outcome: {}, readiness: {}, detections_proposed: 0, gaps_open: 0, gaps_closed: 0, packs_hunted: 0 },
          readiness: [],
        },
        "hunt.backlog": {
          items: [
            {
              item_uid: "HBL-1",
              trigger: "cti",
              title: "The ClickFix shape",
              hypothesis: "A user runs a command a fake CAPTCHA put on their clipboard",
              would_confirm: "",
              data_needed: "endpoint process events",
              why_now: "",
              attack: ["T1204.004"],
              pack_id: "",
              priority: 3,
              state: "rejected",
              created_at: "2026-10-06T06:41:47Z",
              decided_at: "2026-10-07T00:05:31Z",
              decided_by: "agent:Hunter",
              evidence: {
                report_uid: "RPT-1",
                source: "huntress",
                procedure: "explorer.exe started PowerShell with a pasted, padded command",
                logic: "a process whose parent is explorer.exe and whose command line holds caret runs",
                decision: "source_gap",
                because: "no connected source sends process events",
                waiting_for: ["crowdstrike_fdr"],
              },
              context: {
                techniques: [{ id: "T1204.004", name: "Malicious Copy and Paste" }],
                reports: [{ report_uid: "RPT-1", title: "The Fix for ClickFix", relevance: "", said: [] }],
                seen_in: [
                  {
                    kind: "process",
                    label: "process starts",
                    products: [{ source: "crowdstrike_fdr", product: "CrowdStrike Falcon Data Replicator" }],
                    received: [],
                  },
                ],
                rules: [{ id: "endpoint_clickfix_paste_and_run", title: "Paste and run from the Run box", live: false }],
                packs: [],
                cases: [],
              },
            },
          ],
          count: 1,
        },
        "intel.reports": { rows: [{ report_uid: "RPT-1", title: "The Fix for ClickFix" }], count: 1 },
        "ops.alerts": { alerts: [], count: 0 },
      },
      calls,
    );
    show(<Hunts />, "/hunts?tab=backlog&backlog=closed&item=HBL-1");
    expect(await screen.findByText("no connected source sends process events")).toBeInTheDocument();
    expect(screen.getByText("explorer.exe started PowerShell with a pasted, padded command")).toBeInTheDocument();
    expect(screen.getByText("a process whose parent is explorer.exe and whose command line holds caret runs")).toBeInTheDocument();
    expect(await screen.findByText("The Fix for ClickFix")).toBeInTheDocument();
    // The row, the dialog's head and the story all say how it ended, in the same word.
    expect(screen.getAllByText("source gap").length).toBe(3);
    expect(screen.getByText("not received")).toBeInTheDocument();
    expect(screen.getByText("Paste and run from the Run box")).toBeInTheDocument();
    expect(screen.getByText("Malicious Copy and Paste")).toBeInTheDocument();
  });

  it("a palette hand-off to today's hunts runs nothing by itself", async () => {
    const calls: Calls = [];
    stub({ "hunt.backlog": { items: [], count: 0 }, "ops.alerts": { alerts: [], count: 0 } }, calls);
    show(<Hunts />, "/hunts?do=hunts.daily");
    await waitFor(() => expect(calls.some((c) => c.name === "hunt.backlog")).toBe(true));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls.some((c) => c.name === "hunt.daily")).toBe(false);
  });

  it("Hunts never reads a failed load as idle", async () => {
    stub({ "ops.alerts": { alerts: [], count: 0 } }, []);
    show(<Hunts />, "/hunts");
    expect(await screen.findAllByText("Can't tell")).not.toHaveLength(0);
    expect(screen.queryByText("Idle")).toBeNull();
    expect(screen.queryByText(/No hunts in/)).toBeNull();
  });

  it("Intel looks nothing up itself and reads the newest 200", async () => {
    const calls: Calls = [];
    stub(
      {
        "intel.list": {
          rows: [
            {
              type: "url",
              value: "https://cdn.example/payload.bin",
              source: "abuse_ch_urlhaus",
              confidence: 0.8,
              severity: "high",
              description: "",
              tags: [],
              last_seen: new Date().toISOString(),
            },
          ],
          count: 1,
          total: 4941,
          feeds: [{ feed: "abuse_ch_urlhaus", enabled: true, last_ok_at: new Date().toISOString(), last_error: null, indicators: 1 }],
        },
        "hunt.suggest": { suggestions: [], count: 0 },
        "intel.reports": { rows: [], count: 0 },
      },
      calls,
    );
    show(<Intel />, "/intel");
    expect(await screen.findByText("hxxps://cdn.example/payload.bin")).toBeInTheDocument();
    expect(screen.getByText("Feeds ok")).toBeInTheDocument();
    // The feeds themselves are Connections': the strip links there.
    expect(screen.getByRole("link", { name: /feeds failing/ })).toHaveAttribute("href", "/connections?tab=intel");
    expect(calls.find((c) => c.name === "intel.list")?.body).toMatchObject({ limit: 200 });
    expect(calls.some((c) => c.name === "intel.lookup")).toBe(false);
  });

  it("Intel draws today's reads against the budget; Connections adds a report source by name", async () => {
    const calls: Calls = [];
    stub(
      {
        "intel.list": {
          rows: [],
          count: 0,
          total: 0,
          feeds: [],
          presets: [
            { name: "the_dfir_report", url: "https://thedfirreport.com/feed/", host: "thedfirreport.com", grade: 2, configured: false },
            { name: "huntress", url: "https://www.huntress.com/blog/rss.xml", host: "www.huntress.com", grade: 2, configured: true },
          ],
          lookups: [
            { source: "abuse_ch", answers: "", hosts: ["threatfox-api.abuse.ch"], configured: true, enabled: true, per_day: 2000, calls_today: 4, paused_until: null, licence_needed: false, secret_field: "auth_key" },
            { source: "virustotal", answers: "", hosts: ["www.virustotal.com"], configured: false, enabled: false, per_day: 500, calls_today: 0, paused_until: null, licence_needed: true, secret_field: "api_key" },
          ],
          budget: { reports_per_day: 5, tokens_per_day: 100_000, reports_today: 2, tokens_today: 31_000 },
        },
        "hunt.suggest": { suggestions: [], count: 0 },
        "intel.reports": { rows: [], count: 0 },
        "intel.configure": { feed: "the_dfir_report", parser: "rss", enabled: true },
      },
      calls,
    );
    const intel = show(<Intel />, "/intel");
    expect(await screen.findByText("2/5")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Facts" })).getByText("31k/100k")).toBeInTheDocument();
    intel.unmount();
    show(<IntelSources />, "/connections?tab=intel");
    // A lookup set up has its row; one that is not waits in Add intel source.
    expect(await screen.findByText("abuse.ch")).toBeInTheDocument();
    expect(screen.queryByText("VirusTotal")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /add intel source/i }));
    // Only what is not configured yet, with the host it will contact.
    expect(screen.getByText("thedfirreport.com")).toBeInTheDocument();
    expect(screen.queryByText("Huntress")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Add", hidden: true }));
    await waitFor(() => expect(calls.find((c) => c.name === "intel.configure")?.body).toEqual({ preset: "the_dfir_report" }));
  });

  it("Intel's unread reports ask the kernel for the queue", async () => {
    const calls: Calls = [];
    stub(
      {
        "intel.list": { rows: [], count: 0, total: 0, feeds: [] },
        "hunt.suggest": { suggestions: [], count: 0 },
        "intel.reports": { rows: [], count: 0 },
      },
      calls,
    );
    show(<Intel />, "/intel?tab=reports&reports=unread");
    expect(await screen.findByText("Nothing unread")).toBeInTheDocument();
    expect(calls.filter((c) => c.name === "intel.reports").map((c) => c.body.state)).toContain("queue");
  });

  it("Memory asks for the kernel's cap and adds facts in a dialog", async () => {
    const calls: Calls = [];
    stub(
      {
        "memory.search": {
          rows: [
            {
              memory_id: "MEM-1",
              kind: "semantic",
              subject: "testS3Access",
              body: "Read-only role used by the nightly backup job",
              source: "human",
              confidence: 1,
              created_at: new Date(Date.now() - 3 * 86_400_000).toISOString(),
            },
          ],
          count: 1,
        },
      },
      calls,
    );
    show(<Memory />, "/memory");
    // Original case, never uppercased.
    expect(await screen.findByText(/testS3Access/)).toBeInTheDocument();
    expect(within(screen.getByRole("grid")).getByText("3d")).toBeInTheDocument();
    // The strip counts what people said, and when the newest came in.
    const facts = screen.getByRole("group", { name: "Facts" });
    expect(within(facts).getByRole("button", { name: /1\s*told by people/ })).toBeInTheDocument();
    expect(within(facts).getByText("3d")).toBeInTheDocument();
    expect(calls.find((c) => c.name === "memory.search")?.body).toMatchObject({ limit: 100 });
    expect(screen.queryByLabelText("Fact")).toBeNull();
    // A plain subject is the dialog's title and nowhere else in it.
    await userEvent.click(screen.getByText(/Read-only role/));
    const dialog = screen.getByRole("dialog", { hidden: true });
    expect(within(dialog).getByRole("heading", { hidden: true })).toHaveTextContent("testS3Access");
    expect(within(dialog).getAllByText(/testS3Access/)).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: /add fact/i }));
    expect(screen.getByLabelText("Fact")).toBeInTheDocument();
  });

  it("a report's suggestion already on the backlog reads proposed", async () => {
    const hunts = ["Sign-ins from the four published addresses", "OAuth grants replayed from a new ASN"];
    stub(
      {
        "hunt.backlog": {
          items: [{ item_uid: "HBL-1", title: hunts[0]!.slice(0, 20), hypothesis: hunts[0], state: "open" }],
          count: 1,
        },
      },
      [],
    );
    const report: IntelReport = {
      report_uid: "RPT-1",
      url: "",
      source_host: "example.com",
      title: "Report",
      summary: "",
      relevance: "",
      actors: [],
      malware: [],
      campaigns: [],
      techniques: [],
      hunts,
      stored_count: 0,
      confidence: 0.5,
      digested_at: new Date().toISOString(),
    };
    show(<ReportDialog report={report} onClose={() => {}} />, "/intel");
    expect(await screen.findByText("proposed")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /backlog/i, hidden: true })).toHaveLength(1);
  });

  it("Memory lands on Facts, and an empty Facts points to the tab that has rows", async () => {
    stub(
      {
        "memory.search": {
          rows: [
            {
              memory_id: "MEM-2",
              kind: "episodic",
              subject: "case CASE-1",
              body: "Closed as expected travel",
              source: "agent",
              confidence: 0.6,
              created_at: new Date().toISOString(),
            },
          ],
          count: 1,
        },
      },
      [],
    );
    show(<Memory />, "/memory");
    expect(screen.getByRole("tab", { name: /facts/i })).toHaveAttribute("aria-selected", "true");
    await userEvent.click(await screen.findByRole("button", { name: "Notes 1" }));
    expect(await screen.findByText(/Closed as expected travel/)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /notes/i })).toHaveAttribute("aria-selected", "true");
  });

  it("Memory names a correction by its rule's title and who it fired on, never the raw key", async () => {
    stub(
      {
        "rule.list": { rules: [{ id: "google_oauth_token_authorized", title: "Google OAuth app authorised" }], count: 1 },
        "memory.search": {
          rows: [
            {
              memory_id: "MEM-3",
              kind: "correction",
              subject: "google_oauth_token_authorized:jane@example.com",
              body: "Expected: the backup app",
              source: "human",
              confidence: 1,
              created_at: new Date().toISOString(),
            },
          ],
          count: 1,
        },
      },
      [],
    );
    show(<Memory />, "/memory?tab=corrections");
    expect(await screen.findByText(/Google OAuth app authorised/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "user jane@example.com" })).toBeInTheDocument();
    expect(screen.queryByText(/google_oauth_token_authorized:/)).toBeNull();
  });
});
