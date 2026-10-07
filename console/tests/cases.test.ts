import { describe, expect, it } from "vitest";
import { bucket, caseTab, closedBy, hold, huntTitle, inWindow, matches, order } from "@/lib/cases";
import { sinceTime } from "@/lib/since";
import type { Case, CaseState } from "@/types";

const states: CaseState[] = [
  "triage",
  "analysis",
  "containment",
  "eradication",
  "recovery",
  "post_incident",
  "closed",
];

const hour = 3_600_000;
const now = Date.parse("2026-10-03T12:00:00Z");
const at = (offset: number) => new Date(now + offset).toISOString();

function row(state: CaseState, over: Partial<Case> = {}): Case {
  return {
    case_uid: `CASE-${state}`,
    title: `case ${state}`,
    severity: "medium",
    state,
    verdict: "unknown",
    confidence: 0,
    entity_key: "user:deploy-ci",
    summary: "",
    finding_uids: [],
    attack: ["T1078.004"],
    rounds: 0,
    tokens_used: 0,
    opened_at: at(-10 * hour),
    updated_at: at(-hour),
    closed_at: state === "closed" ? at(-2 * hour) : null,
    ...over,
  };
}

describe("the case tabs", () => {
  it("put every case in exactly one tab", () => {
    const buckets = bucket(states.map((s) => row(s)));
    const placed = Object.values(buckets).flat();
    expect(placed).toHaveLength(states.length);
    expect(new Set(placed.map((c) => c.case_uid)).size).toBe(states.length);
  });

  it("keep the phases apart", () => {
    expect(caseTab("triage")).toBe("investigating");
    expect(caseTab("analysis")).toBe("investigating");
    expect(caseTab("containment")).toBe("contained");
    expect(caseTab("post_incident")).toBe("contained");
    expect(caseTab("closed")).toBe("closed");
  });
});

describe("the case order", () => {
  it("puts open work first, worst first, and closed cases by when they closed", () => {
    const rows = [
      row("closed", { case_uid: "old-close", closed_at: at(-5 * hour) }),
      row("triage", { case_uid: "medium" }),
      row("closed", { case_uid: "new-close", closed_at: at(-hour), severity: "critical" }),
      row("analysis", { case_uid: "critical", severity: "critical" }),
      row("containment", { case_uid: "high-fresh", severity: "high", updated_at: at(-60_000) }),
      row("triage", { case_uid: "high-stale", severity: "high", updated_at: at(-5 * hour) }),
    ];
    expect(order(rows).map((c) => c.case_uid)).toEqual([
      "critical",
      "high-fresh",
      "high-stale",
      "medium",
      "new-close",
      "old-close",
    ]);
  });

  it("sorts open cases by age for the oldest fact", () => {
    const rows = [
      row("triage", { case_uid: "young", opened_at: at(-hour), severity: "critical" }),
      row("triage", { case_uid: "old", opened_at: at(-9 * hour) }),
    ];
    expect(order(rows, "oldest").map((c) => c.case_uid)).toEqual(["old", "young"]);
  });
});

describe("a held order", () => {
  it("keeps each row where the reader saw it, drops one that left and holds back one that arrived", () => {
    const rows = [
      row("triage", { case_uid: "arrived", severity: "critical" }),
      row("triage", { case_uid: "b", severity: "high" }),
      row("triage", { case_uid: "a" }),
    ];
    expect(hold(rows, ["a", "gone", "b"]).map((c) => c.case_uid)).toEqual(["a", "b"]);
    expect(hold(rows, null)).toBe(rows);
  });
});

describe("the since window", () => {
  it("reads relative windows and ISO times", () => {
    expect(sinceTime("24h", now)).toBe(now - 24 * hour);
    expect(sinceTime("-7d", now)).toBe(now - 7 * 24 * hour);
    expect(sinceTime(at(-3 * hour), now)).toBe(now - 3 * hour);
    expect(sinceTime("yesterday", now)).toBeNaN();
  });

  it("counts a closed case by when it closed, and any other by when it opened", () => {
    const closed = row("closed", { opened_at: at(-30 * hour), closed_at: at(-2 * hour) });
    expect(inWindow(closed, "24h", "closed", now)).toBe(true);
    expect(inWindow(closed, "24h", "all", now)).toBe(false);
    expect(inWindow(closed, "nonsense", "closed", now)).toBe(false);
  });
});

describe("who closed a case", () => {
  it("counts shoc's own closes with the crew's, so Overview's counter and the list agree", () => {
    expect(closedBy(row("closed", { closed_by: "crew" }), "crew")).toBe(true);
    expect(closedBy(row("closed", { closed_by: "system" }), "crew")).toBe(true);
    expect(closedBy(row("closed", { closed_by: "system" }), "system")).toBe(true);
    expect(closedBy(row("closed", { closed_by: "human" }), "crew")).toBe(false);
    expect(closedBy(row("triage", { closed_by: "crew" }), "crew")).toBe(false);
  });
});

describe("the text filter and hunt titles", () => {
  it("matches title, entity, uid and technique", () => {
    const c = row("triage");
    expect(matches(c, "deploy-ci")).toBe(true);
    expect(matches(c, "case-triage")).toBe(true);
    expect(matches(c, "t1078")).toBe(true);
    expect(matches(c, "okta")).toBe(false);
  });

  it("drops the Hunt prefix, which a glyph replaces", () => {
    expect(huntTitle("Hunt: An API almost nobody uses")).toBe("An API almost nobody uses");
    expect(huntTitle("5 findings for AKIAIOSFODNN7EXAMPLE")).toBeNull();
  });
});
