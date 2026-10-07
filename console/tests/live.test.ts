import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { announce, eventHref, invalidations } from "@/lib/live";
import { backoff, dataOf, type StreamEvent } from "@/lib/stream";
import { dismiss, useToasts } from "@/lib/toast";
import { act, renderHook } from "@testing-library/react";

const ev = (type: string, subject = "S1", payload: Record<string, unknown> = {}): StreamEvent => ({
  seq: 10,
  type,
  subject,
  payload,
  created_at: "2026-10-03T12:00:00Z",
});

const keys = (type: string, payload: Record<string, unknown> = {}) =>
  invalidations(ev(type, "S1", payload)).now.map((k) => k.join(" "));

describe("what each event makes stale (section 7, item 8)", () => {
  it("refreshes a case's list and record, and its timeline after a quiet spell on updates", () => {
    for (const type of ["case.opened", "case.severity_changed", "case.state_changed", "case.verdict", "case.budget_exhausted"])
      expect(invalidations(ev(type))).toEqual({ now: [["case.list"], ["case.get", "S1"]], later: [] });
    expect(invalidations(ev("case.updated")).later).toEqual([{ key: ["timeline.build", "S1"], ms: 5_000 }]);
  });

  it("refreshes the case a message or an action belongs to", () => {
    expect(keys("openspace.message")).toEqual(["case.get S1"]);
    expect(keys("action.proposed", { case_uid: "C1" })).toEqual(["action.list", "case.get C1"]);
    for (const type of ["action.approved", "action.rejected", "action.executed", "action.rolled_back"])
      expect(keys(type, { case_uid: "C1" })).toEqual(["action.list", "case.get C1", "playbook.runs"]);
    expect(keys("action.executed")).toEqual(["action.list", "playbook.runs"]);
  });

  it("refreshes runs on playbook events, and the run itself", () => {
    for (const type of ["playbook.started", "playbook.needs_approval", "playbook.waiting", "playbook.finished"])
      expect(keys(type)).toEqual(["playbook.runs", "playbook.get S1", "action.list"]);
  });

  it("refreshes the finding itself on a new finding, and the lists that follow the stream only after a quiet spell", () => {
    expect(invalidations(ev("finding.new"))).toEqual({
      now: [["health.status"], ["finding.get", "S1"]],
      later: [
        { key: ["health.rules"], ms: 30_000 },
        { key: ["finding.list"], ms: 15_000, live: true },
      ],
    });
    expect(keys("source.needs_credentials")).toEqual(["source.list", "health.status"]);
  });

  it("refreshes health.status only for health, finding and source events", () => {
    expect(keys("health.source.failing")).toEqual(["health.sources", "ops.alerts", "health.status"]);
    expect(keys("health.source.stale")).toEqual(["health.sources", "ops.alerts", "health.status"]);
    expect(keys("health.source.quality")).toEqual(["health.quality", "ops.alerts"]);
    expect(keys("health.rule.failing")).toEqual(["health.rules", "ops.alerts", "health.status"]);
    expect(keys("health.rule.noisy")).toEqual(["health.rules", "ops.alerts", "health.status"]);
    expect(keys("health.jobs.failed")).toEqual(["health.jobs", "ops.alerts", "health.status"]);
    expect(keys("health.llm.failing")).toEqual(["ops.alerts"]);
    expect(keys("health.cost.unpriced")).toEqual(["ops.alerts", "health.cost"]);
    expect(keys("health.cost.over_budget")).toEqual(["ops.alerts", "health.cost"]);
    expect(keys("health.case.stalled")).toEqual(["ops.alerts"]);
    expect(keys("health.action.stuck")).toEqual(["ops.alerts", "action.list"]);
    expect(keys("health.hunt.gap")).toEqual(["ops.alerts", "hunt.results"]);
    expect(keys("health.approval.waiting")).toEqual(["ops.alerts"]);
    expect(keys("health.audit.broken")).toEqual(["health.audit", "ops.alerts"]);
    expect(keys("report.ready")).toEqual([]);
    for (const type of ["case.opened", "openspace.message", "action.executed", "playbook.finished"])
      expect(keys(type)).not.toContain("health.status");
  });
});

describe("where each event leads", () => {
  it("links every event type to its home", () => {
    const href = (type: string, subject = "S1", payload = {}) => eventHref(ev(type, subject, payload));
    expect(href("case.opened")).toBe("/cases/S1");
    expect(href("openspace.message")).toBe("/cases/S1?tab=discussion");
    expect(href("action.proposed")).toBe("?decide=S1");
    expect(href("action.executed")).toBe("?action=S1");
    expect(href("playbook.finished", "R1", { case_uid: "C1" })).toBe("/cases/C1");
    expect(href("finding.new")).toBe("/findings/S1");
    expect(href("source.needs_credentials", "okta,github")).toBe("/connections?source=okta&view=settings");
    expect(href("health.source.failing", "okta")).toBe("/connections?source=okta");
    expect(href("health.source.quality", "Okta System Log")).toBe("/connections?tab=quality&product=Okta%20System%20Log");
    expect(href("health.rule.noisy", "aws_root_login")).toBe("/detection/rules/aws_root_login");
    expect(href("health.jobs.failed")).toBe("/health/jobs");
    expect(href("health.llm.failing")).toBe("/health/crew");
    expect(href("health.cost.unpriced")).toBe("/health/spend");
    expect(href("health.case.stalled")).toBe("/cases/S1");
    expect(href("health.action.stuck")).toBe("?action=S1");
    expect(href("health.hunt.gap", "pack_1")).toBe("/hunts?pack=pack_1");
    expect(href("health.approval.waiting")).toBe("/");
    expect(href("health.audit.broken")).toBe("/access?tab=audit");
    expect(href("report.ready")).toBe("/measurement");
  });
});

describe("toasts from the stream (section 3.5)", () => {
  const client = new QueryClient();
  const hook = () => renderHook(() => useToasts());
  let view: ReturnType<typeof hook>;
  const shown = () => view.result.current;
  const say = (event: StreamEvent) => act(() => announce(event, client, Promise.resolve()));
  beforeEach(() => {
    view = hook();
  });
  afterEach(() => {
    act(() => {
      for (const t of shown()) dismiss(t.id);
    });
  });

  it("says a dry run was planned, and offers Undo only on a real, reversible run", () => {
    say(ev("action.executed", "A1", { type: "cloudflare.block_ip", ok: true, dry_run: true, reversible: true }));
    expect(shown()[0]).toMatchObject({ tone: "ok", text: "Block IP at Cloudflare planned" });
    expect(shown()[0]?.action).toBeUndefined();
    say(ev("action.executed", "A2", { type: "cloudflare.block_ip", ok: true, dry_run: false, reversible: true }));
    expect(shown()[0]).toMatchObject({ text: "Block IP at Cloudflare done", action: { label: "Undo" } });
    expect(shown()[0]?.action?.to).toContain("action=A2");
    expect(shown()[0]?.action?.to).toContain("do=undo");
  });

  it("keeps failures until dismissed", () => {
    say(ev("action.executed", "A3", { type: "cloudflare.block_ip", ok: false }));
    expect(shown()[0]).toMatchObject({ tone: "critical", text: "Block IP at Cloudflare failed", life: Infinity });
    say(ev("health.audit.broken", "chain"));
    expect(shown()[0]).toMatchObject({ tone: "critical", text: "Audit chain broken" });
  });

  it("interrupts for a critical case and a raise to critical, and stays quiet for the rest", () => {
    say(ev("case.opened", "CASE-1a2b3c4d", { severity: "high", entity: "x" }));
    expect(shown()).toHaveLength(0);
    say(ev("case.opened", "CASE-1a2b3c4d", { severity: "critical", entity: "key:AKIAIOSFODNN7EXAMPLE" }));
    expect(shown()[0]).toMatchObject({ text: "Critical case on AKIAIOSFODNN7EXAMPLE", subject: { label: "CASE-1a2b…" } });
    say(ev("case.severity_changed", "CASE-1", { to: "critical" }));
    expect(shown()[0]?.text).toBe("Raised to critical");
  });

  it("folds actions on one case into one toast", () => {
    for (const uid of ["A4", "A5", "A6"])
      say(ev("action.executed", uid, { type: "cloudflare.block_ip", ok: true, dry_run: true, case_uid: "CASE-9" }));
    expect(shown()).toHaveLength(1);
    expect(shown()[0]).toMatchObject({ count: 3, text: "3 actions done" });
  });
});

describe("the stream reader", () => {
  it("reads data lines with or without a space after the colon", () => {
    expect(dataOf('event: x\ndata: {"seq":1}')).toBe('{"seq":1}');
    expect(dataOf('data:{"seq":2}')).toBe('{"seq":2}');
    expect(dataOf(": keep-alive")).toBe("");
  });

  it("waits longer after each failure, never more than 30s and a little at random", () => {
    expect(backoff(0, () => 0.5)).toBe(1000);
    expect(backoff(3, () => 0.5)).toBe(8000);
    expect(backoff(10, () => 1)).toBe(30_000);
    expect(backoff(4, () => 0)).toBe(11_200);
  });
});
