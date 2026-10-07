import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { createElement, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { crewDown, inbox, useNeedsYou } from "@/lib/needs";
import type { Action, Case, ConfiguredSource, Onboarding } from "@/types";

const hour = 3_600_000;
const at = (offset: number) => new Date(Date.parse("2026-10-03T12:00:00Z") + offset).toISOString();

function kase(uid: string, over: Partial<Case> = {}): Case {
  return {
    case_uid: uid,
    title: `case ${uid}`,
    severity: "high",
    state: "analysis",
    verdict: "malicious",
    confidence: 0.8,
    entity_key: "deploy-ci",
    summary: "",
    finding_uids: [],
    attack: [],
    rounds: 1,
    tokens_used: 0,
    opened_at: at(-10 * hour),
    updated_at: at(-hour),
    closed_at: null,
    ...over,
  };
}

function action(uid: string, over: Partial<Action> = {}): Action {
  return {
    action_uid: uid,
    case_uid: "C1",
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
    created_at: at(-2 * hour),
    ...over,
  };
}

describe("the inbox", () => {
  it("lists a pending approval and a needs-you verdict on the same case as two decisions", () => {
    const items = inbox({
      proposals: [action("A1", { decide_by: at(hour) })],
      cases: [kase("C1", { verdict: "needs_human" })],
    });
    expect(items.map((i) => i.kind)).toEqual(["approval", "verdict"]);
    expect(items[0]).toMatchObject({ severity: "high", to: "?decide=A1" });
    expect(items[1]).toMatchObject({ to: "/cases/C1" });
  });

  it("orders by severity, source rows after high, then by deadline", () => {
    const items = inbox({
      proposals: [
        action("late", { case_uid: "C2", decide_by: at(3 * hour) }),
        action("soon", { case_uid: "C2", decide_by: at(hour) }),
        action("crit", { case_uid: "C3", decide_by: at(5 * hour) }),
        action("med", { case_uid: "C4" }),
      ],
      cases: [kase("C2"), kase("C3", { severity: "critical" }), kase("C4", { severity: "medium" })],
      onboarding: [{ source: "okta", step: "credentials" } as Onboarding],
    });
    expect(items.map((i) => i.key)).toEqual(["crit", "soon", "late", "credential:okta", "med"]);
  });

  it("asks to decide again only for an expired approval on an open case with nothing newer of its kind", () => {
    const expired = action("E1", { state: "rejected", approved_by: "unattended", updated_at: at(-hour) });
    const page = action("P1", { type: "notify.page", state: "rejected", approved_by: "unattended" });
    expect(inbox({ actions: [expired, page], cases: [kase("C1")] }).map((i) => i.key)).toEqual(["E1"]);
    expect(inbox({ actions: [expired], cases: [kase("C1", { state: "closed" })] })).toEqual([]);
    const again = action("A2", { created_at: at(-30 * 60_000) });
    expect(inbox({ actions: [expired], proposals: [again], cases: [kase("C1")] }).map((i) => i.key)).toEqual(["A2"]);
  });

  it("raises a source whose credential the provider rejected", () => {
    const rejected = { source: "okta", last_error: "Okta rejected the credential (401)", last_run_at: at(0) };
    const items = inbox({ configured: [rejected as ConfiguredSource] });
    expect(items).toMatchObject([{ kind: "rejected_credential", to: "/connections?source=okta&view=settings" }]);
  });
});

describe("crew down", () => {
  it("names the model before a late worker", () => {
    const failing = [{ kind: "llm.failing", subject: "claude", detail: "", severity: "high" }];
    expect(crewDown(failing, ["hunt.daily"])).toEqual({ down: true, cause: "model", overdue: ["hunt.daily"] });
    expect(crewDown([], ["hunt.daily"])).toMatchObject({ down: true, cause: "worker" });
    expect(crewDown([], [])).toEqual({ down: false, cause: null, overdue: [] });
  });
});

describe("useNeedsYou", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reports a failed list as failed, never as an empty inbox", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/source/list"))
          return new Response(JSON.stringify({ error: { code: "store_error", message: "down" } }), { status: 500 });
        const data = url.endsWith("/v1/case/list") ? { rows: [kase("C1")], count: 1 } : { rows: [], count: 0, waiting_for_approval: 0 };
        return new Response(JSON.stringify({ data, summary: "", citations: [] }), { status: 200 });
      }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children);
    const { result } = renderHook(() => useNeedsYou(), { wrapper });
    expect(result.current.pending).toBe(true);
    await waitFor(() => expect(result.current.pending).toBe(false));
    expect(result.current.failed).toEqual(["sources"]);
    expect(result.current.count).toBe(0);
  });
});
