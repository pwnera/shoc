/**
 * Console guidelines (UI-G) that need a hook rendered: the inbox asks the
 * kernel to filter before its cap rather than filtering a capped list itself.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useNeedsYou } from "@/lib/needs";
import { CASE_CAP } from "@/lib/reads";
import type { Case } from "@/types";

const old = {
  case_uid: "CASE-9",
  title: "case CASE-9",
  severity: "high",
  state: "analysis",
  verdict: "needs_human",
  opened_at: "2026-09-01T12:00:00Z",
  updated_at: "2026-09-02T12:00:00Z",
  closed_at: null,
} as Case;

describe("the inbox's waiting verdicts (UI-G3)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("asks case.list for needs_human cases itself", async () => {
    const asked: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const path = new URL(url, "http://x").pathname;
        const input = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
        let data: unknown = { rows: [], count: 0, waiting_for_approval: 0 };
        if (path === "/v1/source/list") data = { configured: [], onboarding: [] };
        if (path === "/v1/case/list") {
          asked.push(input);
          // The capped log holds 200 newer cases; only the kernel's own filter still finds CASE-9.
          data = input.verdict === "needs_human" ? { rows: [old], count: 1 } : { rows: [], count: 0 };
        }
        return new Response(JSON.stringify({ data, summary: "", citations: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result } = renderHook(() => useNeedsYou(), { wrapper });
    await waitFor(() => expect(result.current.pending).toBe(false));
    expect(asked).toContainEqual({ verdict: "needs_human", open: true, limit: CASE_CAP });
    expect(result.current.items.map((i) => [i.kind, i.key])).toEqual([["verdict", "CASE-9"]]);
    expect(result.current.count).toBe(1);
  });
});
