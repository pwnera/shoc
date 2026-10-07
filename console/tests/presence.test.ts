import { beforeEach, describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { notePresence, resetPresence, usePresence } from "@/lib/presence";
import type { StreamEvent } from "@/lib/stream";

const message = (agent: string, caseUid: string, round = 3, seq = 1): StreamEvent => ({
  seq,
  type: "openspace.message",
  subject: caseUid,
  payload: { agent, kind: "hypothesis", round, to: "", citations: [] },
  created_at: new Date().toISOString(),
});

describe("crew presence", () => {
  beforeEach(() => resetPresence());

  it("marks a role working on a case for two minutes after it speaks", () => {
    const { result } = renderHook(() => usePresence());
    expect(result.current.working).toBe(false);
    act(() => notePresence(message("Investigator", "CASE-1")));
    expect(result.current.working).toBe(true);
    expect(result.current.roles.map((r) => r.who.name)).toEqual(["Investigator"]);
    expect(result.current.onCase("CASE-1")[0]).toMatchObject({ round: 3, kind: "hypothesis" });
    expect(result.current.onCase("CASE-2")).toEqual([]);
  });

  it("forgets a message older than the window", () => {
    const { result } = renderHook(() => usePresence());
    act(() => notePresence(message("Challenger", "CASE-1"), Date.now() - 5 * 60_000));
    expect(result.current.working).toBe(false);
  });

  it("ignores people and the system, which are not the crew", () => {
    const { result } = renderHook(() => usePresence());
    act(() => notePresence(message("human:jane", "CASE-1")));
    act(() => notePresence(message("shoc", "CASE-1")));
    expect(result.current.working).toBe(false);
  });

  it("keeps the round's first sighting, so the age counts from the round's start", () => {
    const { result } = renderHook(() => usePresence());
    const start = Date.now() - 60_000;
    act(() => notePresence(message("Investigator", "CASE-1", 7), start));
    act(() => notePresence(message("Investigator", "CASE-1", 7)));
    expect(result.current.onCase("CASE-1")[0]?.since).toBe(start);
  });

  it("records a model failure until a model-backed role speaks again, and budget stops by case", () => {
    const { result } = renderHook(() => usePresence());
    const failing: StreamEvent = { seq: 2, type: "health.llm.failing", subject: "claude", payload: {}, created_at: "" };
    act(() => notePresence(failing));
    expect(result.current.down).toBe(true);
    act(() => notePresence(message("Investigator", "CASE-1"), Date.now() + 1));
    expect(result.current.down).toBe(false);
    act(() => notePresence({ seq: 3, type: "case.budget_exhausted", subject: "CASE-9", payload: {}, created_at: "" }));
    expect(result.current.budget.has("CASE-9")).toBe(true);
  });
});
