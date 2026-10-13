import { describe, expect, it } from "vitest";
import { noModel, notifyTo, unsentPages } from "@/routes/health/pipeline";
import type { Action, LlmConfig } from "@/types";

const hour = 3_600_000;
const now = Date.parse("2026-10-03T12:00:00Z");
const ago = (ms: number) => new Date(now - ms).toISOString();

const llm = (over: Partial<LlmConfig>): LlmConfig => ({
  provider: "anthropic",
  model: "m",
  model_cheap: "",
  base_url: "",
  key: "set",
  stored: [],
  spend_usd_per_day: 0,
  hunt_tokens_per_day: 0,
  ...over,
});

const page = (uid: string, over: Partial<Action> = {}) =>
  ({ action_uid: uid, type: "notify.page", state: "done", approved_by: null, created_at: ago(hour), ...over }) as Action;

describe("the Health pipeline", () => {
  it("fails Crew with no model, as Services says not connected", () => {
    expect(noModel(llm({ provider: "none" }))).toBe(true);
    expect(noModel(llm({ key: "unset" }))).toBe(true);
    expect(noModel(llm({}))).toBe(false);
  });

  it("sends Notify to Services when nobody can be reached, as its Problems row does, else to Pages", () => {
    expect(notifyTo(true)).toBe("/connections?tab=services");
    expect(notifyTo(false)).toBe("/response?tab=pages");
  });

  it("counts a page that reached nobody in 24h: failed, blocked, or let go by the Manager or by nobody", () => {
    const rows = [
      page("failed", { state: "failed" }),
      page("blocked", { state: "blocked" }),
      page("manager", { state: "rejected", approved_by: "manager" }),
      page("unattended", { state: "rejected", approved_by: "unattended" }),
      page("declined", { state: "rejected", approved_by: "human:op-1" }),
      page("delivered"),
      page("old", { state: "blocked", created_at: ago(30 * hour) }),
      { ...page("not-a-page", { state: "failed" }), type: "aws.disable_access_key" },
    ];
    expect(unsentPages(rows, now).map((a) => a.action_uid)).toEqual(["failed", "blocked", "manager", "unattended"]);
  });
});
