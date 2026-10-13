import { describe, expect, it } from "vitest";
import { ownedByHealth } from "@/lib/alerts";
import type { OpsAlert } from "@/types";

function alert(kind: string, subject: string): OpsAlert {
  return { kind, subject, detail: "", severity: "medium" };
}

describe("ops alerts on Health", () => {
  it("leave Health only the platform's own kinds", () => {
    expect(["jobs.failed", "llm.failing", "cost.over_budget"].every((k) => ownedByHealth(alert(k, "x")))).toBe(true);
    expect(["source.stale", "rule.noisy", "case.stalled", "hunt.gap"].some((k) => ownedByHealth(alert(k, "x")))).toBe(false);
  });

  it("give reaching a person and the database's size a home in Health, and leave sources and feeds to Connections", () => {
    expect(["notify.unreachable", "page.failed", "store.size"].every((k) => ownedByHealth(alert(k, "x")))).toBe(true);
    expect(
      ["source.partial", "source.failing", "intel.feed_failing", "intel.list_failing"].some((k) => ownedByHealth(alert(k, "x"))),
    ).toBe(false);
  });
});
