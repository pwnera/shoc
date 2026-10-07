import { describe, expect, it } from "vitest";
import { byOrigin, origin, ownedByHealth } from "@/lib/alerts";
import type { OpsAlert } from "@/types";

function alert(kind: string, subject: string, severity = "medium"): OpsAlert {
  return { kind, subject, detail: "", severity };
}

describe("ops alerts by origin", () => {
  it("send each alert to the area and screen that owns it", () => {
    expect(origin(alert("source.stale", "okta"))).toEqual({
      area: "connections",
      group: "okta",
      to: "/connections?source=okta",
    });
    expect(origin(alert("source.quality", "Okta System Log")).to).toBe(
      "/connections?tab=quality&product=Okta%20System%20Log",
    );
    expect(origin(alert("rule.noisy", "aws_root_login")).to).toBe("/detection/rules/aws_root_login");
    expect(origin(alert("case.stalled", "CASE-1")).to).toBe("/cases/CASE-1");
    expect(origin(alert("approval.waiting", "response")).to).toBe("/");
    expect(origin(alert("hunt.gap", "pack_1")).to).toBe("/hunts?pack=pack_1");
    expect(origin(alert("action.stuck", "ACT-1")).to).toBe("?action=ACT-1");
    expect(origin(alert("audit.broken", "chain")).to).toBe("/access?tab=audit");
    expect(origin(alert("llm.failing", "claude"))).toMatchObject({ group: "Model", to: "/health/crew" });
    expect(origin(alert("cost.unpriced", "m")).to).toBe("/health/spend");
    expect(origin(alert("jobs.failed", "worker")).to).toBe("/health/jobs");
  });

  it("leave Health only the platform's own kinds", () => {
    expect(["jobs.failed", "llm.failing", "cost.over_budget"].every((k) => ownedByHealth(alert(k, "x")))).toBe(true);
    expect(["source.stale", "rule.noisy", "case.stalled", "hunt.gap"].some((k) => ownedByHealth(alert(k, "x")))).toBe(false);
  });

  it("group one log source's alerts together, the worst group first", () => {
    const groups = byOrigin([
      alert("jobs.failed", "worker"),
      alert("source.quality", "okta"),
      alert("source.stale", "okta", "high"),
      alert("source.quality", "github"),
    ]);
    expect(groups.map((g) => g.group)).toEqual(["okta", "Worker", "github"]);
    expect(groups[0]?.alerts).toHaveLength(2);
  });
});
