import { describe, expect, it } from "vitest";
import { citeIndex, citeLabel } from "@/lib/cite";

describe("E-numbers", () => {
  it("number cited events by time, the earliest E1, whatever order the crew cited them", () => {
    const events = [
      { event_uid: "late", time: "2026-09-25T14:00:00Z" },
      { event_uid: "early", time: "2026-09-25T13:00:00Z" },
      { event_uid: "uncited", time: "2026-09-25T12:00:00Z" },
    ];
    const cites = citeIndex(events, ["late", "early", "gone"]);
    expect(cites.order).toEqual(["early", "late", "gone"]);
    expect(cites.of("early")).toBe(1);
    expect(citeLabel(cites.of("gone")!)).toBe("E3");
    expect(cites.of("uncited")).toBeUndefined();
  });
});
