import { describe, expect, it } from "vitest";
import { begin } from "@/lib/since";

const minute = 60_000;
const now = Date.parse("2026-10-03T12:00:00Z");

describe("the visit window", () => {
  it("covers the last 24 hours on a first visit", () => {
    expect(begin(null, now)).toEqual({ since: now - 24 * 60 * minute, last: now });
  });

  it("starts a new visit at the last heartbeat after 30 minutes away", () => {
    const threeWeeks = now - 21 * 24 * 60 * minute;
    expect(begin({ since: threeWeeks - minute, last: threeWeeks }, now)).toEqual({ since: threeWeeks, last: now });
  });

  it("keeps the window on a reload inside a visit", () => {
    expect(begin({ since: now - 90 * minute, last: now - 5 * minute }, now)).toEqual({
      since: now - 90 * minute,
      last: now,
    });
  });

  it("survives a record that is not one", () => {
    expect(begin({ since: Number.NaN, last: Number.NaN }, now).since).toBe(now - 24 * 60 * minute);
  });
});
