import { describe, expect, it } from "vitest";
import { badged, markFor, titleFor } from "@/lib/title";

describe("the tab title and icon", () => {
  it("leads with the inbox count, left out at zero", () => {
    expect(titleFor("Cases", 2)).toBe("(2) Cases · shoc");
    expect(titleFor("CASE-172f…", 0)).toBe("CASE-172f… · shoc");
    expect(titleFor("", 0)).toBe("shoc");
  });

  it("marks the icon for decisions, and red wins for a critical case", () => {
    expect(markFor(0, false)).toBe("plain");
    expect(markFor(3, false)).toBe("crew");
    expect(markFor(3, true)).toBe("critical");
    expect(markFor(0, true)).toBe("critical");
  });

  it("draws the corner square into the mark", () => {
    const uri = badged('<svg viewBox="0 0 1 1"><rect/></svg>', "red");
    expect(uri.startsWith("data:image/svg+xml,")).toBe(true);
    expect(decodeURIComponent(uri)).toContain('fill="red"');
    expect(decodeURIComponent(uri).endsWith("</svg>")).toBe(true);
  });
});
