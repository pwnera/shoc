import { describe, expect, it } from "vitest";
import { safeHref } from "@/lib/url";

describe("links from kernel data", () => {
  it("link http and https only", () => {
    expect(safeHref("https://example.com/report")).toBe("https://example.com/report");
    expect(safeHref(" HTTP://example.com ")).toBe("HTTP://example.com");
  });

  it("draw every other scheme as text", () => {
    for (const url of ["javascript:alert(1)", "data:text/html,<b>x</b>", "file:///etc/passwd", "ms-msdt:/id", "//example.com", "", "https://"])
      expect(safeHref(url)).toBeUndefined();
  });
});
