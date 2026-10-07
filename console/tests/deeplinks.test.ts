import { describe, expect, it } from "vitest";
import { DEEP_LINKS } from "@/lib/popup";

// Every screen's source, to read its filter dimensions without rendering it.
const sources = import.meta.glob("../src/routes/**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

describe("deep links and filters", () => {
  it("never uses a shell dialog's parameter as a list filter", () => {
    const clashes: string[] = [];
    for (const [file, text] of Object.entries(sources))
      for (const [, id] of text.matchAll(/\{\s*id:\s*"(\w+)",\s*label:/g))
        if ((DEEP_LINKS as readonly string[]).includes(id!)) clashes.push(`${file}: ${id}`);
    expect(clashes).toEqual([]);
  });
});
