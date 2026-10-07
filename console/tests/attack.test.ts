import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { byTactic, knownTechnique, tacticsOf } from "@/lib/attack";

const CONTENT = join(__dirname, "..", "..", "content");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : /\.ya?ml$/.test(name) ? [path] : [];
  });
}

describe("ATT&CK tactics", () => {
  // A console-only copy has no content/ to read; CI checks out the whole repo, so there a missing one fails.
  it.skipIf(!existsSync(CONTENT) && !process.env.CI)("know every technique the shipped rules, hunts and playbooks cite", () => {
    const cited = new Set<string>();
    for (const file of files(CONTENT))
      for (const m of readFileSync(file, "utf8").matchAll(/\bT1\d{3}(?:\.\d{3})?\b/g)) cited.add(m[0].slice(0, 5));
    expect(cited.size).toBeGreaterThan(0);
    expect([...cited].filter((t) => !knownTechnique(t))).toEqual([]);
  });

  it("give a sub-technique its parent's tactics, in kill-chain order", () => {
    expect(tacticsOf(["T1098.001", "T1078.004"])).toEqual([
      "initial-access",
      "persistence",
      "privilege-escalation",
      "defense-evasion",
    ]);
    expect(byTactic(["T1078.004", "T1530"]).get("collection")).toEqual(["T1530"]);
  });
});
