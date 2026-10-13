/**
 * The image's CSP allows index.html's inline theme script by its hash (SEC-1).
 * Vite's dev server sends no CSP, so an edit or a reformat of that script would
 * be blocked in production only, and a saved dark theme would flash light.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const read = (...path: string[]) => readFileSync(join(__dirname, "..", ...path), "utf8");

describe("the content security policy", () => {
  it("names the hash of the inline theme script on every CSP line nginx sends", () => {
    const script = /<script>([\s\S]*?)<\/script>/.exec(read("index.html"))?.[1];
    expect(script, "index.html's inline script").toBeDefined();
    const hash = createHash("sha256").update(script ?? "").digest("base64");
    const policies = read("deploy", "nginx.conf")
      .split("\n")
      .filter((line) => line.includes("Content-Security-Policy"));
    expect(policies.length).toBeGreaterThan(0);
    for (const policy of policies) expect(policy).toContain(`'sha256-${hash}'`);
  });
});
