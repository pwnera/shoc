/**
 * Console guidelines (UI-G) checked over the whole of console/src rather than
 * one screen: who keeps source.list fresh on each route, which commands ask
 * before they run, what a link may point at, and which mutations forget a
 * secret. Each table below is reviewed; a stale entry fails like a new gap.
 */
import { describe, expect, it, vi } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { COMMANDS } from "@/lib/commands";
import { ROUTES } from "@/lib/nav";
import { ON_SOURCES } from "@/lib/reads";

vi.mock("@/lib/stream", async (original) => ({ ...(await original<typeof import("@/lib/stream")>()), streamState: () => "live" }));

const SRC = join(__dirname, "..", "src");
const CONTRACT = join(__dirname, "..", "..", "contract", "v1.json");
const INVARIANTS = join(__dirname, "..", "..", "tests", "unit", "test_security_invariants.py");

/** Every file under `dir` whose name ends in `ext`. */
function files(dir: string, ext: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return files(path, ext);
    return entry.name.endsWith(ext) ? [path] : [];
  });
}

describe("source.list's freshness owner on every route (UI-G4)", () => {
  /** Whether the route renders source.list live, so polls it while the stream is live too. */
  const POLLED: Record<(typeof ROUTES)[number], boolean> = {
    "/": false,
    "/cases": false,
    "/cases/:caseUid": false,
    "/findings": false,
    "/findings/:findingUid": false,
    "/explore": false,
    "/detection": false,
    "/detection/rules/:ruleId": false,
    "/response": false,
    "/response/playbooks/:playbookId": false,
    "/hunts": false,
    "/intel": false,
    "/posture": false,
    "/memory": false,
    "/connections": true,
    "/health": true,
    "/health/:tab": true,
    "/health/jobs": true,
    "/measurement": false,
    "/access": false,
  };

  it("polls source.list on every route from ROUTES that renders it", () => {
    expect(Object.keys(POLLED).sort()).toEqual([...ROUTES].sort());
    try {
      for (const route of ROUTES) {
        window.history.replaceState(null, "", route.replace(/:[^/]+/g, "x1"));
        expect(ON_SOURCES.refetchInterval(), route).toBe(POLLED[route] ? 30_000 : false);
      }
    } finally {
      window.history.replaceState(null, "", "/");
    }
  });
});

describe("a command that writes or spends (UI-G13)", () => {
  /** Levelled commands without `confirm`: each handler only opens a dialog that asks. */
  const CONFIRMS_ITSELF: Record<string, string> = {
    "overview.approve": "the approval card's own confirm (components/ui/approval.tsx)",
    "case.approve": "the approval card's own confirm (components/ui/approval.tsx)",
    "decide.approve": "the approval card's own confirm (components/ui/approval.tsx)",
    "case.close": "opens CloseDialog",
    "detection.run-all": "opens the Run every rule confirm in the screen's menu",
    "detection.work": "opens the Detection Engineer confirm",
    "rule.run": "opens the Run now confirm in the rule's menu",
    "hunts.daily": "opens the daily hunts confirm",
    "sources.onboard-all": "opens the Integrator confirm in the screen's menu",
    "access.invite": "opens the invite form",
    "access.new-token": "opens the new token form",
    "backlog.revert": "opens the revert confirm",
    "action.undo": "opens the undo confirm",
  };

  it("leaves no levelled command without a confirm", () => {
    const bare = COMMANDS.filter((c) => c.level && !c.confirm && !(c.id in CONFIRMS_ITSELF)).map((c) => c.id);
    expect(bare, "set confirm: true, or open a dialog that asks and list it in CONFIRMS_ITSELF").toEqual([]);
    const stale = Object.keys(CONFIRMS_ITSELF).filter((id) => {
      const c = COMMANDS.find((command) => command.id === id);
      return !c || !c.level || c.confirm;
    });
    expect(stale, "no longer a levelled command without confirm: drop from CONFIRMS_ITSELF").toEqual([]);
  });

  /** `confirm: true` says the handler writes or spends at once, yet these declare no level. */
  const KNOWN_UNLEVELLED: Record<string, string> = {
    "source.pull": "known gap: source.sync with no level",
    "pack.run": "known gap: hunt.pack with no level",
    "indicator.sweep": "known gap: a 90-day intel sweep with no level",
  };

  it("gives every command that asks before it runs a level", () => {
    const bare = COMMANDS.filter((c) => c.confirm && !c.level && !(c.id in KNOWN_UNLEVELLED)).map((c) => c.id);
    expect(bare, "declare the level its capability runs at").toEqual([]);
    const stale = Object.keys(KNOWN_UNLEVELLED).filter((id) => {
      const c = COMMANDS.find((command) => command.id === id);
      return !c || !c.confirm || c.level;
    });
    expect(stale, "levelled now: drop from KNOWN_UNLEVELLED").toEqual([]);
  });
});

describe("a link drawn from data (UI-G9)", () => {
  /** `file:expression` links that are not built through safeHref, and why each may stay. */
  const ALLOWED: Record<string, string> = {
    "components/TokenGate.tsx:href": "the landing page's in-page anchors (#how, #sources, #faq), a literal list",
    "components/TokenGate.tsx:link.href": "FOOTER, literal links under REPO",
    "components/Welcome.tsx:otpauth": "the otpauth:// enrolment link user.invite and user.reset return for this person",
    "routes/detection/parts.tsx:to": "LinkChip's external link; every external LinkChip is checked below",
    "routes/intel/Queue.tsx:link": "known gap: hostOf in routes/intel/feeds.ts repeats safeHref's http(s) test; call safeHref",
  };

  /** The text inside each `{...}` that follows `attribute`, with its line. */
  function expressions(text: string, attribute: RegExp): { line: number; expr: string }[] {
    return [...text.matchAll(attribute)].map((m) => {
      const at = m.index ?? 0;
      const start = at + m[0].length;
      let depth = 1;
      let i = start;
      for (; i < text.length && depth; i++) depth += text[i] === "{" ? 1 : text[i] === "}" ? -1 : 0;
      return { line: text.slice(0, at).split("\n").length, expr: text.slice(start, i - 1).trim() };
    });
  }

  /** Built by safeHref or attackUrl, from a module's own https constant, or a local assigned from safeHref. */
  function safe(expr: string, text: string): boolean {
    if (/^(safeHref|attackUrl)\(/.test(expr)) return true;
    const constant = /^(?:`\$\{)?([A-Z][A-Z0-9_]*)\b/.exec(expr)?.[1];
    if (constant && (expr === constant || expr.startsWith("`${")))
      return new RegExp(`^const ${constant} = ["\`]https://`, "m").test(text);
    if (/^\w+$/.test(expr)) return new RegExp(`\\b(?:const|let) ${expr} = safeHref\\(`).test(text);
    return false;
  }

  it("links only through safeHref or a module constant", () => {
    const seen = new Set<string>();
    const unsafe: string[] = [];
    for (const file of files(SRC, ".tsx")) {
      const text = readFileSync(file, "utf8");
      const name = relative(SRC, file).split("\\").join("/");
      const links = [
        ...expressions(text, /\bhref=\{/g),
        ...expressions(text, /<LinkChip\b[^>]*\bexternal\b[^>]*\bto=\{/g),
      ];
      for (const { line, expr } of links) {
        if (safe(expr, text)) continue;
        const key = `${name}:${expr}`;
        seen.add(key);
        if (!(key in ALLOWED)) unsafe.push(`${name}:${line} href={${expr}}`);
      }
    }
    expect(unsafe, "build a link from data with safeHref (lib/url.ts)").toEqual([]);
    expect(Object.keys(ALLOWED).filter((key) => !seen.has(key)), "gone: drop from ALLOWED").toEqual([]);
  });
});

describe("a secret in the mutation cache (UI-G10)", () => {
  const CREDENTIAL = ["secret", "api_key", "bot_token", "signing_secret", "client_secret"];
  /** Hooks of a secret-taking capability that never send the secret, so keep the default cache. */
  const NO_SECRET_SENT: Record<string, string> = {
    useConfigureFeed: "switches a feed on or off: feed, enabled, parser, settings",
    useAddReportSource: "adds a preset or an RSS feed by URL",
    useToggleSource: "pauses or resumes a source; its settings go back, its secret is never sent",
  };

  it.skipIf(!(existsSync(CONTRACT) && existsSync(INVARIANTS)) && !process.env.CI)(
    "passes gcTime 0 for every capability that takes or returns a secret",
    () => {
      type Contract = { capabilities: Record<string, { input_schema: { properties?: Record<string, unknown> } }> };
      const { capabilities } = JSON.parse(readFileSync(CONTRACT, "utf8")) as Contract;
      const takes = Object.entries(capabilities)
        .filter(([, c]) => Object.keys(c.input_schema.properties ?? {}).some((p) => CREDENTIAL.includes(p)))
        .map(([name]) => name);
      const listed = /SECRET_RETURNING = \{([^}]*)\}/.exec(readFileSync(INVARIANTS, "utf8"))?.[1] ?? "";
      const returns = [...listed.matchAll(/"([a-z_.]+)"/g)].map((m) => m[1]!);
      expect(takes.length).toBeGreaterThan(0);
      expect(returns.length).toBeGreaterThan(0);
      const secret = [...new Set([...takes, ...returns])];

      const text = readFileSync(join(SRC, "lib", "queries.ts"), "utf8");
      const hooks = [...text.matchAll(/^(?:export )?function (\w+)[<(][\s\S]*?^}/gm)].map((m) => ({ name: m[1]!, body: m[0] }));
      const count = (body: string, cap: string) => body.split(`"${cap}"`).length - 1;
      for (const cap of secret)
        expect(hooks.reduce((n, h) => n + count(h.body, cap), 0), `${cap} named outside a function in lib/queries.ts`).toBe(
          count(text, cap),
        );

      const kept = hooks.filter((h) => secret.some((cap) => count(h.body, cap)) && !/\bgcTime:\s*0\b/.test(h.body)).map((h) => h.name);
      expect(kept.filter((name) => !(name in NO_SECRET_SENT)), "pass { gcTime: 0 } to useRefreshing").toEqual([]);
      expect(Object.keys(NO_SECRET_SENT).filter((name) => !kept.includes(name)), "gone: drop from NO_SECRET_SENT").toEqual([]);
      for (const name of Object.keys(NO_SECRET_SENT)) {
        const body = hooks.find((h) => h.name === name)?.body ?? "";
        expect(CREDENTIAL.filter((word) => new RegExp(`\\b${word}\\b`).test(body)), `${name} now sends a secret`).toEqual([]);
      }
    },
  );
});
