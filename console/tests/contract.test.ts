/**
 * The console's types against contract/v1.json (API-1). Each list below must
 * name every field of its type (tsc refuses a missing or extra one), and the
 * test holds it to the capability's output fields: a renamed or dropped field
 * fails here instead of reading `undefined` on screen.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ActionPage } from "@/lib/reads";
import type { Case, CaseRecord, Finding, Me, PolicyView, SystemHealth } from "@/types";

const CONTRACT = join(__dirname, "..", "..", "contract", "v1.json");

type Schema = { properties?: Record<string, Schema> };
type Contract = { capabilities: Record<string, { input_schema: Schema; output_schema: Schema }> };

const caseRecord: Record<keyof CaseRecord, true> = { case: true, findings: true, openspace: true, openspace_total: true, entities: true };
const casePage: Record<keyof { rows: Case[]; count: number }, true> = { rows: true, count: true };
const actionPage: Record<keyof ActionPage, true> = { rows: true, count: true, waiting_for_approval: true };
const findingPage: Record<keyof { rows: Finding[]; count: number }, true> = { rows: true, count: true };
const me: Record<keyof Me, true> = { id: true, kind: true, role: true, tenant: true, email: true };
const systemHealth: Record<keyof SystemHealth, true> = {
  ok: true,
  store: true,
  sources: true,
  rules: true,
  jobs: true,
  findings: true,
  reachable: true,
  disk: true,
  heartbeat: true,
  schema_ahead: true,
};
const policyView: Record<keyof PolicyView, true> = {
  version: true,
  defaults: true,
  principals: true,
  actions: true,
  guards: true,
  available_actions: true,
  action_params: true,
  dry_run_from: true,
};

const READ: Record<string, Record<string, true>> = {
  "case.get": caseRecord,
  "case.list": casePage,
  "action.list": actionPage,
  "finding.list": findingPage,
  "user.me": me,
  "health.status": systemHealth,
  "policy.show": policyView,
};

/**
 * Fields the console sends by name, or reads through a type written inline at
 * its call (lib/queries.ts): each must still be in the contract. Fields inside
 * an untyped object (`rules.firings`, a source row's `partial`) are not in the
 * contract to check; types.ts keeps them by hand.
 */
const NAMED: [capability: string, side: "input" | "output", fields: string[]][] = [
  ["health.audit", "input", ["limit", "head", "verify"]],
  ["health.audit", "output", ["chain_ok", "rows_verified", "detail", "checked", "head", "recent"]],
  ["case.list", "input", ["state", "verdict", "limit", "unacknowledged", "open"]],
  ["case.close", "output", ["still_in_force"]],
  ["health.sources", "output", ["sources", "ok"]],
  ["graph.neighbours", "output", ["root", "nodes", "edges", "hops"]],
];

describe("the console's types against the contract", () => {
  it.skipIf(!existsSync(CONTRACT) && !process.env.CI)("reads exactly the fields each capability returns", () => {
    const { capabilities } = JSON.parse(readFileSync(CONTRACT, "utf8")) as Contract;
    for (const [capability, fields] of Object.entries(READ)) {
      const data = capabilities[capability]?.output_schema.properties?.data?.properties;
      expect(Object.keys(data ?? {}).sort(), capability).toEqual(Object.keys(fields).sort());
    }
  });

  it.skipIf(!existsSync(CONTRACT) && !process.env.CI)("still has every field the console names", () => {
    const { capabilities } = JSON.parse(readFileSync(CONTRACT, "utf8")) as Contract;
    for (const [capability, side, fields] of NAMED) {
      const cap = capabilities[capability];
      const schema = side === "output" ? cap?.output_schema.properties?.data : cap?.input_schema;
      const known = Object.keys(schema?.properties ?? {});
      expect(fields.filter((f) => !known.includes(f)), `${capability} ${side}`).toEqual([]);
    }
  });
});
