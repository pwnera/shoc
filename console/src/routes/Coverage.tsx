/**
 * Coverage: can our working rules and ready hunts see each ATT&CK tactic in
 * the data we actually ingest? The strip meters the tactics at least one
 * working rule covers on a scored product, and how many products have one; the
 * matrix crosses the products Connections › Quality scores (configured sources
 * with events in 30 days) with the tactics. A rule works when it can fire
 * (live, armed or noisy), read live from its health, never from a stored
 * survey; "live" keeps Detection's meaning, a rule that fired in 7 days.
 *
 * The matrix lives here rather than in routes/coverage/: console/.gitignore
 * ignores every `coverage/` folder, so Tailwind never scans one.
 *
 * Capabilities: none of its own. Reads health.quality (the products, the
 * query Connections › Quality holds), rule.list, health.rules and hunt.results
 * (ready packs).
 */
import { useRef, useState, type FocusEvent, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { ProductLogo } from "@/components/ui/logo";
import { Meter } from "@/components/ui/meter";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Popover } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Status } from "@/components/ui/status";
import { Strip } from "@/components/ui/strip";
import { Tip } from "@/components/ui/tip";
import { TACTIC_SHORT, tacticLabel, TACTICS, type Tactic } from "@/lib/attack";
import { ruleState, RULE_STATES } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useHuntResults, useQuality, useRuleHealth, useRules } from "@/lib/queries";
import type { RuleHealth } from "@/types";
import { coverage, logsourceOf, type Cell, type Coverage as Cover } from "./coverage/products";
import { Readiness } from "./hunts/Packs";

const STEP: Record<string, [number, number]> = { ArrowUp: [-1, 0], ArrowDown: [1, 0], ArrowLeft: [0, -1], ArrowRight: [0, 1] };

function Behind({ cell, health, now }: { cell: Cell; health: Map<string, RuleHealth>; now: number }) {
  return (
    <ul className="m-0 flex max-h-72 min-w-64 list-none flex-col gap-1 overflow-y-auto p-0">
      {cell.rules.map((rule) => {
        const state = RULE_STATES.find((s) => s.id === ruleState(health.get(rule.id)));
        return (
          <li key={rule.id} className="flex items-center gap-2">
            {state ? (
              <Status tone={state.tone} label={state.word} />
            ) : null}
            <Link to={`/detection/rules/${encodeURIComponent(rule.id)}`} state={{ back: "/coverage" }} className="sh-link min-w-0 truncate">
              {rule.title}
            </Link>
          </li>
        );
      })}
      {cell.packs.map((pack) => (
        <li key={pack.pack_id} className="flex items-center gap-2">
          <Readiness row={pack} now={now} />
          <Link to={`/hunts?pack=${encodeURIComponent(pack.pack_id)}`} className="sh-link min-w-0 truncate">
            {pack.title ?? pack.pack_id}
          </Link>
        </li>
      ))}
    </ul>
  );
}

/**
 * Scored products × the fourteen ATT&CK tactics. A cell counts the working
 * rules that read that product for that tactic, on the neutral ramp; a dot
 * marks a ready hunt pack; an empty cell is outlined, never red. A cell opens
 * the rules and packs behind it; a product opens Detection filtered to it.
 * One tab stop, on the cell last visited: arrow keys move between cells and
 * left from the first column onto the product, Enter opens.
 */
function Matrix({
  products,
  cover,
  health,
  now,
}: {
  products: string[];
  cover: Cover;
  health: Map<string, RuleHealth>;
  now: number;
}) {
  const box = useRef<HTMLTableElement>(null);
  // Column -1 is the product link; the tab stop stays where focus last was, clamped to today's rows.
  const [last, setLast] = useState<[number, number]>([0, 0]);
  const at: [number, number] = [Math.min(last[0], products.length - 1), last[1]];
  const stop = (r: number, c: number) => (r === at[0] && c === at[1] ? 0 : -1);
  const onFocus = (event: FocusEvent<HTMLTableElement>) => {
    const { r, c } = (event.target as HTMLElement).dataset;
    if (r !== undefined && c !== undefined) setLast([Number(r), Number(c)]);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLTableElement>) => {
    const step = STEP[event.key];
    const el = event.target as HTMLElement;
    if (!step || el.dataset.r === undefined) return;
    event.preventDefault();
    const r = Math.max(0, Math.min(products.length - 1, Number(el.dataset.r) + step[0]));
    const c = Math.max(-1, Math.min(TACTICS.length - 1, Number(el.dataset.c) + step[1]));
    box.current?.querySelector<HTMLElement>(`[data-r="${r}"][data-c="${c}"]`)?.focus();
  };

  return (
    <div className="sh-table-wrap sh-table-wrap--bounded scrollbar-thin" style={{ "--table-max": "560px" } as React.CSSProperties}>
      <table ref={box} className="border-separate border-spacing-0.5" aria-label="Coverage" onKeyDown={onKeyDown} onFocus={onFocus}>
        <thead>
          <tr>
            <th scope="col" className="sticky top-0 left-0 z-40 bg-bg-1">
              <span className="sr-only">Product</span>
            </th>
            {TACTICS.map(([id], c) => (
              // Each head sits over the next, so a name at 45° runs over its neighbour's background, never under it.
              <th key={id} scope="col" className="sticky top-0 bg-bg-1 px-0 pb-1 align-bottom font-normal" style={{ zIndex: 30 - c }}>
                {/* Under 1024px two letters, the name in the tip and for a screen reader. */}
                <Tip label={tacticLabel(id)}>
                  <abbr className="sh-micro block w-6 text-center no-underline min-[1024px]:hidden" aria-hidden>
                    {TACTIC_SHORT[id]}
                  </abbr>
                </Tip>
                <span className="sr-only min-[1024px]:hidden">{tacticLabel(id)}</span>
                {/* From 1024px the tactic's name, at 45°, so fourteen fit over 24px columns. */}
                <span className="relative hidden h-[100px] w-6 min-[1024px]:block">
                  <span className="absolute bottom-1 left-3 origin-bottom-left -rotate-45 [font:var(--text-micro)] whitespace-nowrap text-fg-3">
                    {tacticLabel(id)}
                  </span>
                </span>
              </th>
            ))}
            <th scope="col" className="sticky top-0 z-10 bg-bg-1 max-md:hidden min-[1024px]:min-w-8">
              <span className="sr-only">Rules that can fire</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {products.map((product, r) => {
            const row = cover.cells.get(product);
            const working = cover.working.get(product) ?? 0;
            return (
              <tr key={product}>
                <th scope="row" className="sticky left-0 z-10 bg-bg-1 text-left">
                  <Link
                    to={`/detection?product=${encodeURIComponent(logsourceOf(product))}`}
                    data-r={r}
                    data-c={-1}
                    tabIndex={stop(r, -1)}
                    className="flex items-center gap-2 pr-3 font-normal whitespace-nowrap text-fg-1 hover:underline"
                  >
                    <ProductLogo product={product} />
                    <span className="max-md:max-w-24 max-md:truncate" title={product}>
                      {product}
                    </span>
                    {/* On a phone the last column is off-screen, so the row's warning sits by its name. */}
                    {working ? null : <Status tone="warn" label="no rule can fire" className="ml-auto md:hidden" />}
                  </Link>
                </th>
                {TACTICS.map(([id], c) => {
                  const cell = row?.get(id as Tactic);
                  const n = cell?.rules.length ?? 0;
                  const packs = cell?.packs.length ?? 0;
                  const name = `${product}, ${tacticLabel(id)}: ${n} ${n === 1 ? "rule can" : "rules can"} fire${packs ? `, ${packs} ready ${packs === 1 ? "pack" : "packs"}` : ""}`;
                  const face = (
                    <>
                      {n || ""}
                      {packs ? (
                        <i className="absolute top-0.5 right-0.5 h-1 w-1 rounded-full bg-current" aria-hidden />
                      ) : null}
                    </>
                  );
                  const props = {
                    "data-r": r,
                    "data-c": c,
                    tabIndex: stop(r, c),
                    // A fixed 24px: the phone rule that lets the tactics strip share a row would shrink these to slivers.
                    className: "sh-tactics__cell relative h-6 w-6",
                    "data-level": n ? Math.min(4, n) : undefined,
                    "aria-label": name,
                  };
                  return (
                    <td key={id} className="p-0">
                      {cell ? (
                        <Popover
                          pad
                          label={`${product} · ${tacticLabel(id)}`}
                          trigger={(pop) => (
                            <button type="button" {...pop} {...props}>
                              {face}
                            </button>
                          )}
                        >
                          <span className="sh-label">
                            {product} · {tacticLabel(id)}
                          </span>
                          <Behind cell={cell} health={health} now={now} />
                        </Popover>
                      ) : (
                        <button type="button" {...props} aria-disabled>
                          {face}
                        </button>
                      )}
                    </td>
                  );
                })}
                <td className="pl-3 whitespace-nowrap max-md:hidden">
                  {working ? null : <span className="text-warn">no rule can fire</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Coverage() {
  const now = useNow();
  // The products Connections › Quality scores, from the same query, so the two screens list one set.
  const quality = useQuality(30);
  const rules = useRules();
  const health = useRuleHealth("all");
  // The same key as Hunts' default window, so the two share one fetch.
  const hunts = useHuntResults("", 7, 200);
  const queries = [quality, rules, health, hunts];
  const failed = queries.find((q) => q.isError && !q.data);
  const pending = queries.some((q) => q.isPending);

  const products = (quality.data?.sources ?? []).filter((p) => p.events > 0).map((p) => p.product);
  const byRule = new Map((health.data?.rules ?? []).map((h) => [h.rule_id, h]));
  const cover = coverage(products, rules.data?.rules ?? [], byRule, hunts.data?.readiness ?? []);
  const lit = cover.lit.size;
  const watched = products.filter((p) => (cover.working.get(p) ?? 0) > 0).length;
  const all = TACTICS.length;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Coverage"
        strip={
          <Strip
            state={
              !products.length
                ? { tone: "idle", word: "Nothing arriving" }
                : lit === all
                  ? { tone: "good", word: "Covered" }
                  : { tone: "warn", word: "Partial" }
            }
            loading={pending}
            error={failed?.error}
            onRetry={() => {
              for (const q of queries) if (q.isError) void q.refetch();
            }}
            viz={
              pending || failed ? undefined : (
                <Meter
                  value={lit}
                  max={all}
                  tone={lit === all ? "good" : "warn"}
                  label="Tactics a rule can see"
                  valueText={`${lit} of ${all} tactics`}
                  format={() => `${lit} of ${all} tactics`}
                  size="md"
                />
              )
            }
            facts={[{ label: "products a rule can see", value: products.length ? `${watched} of ${products.length}` : null }]}
          />
        }
      />
      <Card>
        {failed ? (
          <ErrorNote
            error={failed.error}
            onRetry={() => {
              for (const q of queries) if (q.isError) void q.refetch();
            }}
          />
        ) : pending ? (
          <div className="flex flex-col gap-2 p-3" aria-busy="true">
            <span role="status" className="sr-only">
              loading
            </span>
            {Array.from({ length: 6 }, (_, i) => (
              <Skel key={i} kind="row" width={`${60 + ((i * 13) % 30)}%`} />
            ))}
          </div>
        ) : !products.length ? (
          <Empty
            title="No source delivered in 30 days"
            action={
              <Link to="/connections" className="sh-link">
                Connections
              </Link>
            }
          />
        ) : (
          <div className="p-3">
            <Matrix products={products} cover={cover} health={byRule} now={now} />
          </div>
        )}
      </Card>
    </div>
  );
}
