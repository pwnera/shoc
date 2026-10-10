/**
 * Access › Capabilities: the registry as one list. The areas sit in a rail
 * (sticky, following the scroll, a click jumps); the list scrolls in its own
 * box with each area's name pinned while its rows pass. A row is the audited
 * chain, "you" on the capabilities only a person may call, and the name, with
 * the summary in its tip. Filters (caller, autonomy, audited, text) live in
 * the URL; C copies the active name; a row opens the capability dialog.
 *
 * Capabilities used: capability.list.
 */
import { useRef, useState } from "react";
import { Link2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { AutonomyBadge } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { useCommand, useListNav } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import type { Filters } from "@/lib/filters";
import { useFollow } from "@/lib/popup";
import { useSort } from "@/lib/sort";
import type { CapabilityDoc } from "@/types";
import { areaOf, CAPABILITY_DIMS } from "./parts";

export function Registry({
  query,
  filters,
  rows: given,
  current,
  onOpen,
}: {
  query: {
    data?: { capabilities: CapabilityDoc[] };
    isPending: boolean;
    isLoadingError: boolean;
    error: unknown;
    refetch: () => unknown;
  };
  filters: Filters<CapabilityDoc>;
  rows: CapabilityDoc[];
  /** The capability whose dialog is open: the active row follows it. */
  current: string;
  onOpen: (name: string) => void;
}) {
  const columns: Column<CapabilityDoc>[] = [
    {
      label: "Audit",
      // The glyph's 14px plus the cell's padding, so it is drawn whole and centred on the row.
      width: 40,
      truncate: false,
      sort: (c) => Number(!c.audit),
      cell: (c) =>
        c.audit ? (
          <Tip label="Audited">
            <span role="img" aria-label="audited" className="flex items-center text-fg-4">
              <Link2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
            </span>
          </Tip>
        ) : null,
    },
    {
      label: "Autonomy",
      width: 64,
      truncate: false,
      sort: (c) => c.autonomy,
      cell: (c) => (c.autonomy === "L2" ? <AutonomyBadge level="L2" /> : null),
    },
    {
      label: "Name",
      truncate: false,
      sort: (c) => c.name,
      cell: (c) => (
        <Tip label={c.summary}>
          <span className="sh-mono sh-mono--strong block truncate">{c.name}</span>
        </Tip>
      ),
    },
  ];
  const areas = [...new Set(given.map((c) => areaOf(c.name)))];
  // One sort for every area: a head in any of them orders the capabilities within each.
  const sorted = useSort(given, columns);
  const rows = areas.flatMap((area) => sorted.rows.filter((c) => areaOf(c.name) === area));
  const nav = useListNav(rows, (c) => c.name, { onOpen: (c) => onOpen(c.name) });
  useFollow(nav, current);
  useCommand("access.copy-name", () => void (nav.activeKey && copyAndSay(nav.activeKey)), Boolean(nav.activeKey));

  const box = useRef<HTMLDivElement>(null);
  const [spied, setSpied] = useState("");
  const onScroll = () => {
    const el = box.current;
    if (!el) return;
    const heads = [...el.querySelectorAll<HTMLElement>("[data-area]")];
    const top = el.scrollTop + 8;
    setSpied(heads.filter((h) => h.offsetTop <= top).at(-1)?.dataset.area ?? heads[0]?.dataset.area ?? "");
  };
  const jump = (area: string) => {
    const el = box.current;
    const head = el?.querySelector<HTMLElement>(`[data-area="${CSS.escape(area)}"]`);
    const still = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (el && head) el.scrollTo({ top: head.offsetTop, behavior: still ? "auto" : "smooth" });
    setSpied(area);
    // The area's first capability becomes the active row and takes focus, so the keys carry on from there.
    const first = rows.find((c) => areaOf(c.name) === area)?.name;
    if (!first) return;
    nav.setActive(first);
    el?.querySelector<HTMLElement>(`[data-row-key="${CSS.escape(first)}"]`)?.focus({ preventScroll: true });
  };


  const shown = spied || areas[0] || "";
  return (
    <div className="sh-layout--rail">
      <nav aria-label="Areas" className="sticky top-[calc(var(--topbar-h)+16px)] max-lg:hidden">
        <Card className="max-h-[calc(100dvh-var(--topbar-h)-259px)] overflow-y-auto py-1">
          {query.isPending ? (
            <div className="flex flex-col gap-2 p-3">
              <Skel kind="text" />
              <Skel kind="text" />
              <Skel kind="text" />
            </div>
          ) : (
            <ul className="m-0 list-none p-0">
              {areas.map((area) => (
                <li key={area}>
                  <button
                    type="button"
                    onClick={() => jump(area)}
                    aria-current={area === shown ? "true" : undefined}
                    className={cn(
                      "flex h-7 w-full items-center justify-between gap-2 border-0 bg-transparent px-3 text-left font-mono text-fg-3 hover:bg-bg-2",
                      area === shown && "bg-bg-2 text-fg-1 shadow-[inset_2px_0_0_var(--fg-1)]",
                    )}
                  >
                    <span className="truncate">{area}</span>
                    <span className="text-fg-4">{rows.filter((c) => areaOf(c.name) === area).length}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </nav>
      <Card className="min-w-0">
        <FilterBar
          dims={CAPABILITY_DIMS}
          value={filters.values}
          onChange={filters.set}
          text={filters.text}
          onText={filters.setText}
          onClear={filters.clear}
          placeholder="Filter capabilities"
        />
        <div
          ref={box}
          onScroll={onScroll}
          className="relative h-[calc(100dvh-var(--topbar-h)-300px)] min-h-80 overflow-y-auto scrollbar-thin"
        >
          {query.isPending || query.isLoadingError ? (
            <Table
              columns={columns}
              rows={[]}
              rowKey={(c) => c.name}
              loading={query.isPending}
              error={query.isLoadingError ? query.error : undefined}
              onRetry={() => void query.refetch()}
            />
          ) : !rows.length ? (
            <Empty
              kind="filtered"
              title="No capability matches"
              chips={filters.chips.map((c) => `${c.label} ${c.word}`).join(" · ")}
              onClear={filters.clear}
            />
          ) : (
            areas.map((area) => (
              <section key={area} aria-label={area}>
                <div
                  data-area={area}
                  className="sh-label sticky top-0 z-[2] border-b border-line-1 bg-bg-1 px-3 py-1.5"
                >
                  {area}
                </div>
                <Table
                  label={`${area} capabilities`}
                  columns={columns}
                  rows={rows.filter((c) => areaOf(c.name) === area)}
                  sort={sorted.sort}
                  rowKey={(c) => c.name}
                  rowProps={nav.rowProps}
                />
              </section>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
