/**
 * Exposed × privileged as a 2×2, counted from the same rows as the list below
 * so the numbers agree. A cell toggles the list's filter; arrow keys move
 * between cells. Stale entities outline their cell's count; above zero a cell
 * takes its flag's look (`FLAGS`), the one the rows' badges take.
 */
import { useRef, type KeyboardEvent } from "react";
import { cn } from "@/lib/cn";
import { Skel } from "@/components/ui/state";
import { Tip } from "@/components/ui/tip";
import type { Exposure } from "@/types";
import { CELL_FLAG, CELLS, cellOf, FLAGS, type Cell } from "./cells";

/* The status tones as a cell border and ink; privileged brings its own classes. */
const TONE = { bad: "border-bad-line text-bad", warn: "border-warn-line text-warn", idle: "" } as const;

const GRID: Cell[][] = [
  ["ep", "en"],
  ["np", "nn"],
];
const STEP: Record<string, [number, number]> = { ArrowUp: [-1, 0], ArrowDown: [1, 0], ArrowLeft: [0, -1], ArrowRight: [0, 1] };

export function Quadrant({
  rows,
  loading,
  unknown,
  value,
  onPick,
}: {
  rows: Exposure[];
  loading: boolean;
  /** The rows failed to load: every count reads "—", never zero. */
  unknown?: boolean;
  value: string;
  onPick: (cell: Cell) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const tally = (cell: Cell) => {
    const members = rows.filter((e) => cellOf(e) === cell);
    return { n: members.length, stale: members.filter((e) => e.stale).length };
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = STEP[event.key];
    const at = (event.target as HTMLElement).dataset.cell as Cell | undefined;
    if (!step || !at) return;
    event.preventDefault();
    const r = GRID.findIndex((row) => row.includes(at));
    const c = GRID[r]!.indexOf(at);
    const next = GRID[(r + step[0] + 2) % 2]![(c + step[1] + 2) % 2]!;
    box.current?.querySelector<HTMLElement>(`[data-cell="${next}"]`)?.focus();
  };

  const head = "sh-micro uppercase";
  return (
    <div
      ref={box}
      role="group"
      aria-label="Exposed by privileged"
      onKeyDown={onKeyDown}
      className="grid w-fit grid-cols-[auto_96px_96px] items-center gap-1"
    >
      <span />
      <span className={cn(head, "text-center")}>privileged</span>
      <span className={cn(head, "text-center")}>not privileged</span>
      {GRID.map((row, r) => (
        <div key={r} className="contents">
          <span className={cn(head, "pr-2 text-right")}>{r === 0 ? "exposed" : "not exposed"}</span>
          {row.map((cell) => {
            const { n, stale } = tally(cell);
            const label = CELLS.find((c) => c.id === cell)!.label;
            const flag = n > 0 && !unknown ? CELL_FLAG[cell] : null;
            const look = flag ? FLAGS[flag] : null;
            const pressed = value === cell;
            return (
              <Tip key={cell} label={stale ? `${label} · ${stale} stale` : label}>
                <button
                  type="button"
                  data-cell={cell}
                  tabIndex={cell === (value || "ep") ? 0 : -1}
                  aria-pressed={pressed}
                  aria-label={`${label}: ${loading ? "loading" : unknown ? "unknown" : n}${stale ? `, ${stale} stale` : ""}`}
                  onClick={() => onPick(cell)}
                  className={cn(
                    "flex h-12 items-center justify-center rounded-[var(--radius-1)] border bg-bg-1 transition-colors hover:bg-bg-2",
                    look ? (look.className ?? TONE[look.tone ?? "idle"]) : "border-line-1 text-fg-1",
                    pressed && "bg-bg-2 shadow-[inset_0_0_0_1px_var(--fg-1)]",
                  )}
                >
                  {loading ? (
                    <Skel kind="fact" />
                  ) : unknown ? (
                    <span style={{ font: "var(--text-fact)" }}>—</span>
                  ) : (
                    <span
                      className={cn(
                        "px-1.5 tabular-nums",
                        stale && "rounded-[2px] outline-1 outline-offset-1 outline-dashed outline-idle-dot",
                      )}
                      style={{ font: "var(--text-fact)" }}
                    >
                      {n.toLocaleString()}
                    </span>
                  )}
                </button>
              </Tip>
            );
          })}
        </div>
      ))}
    </div>
  );
}
