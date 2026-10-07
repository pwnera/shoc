/**
 * Time by incident type: one row per type, a bar per phase (detect, triage,
 * contain, resolve) on one log axis shared by every bar, with its m, h and d
 * ticks over each phase. Under 1024px a row keeps resolve and its popup holds
 * all four. A row opens that popup (`?type=`), which links the window's
 * closed cases.
 *
 * Capabilities used: none of its own; metrics.get arrives from the page.
 */
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Meter } from "@/components/ui/meter";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { num, span } from "@/lib/format";
import type { IncidentMetrics } from "@/types";
import { useNarrow } from "@/lib/media";
import { useFollow, useOpen } from "@/lib/popup";

const PHASES = [
  { key: "mttd_minutes", label: "Detect" },
  { key: "time_to_triage_minutes", label: "Triage" },
  { key: "time_to_contain_minutes", label: "Contain" },
  { key: "mttr_minutes", label: "Resolve" },
] as const;

export type TypeRow = IncidentMetrics & { type: string };

/* The type column is capped, so the phases share the rest and a bar's length reads against its ticks. */
const TYPE = 240;
const TYPE_NARROW = 160;
/* Table's own floor for a column without a width: the head's grid keeps the same one. */
const PHASE_MIN = 160;
/* The value beside a bar has a fixed width, so every track, and the axis over it, starts and ends at the same x. */
const VALUE = "w-[6ch] shrink-0 text-right";
const TICKS = [
  { minutes: 1, label: "m" },
  { minutes: 60, label: "h" },
  { minutes: 1440, label: "d" },
];

/** A duration on the shared log axis: minutes to a share of the slowest. */
const logShare = (minutes: number, max: number) => Math.log10(1 + minutes) / Math.log10(1 + Math.max(1, max));

function PhaseBar({ minutes, max, label }: { minutes: number | null; max: number; label: string }) {
  if (minutes === null) return <span className="sh-mono text-fg-4">—</span>;
  const text = span(minutes * 60);
  return (
    <span className="flex w-full items-center gap-2">
      <Meter value={logShare(minutes, max)} showValue={false} label={label} valueText={text} className="min-w-0 flex-1" />
      <span className={`sh-mono text-fg-2 ${VALUE}`}>{text}</span>
    </span>
  );
}

/** A phase's head: its name, and under it where a minute, an hour and a day fall on the axis. */
function Axis({ label, max, ticks }: { label: string; max: number; ticks: boolean }) {
  return (
    <span className="flex flex-col gap-0.5 px-[var(--cell-pad-x)] py-1">
      <span>{label}</span>
      <span className="flex items-center gap-2" aria-hidden>
        <span className="relative h-3 min-w-0 flex-1">
          {ticks
            ? TICKS.filter((t) => t.minutes <= max).map((t) => (
                <span
                  key={t.label}
                  className="absolute top-0 -translate-x-1/2 normal-case leading-3"
                  style={{ left: `${logShare(t.minutes, max) * 100}%` }}
                >
                  {t.label}
                </span>
              ))
            : null}
        </span>
        <span className={VALUE} />
      </span>
    </span>
  );
}

export function Times({
  types,
  loading,
  error,
  onRetry,
  empty,
  closedLink,
}: {
  types: TypeRow[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  empty: string;
  closedLink: string;
}) {
  const navigate = useNavigate();
  const narrow = useNarrow();
  const phases = narrow ? PHASES.slice(-1) : PHASES;
  const type = narrow ? TYPE_NARROW : TYPE;
  const slowest = Math.max(1, ...types.flatMap((t) => PHASES.map((p) => t[p.key] ?? 0)));
  const dialog = useOpen("type", types.map((t) => t.type));
  const nav = useListNav(types, (t) => t.type, { onOpen: (t) => dialog.open(t.type) });
  useFollow(nav, dialog.value);
  const picked = types[dialog.at];

  const columns: Column<TypeRow>[] = [
    {
      label: "",
      width: type,
      cell: (t) => (
        <>
          <span className="text-fg-1">{t.type}</span>
          <span className="sh-mono text-fg-4"> ({num(t.cases)})</span>
        </>
      ),
    },
    ...phases.map(
      (p): Column<TypeRow> => ({
        label: "",
        truncate: false,
        cell: (t) => <PhaseBar minutes={t[p.key]} max={slowest} label={`${t.type} ${p.label.toLowerCase()}`} />,
      }),
    ),
  ];
  const minWidth = type + phases.length * PHASE_MIN;

  return (
    <>
      {/* The head and the rows scroll together, so the axis stays over its bars. */}
      <div className="overflow-x-auto scrollbar-thin">
        <div style={{ minWidth }}>
          <div
            className="grid border-b border-line-1 text-fg-4 uppercase [font:var(--text-label)] tracking-[var(--tracking-label)]"
            style={{ gridTemplateColumns: `${type}px repeat(${phases.length}, minmax(0, 1fr))` }}
            aria-hidden
          >
            <span className="self-start px-[var(--cell-pad-x)] py-1">Type</span>
            {phases.map((p) => (
              <Axis key={p.key} label={p.label} max={slowest} ticks={types.length > 0} />
            ))}
          </div>
          <Table
            label="Time by incident type"
            columns={columns}
            rows={types}
            rowKey={(t) => t.type}
            rowProps={nav.rowProps}
            loading={loading}
            error={error}
            onRetry={onRetry}
            empty={empty}
          />
        </div>
      </div>
      {picked ? (
        <Dialog
          key={picked.type}
          title={picked.type}
          size="sm"
          step={dialog.step}
          onClose={dialog.close}
          footer={
            <Button variant="ghost" onClick={() => navigate(closedLink)}>
              Closed cases
            </Button>
          }
        >
          <Fields
            ruled
            rows={[
              ["Cases", num(picked.cases)],
              ...PHASES.map((p): [string, string] => [p.label, picked[p.key] === null ? "—" : span((picked[p.key] ?? 0) * 60)]),
            ]}
          />
        </Dialog>
      ) : null}
    </>
  );
}
