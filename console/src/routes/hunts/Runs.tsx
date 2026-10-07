/**
 * Hunts › Runs: every run in the window, newest first. A row is a finding
 * glyph when the run raised one, the outcome, the pack and when it ran; rows
 * returned and duration are in the run dialog, which a row opens (`?run=`) and
 * which steps through the filtered list with J and K.
 */
import { Radar } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import type { Dim, Filters } from "@/lib/filters";
import { age } from "@/lib/format";
import { OUTCOMES } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, usePopParam } from "@/lib/popup";
import type { HuntRun } from "@/types";
import { HuntRunDialog } from "./HuntRunDialog";

export function Runs({
  runs,
  titleOf,
  dims,
  filters,
  days,
  loading,
  error,
  onRetry,
}: {
  runs: HuntRun[];
  titleOf: (packId: string) => string;
  dims: Dim<HuntRun>[];
  filters: Filters<HuntRun>;
  days: string;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const now = useNow();
  const [params] = useSearchParams();
  const rows = runs.filter(filters.keep);
  const paged = usePaged(rows, 25);
  // Opening is a history step, so Back closes the dialog; stepping and closing replace it.
  const pop = usePopParam("run");
  const open = (run: HuntRun | undefined, replace = false) => pop(run && run.run_uid, replace);
  const nav = useListNav(paged.page, (r) => r.run_uid, {
    onOpen: (r) => open(r),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const picked = rows.findIndex((r) => r.run_uid === params.get("run"));
  const run = rows[picked] ?? runs.find((r) => r.run_uid === params.get("run"));
  useFollow(nav, rows[picked]?.run_uid ?? "", { keys: rows.map((r) => r.run_uid), size: 25, go: paged.go });

  const columns: Column<HuntRun>[] = [
    {
      label: "",
      fit: true,
      cell: (r) => {
        const o = OUTCOMES[r.outcome] ?? { word: r.outcome, tone: "idle" as const };
        return (
          <span className="flex items-center gap-2">
            {r.finding_uid ? (
              <Radar className="h-3.5 w-3.5 shrink-0 text-fg-2" role="img" aria-label="raised a finding" />
            ) : (
              <span className="h-3.5 w-3.5 shrink-0" aria-hidden />
            )}
            {/* On a phone the shared row rule applies: a shaped mark alone, an idle one keeps its word. */}
            <Status tone={o.tone} badge>
              {o.word}
            </Status>
          </span>
        );
      },
    },
    { label: "", strong: true, cell: (r) => titleOf(r.pack_id) },
    { label: "", fit: true, mono: true, hide: "md", cell: (r) => age(r.ran_at, now) },
  ];

  return (
    <>
      {/* With no run there is nothing to filter. */}
      {runs.length || loading || filters.active ? (
        <FilterBar
          dims={dims}
          value={filters.values}
          onChange={filters.set}
          text={filters.text}
          onText={filters.setText}
          onClear={filters.clear}
          placeholder="Filter runs"
        />
      ) : null}
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(r) => r.run_uid}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Runs"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No run matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title={`No hunts in ${days} days`} />
          )
        }
      />
      {paged.pager}
      {run ? (
        <HuntRunDialog
          run={run}
          title={titleOf(run.pack_id)}
          onClose={() => open(undefined, true)}
          step={
            picked >= 0
              ? {
                  index: picked,
                  total: rows.length,
                  onPrev: picked > 0 ? () => open(rows[picked - 1], true) : undefined,
                  onNext: picked < rows.length - 1 ? () => open(rows[picked + 1], true) : undefined,
                }
              : undefined
          }
        />
      ) : null}
    </>
  );
}
