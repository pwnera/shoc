/**
 * Connections › Quality: one row per product, silent and then worst first, keyed by product until
 * the kernel names the source beside it. A row carries the volume mark (silent
 * or low against its 30-day average, "no recent push" when its sources push) and the
 * score; it opens the quality dialog, which is where `source.quality` alerts land.
 *
 * Capabilities used: health.quality, health.cost (30-day volume),
 * events.summarize (24-hour volume), source.list and health.sources (which
 * sources push).
 */
import { Meter } from "@/components/ui/meter";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { usePaged } from "@/lib/paged";
import { useFollow } from "@/lib/popup";
import { qualityTone, type ShownVolume } from "@/lib/sources";
import type { SourceQuality } from "@/types";
import { SCORE_MARKS, useQualityRows, volumeText } from "./state";

const MARK_TONE = { silent: "bad", low: "warn", "no recent push": "idle" } as const;

export function VolumeMark({ volume }: { volume: ShownVolume | undefined }) {
  if (!volume?.mark) return null;
  return (
    <Tip label={volumeText(volume)}>
      <span className="inline-flex">
        <Mark tone={MARK_TONE[volume.mark]} label={volume.mark} />
      </span>
    </Tip>
  );
}

/** `current` is the product whose dialog is open: the active row follows it. */
export function Quality({ current, onOpen }: { current: string; onOpen: (product: string) => void }) {
  const { quality, volume, rows } = useQualityRows();
  const { page, pager, start, prev, next } = usePaged(rows);
  const nav = useListNav(page, (row) => row.product, {
    onOpen: (row) => onOpen(row.product),
    onPrevPage: prev,
    onNextPage: next,
  });
  useFollow(nav, current);
  const columns: Column<SourceQuality>[] = [
    { label: "", width: 28, truncate: false, cell: (row) => <VolumeMark volume={volume.of(row.product)} /> },
    {
      label: "",
      width: 108,
      truncate: false,
      cell: (row) => (
        <Meter badge value={row.score} tone={qualityTone} marks={SCORE_MARKS} label={`${row.product} quality`} />
      ),
    },
    { label: "", strong: true, cell: (row) => row.product },
  ];
  return (
    <>
      <Table
        label="Data quality, 30 days"
        columns={columns}
        rows={page}
        start={start}
        rowKey={(row) => row.product}
        rowProps={nav.rowProps}
        loading={quality.isPending}
        error={quality.isLoadingError ? quality.error : undefined}
        onRetry={() => void quality.refetch()}
        empty="Nothing to score"
      />
      {pager}
    </>
  );
}
