/**
 * Events over the window, 64px, failures stacked in bad under the rest.
 * Brushing or clicking a bucket zooms in (a history step); a double click
 * zooms out to twice the window. The box keeps its size between runs: the
 * previous answer stays drawn while the next one loads, and a window with no
 * events keeps only its time axis.
 */
import { Skel } from "@/components/ui/state";
import { TimeBar } from "@/components/ui/timebar";
import type { Summary } from "@/types";
import { buckets } from "./query";

export function Histogram({
  all,
  failed,
  range,
  pending,
  onZoom,
}: {
  all?: Summary;
  failed?: Summary;
  range: { from: number; to: number };
  pending: boolean;
  onZoom: (from: number, to: number) => void;
}) {
  // Empty buckets would draw a flat line under a "1" on the y axis, as if there were data.
  const bars = all?.total ? buckets(all.rows, failed?.rows ?? [], all.interval, range) : [];
  const zoomOut = () => {
    const half = range.to - range.from;
    onZoom(range.from - half / 2, Math.min(Date.now(), range.to + half / 2));
  };
  return (
    <div className={bars.length ? "h-16" : String.raw`h-16 [&_.sh-timebar\_\_ymax]:invisible`} onDoubleClick={zoomOut}>
      {pending && !all ? (
        <Skel kind="block" className="h-full w-full" />
      ) : (
        <TimeBar
          variant="bars"
          from={new Date(bars[0] ? Date.parse(bars[0].from) : range.from).toISOString()}
          to={new Date(range.to).toISOString()}
          bars={bars}
          onBrush={(brushed) => brushed && onZoom(Date.parse(brushed.from), Date.parse(brushed.to))}
          onBucket={(bucket) => onZoom(Date.parse(bucket.from), Date.parse(bucket.to))}
          label={`Events per ${all?.interval || "hour"}`}
        />
      )}
    </div>
  );
}
