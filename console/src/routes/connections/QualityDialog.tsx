/**
 * One product's data quality: the four axes as meters against their
 * thresholds, history as progress toward the 30 days a hunt needs (neutral
 * while the product is younger), the last day's volume against its 30-day
 * average, and per field (named as Explore names it) how often it is filled,
 * with the rules that read it by title, each opening its page. The kernel's
 * notes are never shown; the fields say the same.
 *
 * Capabilities used: health.quality, health.cost, events.summarize, rule.list
 * (titles), and source.list and health.sources (which sources push).
 */
import { Link } from "react-router-dom";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Meter } from "@/components/ui/meter";
import { Empty, Label } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { fieldPath } from "@/lib/explore";
import { span } from "@/lib/format";
import { useRules } from "@/lib/queries";
import { qualityTone } from "@/lib/sources";
import type { SourceQuality } from "@/types";
import { VolumeMark } from "./Quality";
import { SCORE_MARKS, useVolume, volumeText } from "./state";

const HUNT_DAYS = 30;

export function QualityDialog({
  row,
  step,
  onClose,
}: {
  row: SourceQuality;
  step: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const volume = useVolume();
  const rules = useRules();
  const title = new Map((rules.data?.rules ?? []).map((r) => [r.id, r.title]));
  const v = volume.of(row.product);
  const fields = Object.entries(row.fields).sort(([, a], [, b]) => a - b);
  const axis = (label: string, value: number, text?: string) => (
    <Meter value={value} tone={qualityTone} marks={SCORE_MARKS} label={label} width={160} format={text ? () => text : undefined} />
  );
  return (
    <Dialog
      title={row.product}
      head={<Meter badge value={row.score} tone={qualityTone} marks={SCORE_MARKS} label="Quality" />}
      step={step}
      onClose={onClose}
    >
      <Fields
        ruled
        rows={[
          ["Arriving", axis("Arriving", row.completeness)],
          [
            "History",
            <Meter
              value={Math.min(row.retention_days, HUNT_DAYS)}
              max={HUNT_DAYS}
              tone={row.retention_days >= HUNT_DAYS ? "good" : "neutral"}
              label="History toward 30 days"
              width={160}
              format={() => `${Math.floor(row.retention_days)} / ${HUNT_DAYS} d`}
            />,
          ],
          ["Delay", axis("Delay", row.timeliness, span(row.timeliness_seconds))],
          ["Fields", axis("Fields", row.field_fidelity)],
          [
            "Volume",
            volume.isError && !volume.data ? "—" : v ? (
              <span className="inline-flex items-center gap-2">
                <VolumeMark volume={v} />
                <span className="sh-mono">{volumeText(v)}</span>
              </span>
            ) : volume.isPending ? (
              "…"
            ) : null,
          ],
        ]}
      />
      <div className="flex flex-col gap-2">
        <Label>fields</Label>
        {fields.length ? (
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {fields.map(([field, rate]) => {
              const readers = row.readers?.[field] ?? [];
              const name = fieldPath(field);
              return (
                <li key={field} className="flex flex-col gap-1">
                  {/* A phone stacks the name over a full-width meter, so the sheet never scrolls sideways. */}
                  <span className="grid gap-1 md:grid-cols-[minmax(0,1fr)_auto] md:items-center md:gap-3">
                    <span className="sh-mono truncate text-fg-2">{name}</span>
                    <Meter
                      value={rate}
                      tone={qualityTone}
                      marks={SCORE_MARKS}
                      label={`${name} filled`}
                      className="max-md:w-full md:[&_.sh-meter\_\_track]:w-24 md:[&_.sh-meter\_\_track]:flex-none"
                    />
                  </span>
                  {readers.length ? (
                    <span className="flex flex-wrap gap-1">
                      {/* Ids only when the titles cannot load: chips that reflow when they arrive read as noise. */}
                      {readers.map((rule) =>
                        rules.isPending ? (
                          <Skel key={rule} kind="badge" width={120} className="h-6" />
                        ) : (
                          <Link key={rule} to={`/detection/rules/${encodeURIComponent(rule)}`} className="sh-chip no-underline">
                            <span className="truncate">{title.get(rule) ?? rule}</span>
                          </Link>
                        ),
                      )}
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : (
          <Empty title="No field is read by a rule" />
        )}
      </div>
    </Dialog>
  );
}
