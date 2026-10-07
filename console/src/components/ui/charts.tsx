/**
 * Labelled horizontal bars: a mono label, a 6px track, the value. One grid for
 * every row, so the label and value columns size to their longest content.
 * Charts are not the crew: bars are neutral unless a tone says otherwise.
 * (Time charts are `TimeBar`.)
 */
import type { MeterTone } from "./meter";

export function BarList({
  rows,
  format = (value) => value.toLocaleString(),
  tone,
  onPick,
  label,
}: {
  rows: { label: string; value: number; tone?: MeterTone; key?: string }[];
  format?: (value: number) => string;
  tone?: MeterTone;
  /** Makes each label a button: a pivot to the slice. */
  onPick?: (label: string) => void;
  label?: string;
}) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <ul className="sh-barlist" aria-label={label}>
      {rows.map((row) => (
        <li key={row.key ?? row.label}>
          {onPick ? (
            <button type="button" className="sh-barlist__label" onClick={() => onPick(row.label)} title={row.label}>
              {row.label}
            </button>
          ) : (
            <span className="sh-barlist__label" title={row.label}>
              {row.label}
            </span>
          )}
          <span className="sh-barlist__track" aria-hidden>
            <span
              className="sh-barlist__fill"
              data-tone={row.tone ?? tone}
              style={{ width: `${(row.value / max) * 100}%` }}
            />
          </span>
          <span className="sh-barlist__value">{format(row.value)}</span>
        </li>
      ))}
    </ul>
  );
}
