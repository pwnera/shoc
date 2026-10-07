/**
 * The fourteen ATT&CK tactics as 24px cells in kill-chain order, lit on the
 * neutral ramp by how many of the given techniques fall under each (never
 * red: a tactic is not a severity). Shown, a lit cell opens the techniques
 * behind it, each linked to ATT&CK; as a filter, each cell toggles a tactic.
 * `compact` draws 20px cells, so the fourteen fit a 320px aside. `named`
 * writes the lit tactics' names under the cells, where the two-letter codes
 * are the record's only mention of them (a case, a finding).
 */
import { attackUrl, TACTIC_SHORT, tacticLabel, tacticsOf, TACTICS, type Tactic } from "@/lib/attack";
import { cn } from "@/lib/cn";
import { Popover } from "./pop";
import { Tip } from "./tip";

export function Tactics({
  techniques,
  mode = "show",
  selected = [],
  onToggle,
  label = "ATT&CK tactics",
  compact,
  named,
}: {
  techniques: readonly string[];
  mode?: "show" | "filter";
  compact?: boolean;
  /** Tactics switched on, in filter mode. */
  selected?: readonly string[];
  onToggle?: (tactic: Tactic) => void;
  label?: string;
  named?: boolean;
}) {
  const under = new Map<Tactic, string[]>();
  for (const technique of new Set(techniques))
    for (const tactic of tacticsOf([technique])) under.set(tactic, [...(under.get(tactic) ?? []), technique]);

  const strip = (
    <div className={cn("sh-tactics", compact && "sh-tactics--compact")} role="group" aria-label={label}>
      {TACTICS.map(([id]) => {
        const list = under.get(id) ?? [];
        const level = list.length ? Math.min(4, list.length) : undefined;
        const name = tacticLabel(id);
        const said = list.length ? `${name}: ${list.join(", ")}` : name;
        if (mode === "filter")
          return (
            <Tip key={id} label={said}>
              <button
                type="button"
                className="sh-tactics__cell"
                data-level={level}
                aria-pressed={selected.includes(id)}
                aria-label={name}
                onClick={() => onToggle?.(id)}
              >
                {TACTIC_SHORT[id]}
              </button>
            </Tip>
          );
        if (!list.length)
          return (
            <Tip key={id} label={name}>
              <span className="sh-tactics__cell" role="img" aria-label={`${name}, none`}>
                {TACTIC_SHORT[id]}
              </span>
            </Tip>
          );
        return (
          <Popover
            key={id}
            pad
            label={name}
            trigger={(props) => (
              <button {...props} type="button" className="sh-tactics__cell" data-level={level} aria-label={said}>
                {TACTIC_SHORT[id]}
              </button>
            )}
          >
            <span className="sh-label">{name}</span>
            <ul className="sh-tactics__list">
              {list.map((technique) => (
                <li key={technique}>
                  <a className="sh-link" href={attackUrl(technique)} target="_blank" rel="noreferrer">
                    {technique}
                  </a>
                </li>
              ))}
            </ul>
          </Popover>
        );
      })}
    </div>
  );
  if (!named || !under.size) return strip;
  return (
    <div className="flex flex-col gap-1">
      {strip}
      <p className="sh-micro m-0 text-fg-3" aria-hidden>
        {TACTICS.filter(([id]) => under.has(id))
          .map(([, name]) => name)
          .join(" · ")}
      </p>
    </div>
  );
}
