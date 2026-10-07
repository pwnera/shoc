/**
 * What the crew could not see, as one warn chip on the strip, only when there
 * is something: cited events the store no longer holds, a timeline cut at its
 * limit, older messages left out of the discussion, and in-case roles that
 * never spoke. Each is a typed row, never a sentence about the case.
 */
import { Popover } from "@/components/ui/pop";
import { Mark } from "@/components/ui/status";
import { count } from "@/lib/format";
import type { CaseRecord, TimelineResult } from "@/types";
import { gapsOf } from "./moments";

export function Gaps({ data, timeline }: { data: CaseRecord; timeline?: TimelineResult }) {
  const rows = gapsOf(data, timeline);
  if (!rows.length) return null;
  return (
    <Popover
      pad
      align="end"
      label="Gaps"
      trigger={(props) => (
        <button {...props} type="button" className="sh-chip text-warn">
          <Mark tone="warn" />
          {count(rows.length, "gap")}
        </button>
      )}
    >
      <ul className="m-0 flex list-none flex-col gap-1 p-0 font-mono text-xs text-fg-2">
        {rows.map((row) => (
          <li key={row} className="flex items-center gap-2">
            <Mark tone="warn" />
            {row}
          </li>
        ))}
      </ul>
    </Popover>
  );
}
