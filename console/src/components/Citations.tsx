/**
 * Evidence, inline.
 *
 * Every agent statement cites event IDs, and an uncited verdict does not
 * count. `Cites` draws the citations as E-chips ("E1 E2 E3 E4 E5 +9"): a chip
 * opens EventDialog stepping over the cited set, "+N" opens the evidence list,
 * and pointing at a chip tells the host (`onPoint`) so the same event lights
 * everywhere on the page. A host that numbers events per case (`lib/cite.ts`)
 * passes `number`.
 *
 * Capabilities used: events.query (by event_uid; EventDialog adds the raw record).
 */
import { Suspense, useState } from "react";
import { citeLabel } from "@/lib/cite";
import { useEvents } from "@/lib/reads";
import { lazyNamed } from "@/lib/stale";
import { Dialog } from "./ui/dialog";

// Loaded on a click: the chat draws E-chips, and the main chunk need not carry the event views.
const EventDialog = lazyNamed(() => import("./EventDialog"), "EventDialog");
const EventTable = lazyNamed(() => import("./EventTable"), "EventTable");

export function Cites({
  uids,
  onPoint,
  highlight,
  number,
  max = 5,
}: {
  uids: string[];
  /** Hover or focus on a chip; null when it ends. */
  onPoint?: (uid: string | null) => void;
  /** Uids lit by another view. */
  highlight?: readonly string[];
  /** The page's E-number of a uid; the position in `uids` otherwise. */
  number?: (uid: string) => number | undefined;
  max?: number;
}) {
  const [open, setOpen] = useState<number | null>(null);
  const [list, setList] = useState(false);
  if (!uids.length) return <span className="sh-cite sh-cite--none">no evidence</span>;
  const lit = new Set(highlight ?? []);
  const shown = uids.slice(0, max);
  const rest = uids.length - shown.length;
  return (
    <>
      <span className="sh-cite-row">
        {shown.map((uid, index) => {
          const n = number?.(uid) ?? index + 1;
          return (
            <button
              key={uid}
              type="button"
              className="sh-cite"
              data-hl={lit.has(uid) ? "" : undefined}
              aria-label={`Evidence ${citeLabel(n)}`}
              onClick={(event) => {
                event.stopPropagation();
                setOpen(index);
              }}
              onMouseEnter={() => onPoint?.(uid)}
              onMouseLeave={() => onPoint?.(null)}
              onFocus={() => onPoint?.(uid)}
              onBlur={() => onPoint?.(null)}
            >
              {citeLabel(n)}
            </button>
          );
        })}
        {rest > 0 ? (
          <button
            type="button"
            className="sh-cite sh-cite--more"
            aria-label={`${rest} more cited events`}
            onClick={(event) => {
              event.stopPropagation();
              setList(true);
            }}
          >
            +{rest}
          </button>
        ) : null}
      </span>
      <Suspense fallback={null}>
        {open !== null && uids[open] ? (
          <EventDialog
            uid={uids[open]}
            onClose={() => setOpen(null)}
            step={{
              index: open,
              total: uids.length,
              onPrev: open > 0 ? () => setOpen(open - 1) : undefined,
              onNext: open < uids.length - 1 ? () => setOpen(open + 1) : undefined,
            }}
          />
        ) : null}
      </Suspense>
      {list ? <EvidenceList uids={uids} onClose={() => setList(false)} /> : null}
    </>
  );
}

/** Every cited event as rows; a row opens EventDialog stepping over the set. */
export function EvidenceList({ uids, onClose }: { uids: string[]; onClose: () => void }) {
  return (
    <Dialog title="Evidence" head={<span className="sh-mono">{uids.length}</span>} onClose={onClose} size="wide">
      <Evidence uids={uids} />
    </Dialog>
  );
}

function Evidence({ uids }: { uids: string[] }) {
  // events.query caps a fetch at 1000 rows.
  const events = useEvents(uids.slice(0, 1000), false);
  return (
    <Suspense fallback={null}>
      <EventTable
        rows={events.data?.rows ?? []}
        loading={events.isPending}
        error={events.error ?? undefined}
        onRetry={() => void events.refetch()}
        empty="No longer in the store"
        label="Evidence"
      />
    </Suspense>
  );
}
