/**
 * E-numbers for a case's cited events. E1 is the earliest cited event in time,
 * and the same number labels the strip chip, the timeline row, the time-bar
 * tick and a message's citations, so "E3" means one event everywhere on the
 * page. A cited event the store no longer holds keeps a number after the
 * dated ones, in the order the crew cited it.
 */
export type Cites = {
  /** Cited uids in E order. */
  order: string[];
  /** 1-based number of a cited uid, or undefined when the case never cited it. */
  of: (uid: string) => number | undefined;
};

export function citeIndex(
  events: readonly { event_uid: string; time: string }[],
  cited: Iterable<string>,
): Cites {
  const wanted = new Set(cited);
  const when = new Map<string, number>();
  for (const e of events) if (wanted.has(e.event_uid)) when.set(e.event_uid, Date.parse(e.time));
  const dated = [...when.keys()].sort((a, b) => when.get(a)! - when.get(b)! || a.localeCompare(b));
  const order = [...dated, ...[...wanted].filter((uid) => !when.has(uid))];
  const number = new Map(order.map((uid, i) => [uid, i + 1]));
  return { order, of: (uid) => number.get(uid) };
}

/** "E3". */
export const citeLabel = (n: number) => `E${n}`;
