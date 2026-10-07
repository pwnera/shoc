/**
 * The near misses `playbook.list {case_uid}` returns, typed for the Run a
 * playbook dialog: the kernel's "confidence is 0.08, it wants 0.80" becomes
 * numbers, so when every playbook misses on confidence one chip on top says
 * so, and a miss every playbook shares shows once. Closest first: fewest
 * misses, then the lowest confidence bar. Pure, so the tests feed it.
 */
export type NearMiss = { playbook_id: string; title: string; misses: string[] };

export type Miss = NearMiss & {
  /** The confidence the playbook wants, when that is one of its misses. */
  wants: number | null;
  /** Its other misses, without the ones every playbook shares. */
  own: string[];
};

const CONFIDENCE = /^confidence is ([\d.]+), it wants ([\d.]+)$/;

export function nearMisses(rows: readonly NearMiss[]): {
  misses: Miss[];
  shared: string[];
  /** The case's confidence, when a playbook misses on it. */
  has: number | null;
  /** The most common bar, when every playbook misses on confidence: the chip on top. */
  bar: number | null;
} {
  let has: number | null = null;
  const parsed = rows.map((row) => {
    let wants: number | null = null;
    const rest: string[] = [];
    for (const miss of row.misses) {
      const match = CONFIDENCE.exec(miss);
      if (match) [has, wants] = [Number(match[1]), Number(match[2])];
      else rest.push(miss);
    }
    return { ...row, wants, rest };
  });
  const shared = parsed.length > 1 ? parsed[0]!.rest.filter((miss) => parsed.every((p) => p.rest.includes(miss))) : [];
  const bars = new Map<number, number>();
  for (const p of parsed) if (p.wants !== null) bars.set(p.wants, (bars.get(p.wants) ?? 0) + 1);
  const every = parsed.length > 1 && parsed.every((p) => p.wants !== null);
  const bar = every ? ([...bars].sort((a, b) => b[1] - a[1] || b[0] - a[0])[0]?.[0] ?? null) : null;
  const misses = parsed
    .map(({ rest, ...p }) => ({ ...p, own: rest.filter((miss) => !shared.includes(miss)) }))
    .sort((a, b) => a.misses.length - b.misses.length || (a.wants ?? 1) - (b.wants ?? 1));
  return { misses, shared, has, bar };
}
