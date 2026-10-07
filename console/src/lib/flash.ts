/**
 * The one flash a row gives when it arrives or changes, for every live list
 * (Cases, Findings, Response, the case Discussion): a row whose key is new,
 * or whose version changed, since the list first loaded stays in the set for
 * 1.2s, which `[data-new]` and `tr.is-new` draw. The first load flashes
 * nothing, so opening a screen never lights every row.
 */
import { useEffect, useRef, useState } from "react";

/** Keys that arrived or changed since the list first loaded. Pass `undefined` while the list is loading. */
export function useFlash(entries: [key: string, version: string][] | undefined): ReadonlySet<string> {
  const seen = useRef<Map<string, string> | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [fresh, setFresh] = useState<ReadonlySet<string>>(new Set());
  const signature = entries ? JSON.stringify(entries) : undefined;
  useEffect(() => {
    if (signature === undefined) return;
    const now = new Map(JSON.parse(signature) as [string, string][]);
    const before = seen.current;
    seen.current = now;
    if (!before) return;
    const changed = [...now].filter(([k, v]) => before.get(k) !== v).map(([k]) => k);
    if (!changed.length) return;
    setFresh(new Set(changed));
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setFresh(new Set()), 1200);
  }, [signature]);
  useEffect(() => () => clearTimeout(timer.current), []);
  return fresh;
}
