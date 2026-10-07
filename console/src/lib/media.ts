/**
 * Whether a media query matches, kept current, for content that changes with
 * the width where CSS cannot do it (a column's width, a row's words). A
 * column that only drops under 1024px takes `hide: "md"` instead. `fallback`
 * answers where there is no `matchMedia`.
 */
import { useSyncExternalStore } from "react";

export function useMedia(query: string, fallback = false): boolean {
  return useSyncExternalStore(
    (changed) => {
      const media = window.matchMedia?.(query);
      media?.addEventListener?.("change", changed);
      return () => media?.removeEventListener?.("change", changed);
    },
    () => window.matchMedia?.(query).matches ?? fallback,
    () => fallback,
  );
}

/** Under 1024px, where the rail leaves and tables drop their `hide: "md"` columns. */
export const useNarrow = () => useMedia("(max-width: 1023px)");

/** Under 768px: a phone. */
export const usePhone = () => useMedia("(max-width: 767px)");
