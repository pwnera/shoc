/**
 * The tab's title and icon, so a background tab says "(2)" without being
 * opened. Both read the same selectors as the rail: the inbox count and
 * whether an open case is critical.
 */
import { useEffect, useSyncExternalStore } from "react";
import { useCriticalOpen, useNeedsYou } from "./needs";

/** "(2) Cases · shoc"; the count is left out at zero. */
export function titleFor(screen: string, count: number): string {
  return `${count > 0 ? `(${count}) ` : ""}${screen ? `${screen} · ` : ""}shoc`;
}

/* The names routes asked for, the latest mount last; the shell writes the title. */
let named: { screen: string }[] = [];
const namedListeners = new Set<() => void>();
function setNamed(next: typeof named) {
  named = next;
  for (const l of namedListeners) l();
}

/**
 * A route names its screen, or a detail page its short id or title. The shell
 * owns `document.title`, so the route's name and the count never race.
 */
export function useDocumentTitle(screen: string): void {
  useEffect(() => {
    const entry = { screen };
    setNamed([...named, entry]);
    return () => setNamed(named.filter((e) => e !== entry));
  }, [screen]);
}

/** Mounted once by the shell: the route's name when it gave one, else `fallback` from the path. */
export function useShellTitle(fallback: string): void {
  const { count } = useNeedsYou();
  const current = useSyncExternalStore(
    (l) => (namedListeners.add(l), () => namedListeners.delete(l)),
    () => named,
  );
  const screen = current.at(-1)?.screen ?? fallback;
  useEffect(() => {
    document.title = titleFor(screen, count);
  }, [screen, count]);
}

export type Mark = "plain" | "crew" | "critical";

/** The mark with a corner square: crew when decisions wait, critical when a case is (red wins). */
export function markFor(count: number, critical: boolean): Mark {
  return critical ? "critical" : count > 0 ? "crew" : "plain";
}

/** The favicon's SVG with a corner square in `color`, as a data URI. */
export function badged(svg: string, color: string): string {
  const corner = `<rect x="140" y="132" width="104" height="104" rx="16" fill="${color}" stroke="#1F1A3D" stroke-width="14"/>`;
  return `data:image/svg+xml,${encodeURIComponent(svg.replace("</svg>", `${corner}</svg>`))}`;
}

let source: Promise<string> | undefined;

/** Mounted once by the shell: swaps the tab icon as the inbox and critical cases change. */
export function useFavicon(): void {
  const { count } = useNeedsYou();
  const critical = useCriticalOpen();
  const mark = markFor(count, critical);
  useEffect(() => {
    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
    if (!link) return;
    if (mark === "plain") {
      link.href = "/favicon.svg";
      return;
    }
    let live = true;
    source ??= fetch("/favicon.svg").then((r) => (r.ok ? r.text() : Promise.reject(new Error("no icon"))));
    source
      .then((svg) => {
        if (!live) return;
        const token = mark === "critical" ? "--critical-dot" : "--crew-dot";
        const color = getComputedStyle(document.documentElement).getPropertyValue(token).trim();
        link.href = badged(svg, color || (mark === "critical" ? "#e5484d" : "#6e8bff"));
      })
      .catch(() => {
        source = undefined;
      });
    return () => {
      live = false;
    };
  }, [mark]);
}
