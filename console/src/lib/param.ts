/**
 * Screen state in the URL, so a count elsewhere can link to a screen already
 * filtered and Back undoes a step.
 */
import { useSearchParams } from "react-router-dom";

/**
 * One query parameter as state. The fallback is left out of the URL; changes
 * replace the history entry instead of adding one per keystroke.
 */
export function useParam<T extends string = string>(
  name: string,
  fallback = "" as T,
): [T, (value: T) => void] {
  const [params, setParams] = useSearchParams();
  const value = (params.get(name) ?? fallback) as T;
  const set = (next: T) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        if (next === fallback) out.delete(name);
        else out.set(name, next);
        return out;
      },
      { replace: true },
    );
  return [value, set];
}

/** Edition two's tab ids that edition three renamed; read only where the new id is one of the screen's tabs. */
const RENAMED: Record<string, string> = { history: "activity", policy: "autonomy" };

/**
 * The screen's tab, in `?tab=`, with edition two's `?pane=` read as an alias
 * and its renamed ids (`history`, `policy`) as their successors. Each change
 * is a history step, so Back returns to the previous tab; an unknown id falls
 * back to the first tab.
 */
export function useTab<T extends string>(ids: readonly T[], fallback: T = ids[0]!): [T, (tab: T) => void] {
  const [params, setParams] = useSearchParams();
  const given = params.get("tab") ?? params.get("pane") ?? "";
  const renamed = RENAMED[given];
  const asked = (renamed && ids.includes(renamed as T) && !ids.includes(given as T) ? renamed : given) as T;
  const tab = ids.includes(asked) ? asked : fallback;
  const set = (next: T) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.delete("pane");
      out.delete("page");
      if (next === fallback) out.delete("tab");
      else out.set("tab", next);
      return out;
    });
  return [tab, set];
}
