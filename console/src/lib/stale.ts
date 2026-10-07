/**
 * A redeploy removes the hashed chunks an open tab was built against, so its
 * next lazy screen or dialog fails to load. That is a stale build, not a bug:
 * the tab reloads once per URL onto the new one (`main.tsx` for Vite's
 * preload, `ErrorBoundary` for a failed import).
 */
import { lazy, type ComponentType } from "react";

const RELOADED = "shoc.reloaded";
/** Chrome, Safari and Firefox's words for a lazy chunk the server no longer has. */
export const STALE = /dynamically imported module|Importing a module script failed/i;

/** Reload once per URL onto the deployed build; false when this URL already did, so a real gap shows its error. */
export function reloadForNewBuild(): boolean {
  try {
    if (sessionStorage.getItem(RELOADED) === location.href) return false;
    sessionStorage.setItem(RELOADED, location.href);
  } catch {
    return false;
  }
  location.reload();
  return true;
}

/** Called once the app has run a while: a later redeploy may reload this URL again. */
export function forgetReload() {
  try {
    sessionStorage.removeItem(RELOADED);
  } catch {
    /* nothing kept */
  }
}

/**
 * A lazy named export. When Vite's preload handler has started the reload for
 * a stale chunk it resolves the import with nothing: the screen then stays on
 * its skeleton until the reload lands, rather than flashing a TypeError.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- React.lazy's own constraint
export function lazyNamed<M extends Record<K, ComponentType<any>>, K extends string>(load: () => Promise<M>, name: K) {
  return lazy(() => load().then((m) => (m ? { default: m[name] } : new Promise<never>(() => {}))));
}
