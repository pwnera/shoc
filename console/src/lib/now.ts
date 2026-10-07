/**
 * One shared clock for every age and countdown on screen. It ticks every 15
 * seconds while anything reads it, so a page of "4m ago" labels re-renders
 * together and no row runs a timer of its own.
 */
import { useSyncExternalStore } from "react";

const TICK = 15_000;

let current = Date.now();
let timer: ReturnType<typeof setInterval> | undefined;
const listeners = new Set<() => void>();

function listen(listener: () => void) {
  listeners.add(listener);
  if (!timer) {
    current = Date.now();
    timer = setInterval(() => {
      current = Date.now();
      for (const l of listeners) l();
    }, TICK);
  }
  return () => {
    listeners.delete(listener);
    if (!listeners.size && timer) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

/** The time of the last tick, in milliseconds. */
export function useNow(): number {
  return useSyncExternalStore(listen, () => current);
}
