/**
 * Light, dark, or whatever the operating system says. Light is the design
 * system's default. The choice is this browser's alone; index.html applies it
 * before the first paint, so the page never flashes the other mode.
 */
import { useEffect, useState } from "react";

export type Mode = "light" | "dark" | "system";
export const MODES: Mode[] = ["light", "dark", "system"];
const KEY = "shoc.theme";
const dark = () => window.matchMedia?.("(prefers-color-scheme: dark)");

function stored(): Mode {
  try {
    const value = localStorage.getItem(KEY);
    return value === "dark" || value === "system" ? value : "light";
  } catch {
    return "light";
  }
}

function apply(mode: Mode) {
  const resolved = mode === "system" ? (dark()?.matches ? "dark" : "light") : mode;
  document.documentElement.dataset.theme = resolved;
}

let current = stored();
// Follows the operating system while "system" is the choice, whether or not the menu is open.
dark()?.addEventListener?.("change", () => current === "system" && apply("system"));

export function useTheme(): [Mode, (mode: Mode) => void] {
  const [mode, setMode] = useState(current);

  useEffect(() => {
    current = mode;
    apply(mode);
    try {
      localStorage.setItem(KEY, mode);
    } catch {
      /* private window: the choice lasts until the tab closes */
    }
  }, [mode]);

  return [mode, setMode];
}
