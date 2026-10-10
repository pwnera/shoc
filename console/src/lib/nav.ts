/** The rail, where every screen sits in it, and the routes the app serves. */
import {
  Activity,
  Box,
  Brain,
  Compass,
  Crosshair,
  Gauge,
  Globe,
  KeyRound,
  Plug,
  Radar,
  Ruler,
  ShieldAlert,
  Telescope,
  Zap,
} from "lucide-react";

export type Screen = {
  to: string;
  label: string;
  icon: typeof Gauge;
  /** The second key of its G chord ("g c"). */
  chord: string;
  /** Tab labels; the URL id is the first word in lower case (`?tab=closed`). */
  tabs?: string[];
};

/* Three groups, one home per fact. Operate is what is happening; Program is
   what shoc knows and does about it; Platform is shoc itself: what it connects
   to, whether it works, and who may use it. A screen answers one question and
   sends you elsewhere for the rest, so nothing is shown twice. */
export const NAV: { label: string; items: Screen[] }[] = [
  {
    label: "Operate",
    items: [
      { to: "/", label: "Overview", icon: Gauge, chord: "o" },
      {
        to: "/cases",
        label: "Cases",
        icon: Box,
        chord: "c",
        tabs: ["All", "Investigating", "Contained", "Closed"],
      },
      { to: "/findings", label: "Findings", icon: Radar, chord: "f", tabs: ["Open", "Handled", "Set aside"] },
      { to: "/explore", label: "Explore", icon: Compass, chord: "e" },
    ],
  },
  {
    label: "Program",
    items: [
      {
        to: "/detection",
        label: "Detection",
        icon: Crosshair,
        chord: "d",
        tabs: ["Rules", "Coverage", "Changes", "Muted"],
      },
      {
        to: "/response",
        label: "Response",
        icon: Zap,
        chord: "r",
        tabs: ["Activity", "Pages", "Playbooks", "Autonomy"],
      },
      { to: "/hunts", label: "Hunts", icon: Telescope, chord: "h", tabs: ["Runs", "Packs", "Backlog"] },
      { to: "/intel", label: "Intel", icon: Globe, chord: "i", tabs: ["Indicators", "Leads", "Reports"] },
      { to: "/posture", label: "Posture", icon: ShieldAlert, chord: "p", tabs: ["Seen", "Listed only"] },
      { to: "/memory", label: "Memory", icon: Brain, chord: "m", tabs: ["Facts", "Notes", "Corrections"] },
    ],
  },
  {
    label: "Platform",
    items: [
      {
        to: "/connections",
        label: "Connections",
        icon: Plug,
        chord: "s",
        tabs: ["Products", "Intel", "Services", "Quality", "shoc's own"],
      },
      { to: "/health", label: "Health", icon: Activity, chord: "l", tabs: ["Problems", "Crew", "Jobs", "Spend"] },
      { to: "/measurement", label: "Measurement", icon: Ruler, chord: "n" },
      { to: "/access", label: "Access", icon: KeyRound, chord: "a", tabs: ["People", "Tokens", "Capabilities", "Audit"] },
    ],
  },
];

export const SCREENS: Screen[] = NAV.flatMap((group) => group.items);

/** Every path the app routes, as `App.tsx` declares them. */
export const ROUTES = [
  "/",
  "/cases",
  "/cases/:caseUid",
  "/findings",
  "/findings/:findingUid",
  "/explore",
  "/detection",
  "/detection/rules/:ruleId",
  "/response",
  "/response/playbooks/:playbookId",
  "/hunts",
  "/intel",
  "/posture",
  "/memory",
  "/connections",
  "/health",
  "/health/:tab",
  "/health/jobs",
  "/measurement",
  "/access",
] as const;

/** The URL id of a tab label: its first word in lower case, except the ones the spec names. */
export function tabId(label: string): string {
  if (label === "Set aside") return "aside";
  if (label === "Listed only") return "listed";
  // Renamed from "Suppressions"; the id stays, so links already shared keep working.
  if (label === "Muted") return "suppressions";
  // Renamed from "Footprint"; `?tab=footprint` links keep working.
  if (label === "shoc's own") return "footprint";
  return (label.split(" ")[0] ?? label).toLowerCase();
}

/** Where a tab lives: Health's tabs are paths, every other screen's a `?tab=`. */
export function tabHref(screen: Screen, label: string): string {
  const id = tabId(label);
  if (screen.tabs?.[0] === label) return screen.to;
  return screen.to === "/health" ? `/health/${id}` : `${screen.to}?tab=${id}`;
}

/** The group and screen a path belongs to, for the breadcrumb. */
export function place(path: string): { group: string; screen: string; to: string } | null {
  const top = `/${path.split("/")[1] ?? ""}`;
  for (const group of NAV)
    for (const item of group.items)
      if (item.to === top) return { group: group.label, screen: item.label, to: item.to };
  return null;
}
