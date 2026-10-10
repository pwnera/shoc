/**
 * The rail: fourteen screens in three groups (`lib/nav.ts`). One number, the
 * inbox count on Overview in crew ink; two dots without numbers, Cases while an
 * open case is critical and Health while the store or the crew is down. Each
 * mirrors a fact its screen owns, from the same selectors. Collapsed (⌘\) it
 * is a 56px column of icons, each with its label and G chord in a tip.
 *
 * Capabilities used (through `lib/needs.ts`): action.list, case.list,
 * source.list, ops.alerts, health.status.
 */
import { Fragment } from "react";
import { NavLink } from "react-router-dom";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { cn } from "@/lib/cn";
import { keyLabel } from "@/lib/commands";
import { NAV, type Screen } from "@/lib/nav";
import { useCriticalOpen, useCrewDown, useNeedsYou } from "@/lib/needs";
import { useHealth, useWarmRuleHealth } from "@/lib/reads";
import { Tip } from "./ui/tip";

const WARMS = new Set(["/detection", "/response"]);

export function Rail({
  collapsed = false,
  onCollapse,
  onPick,
}: {
  collapsed?: boolean;
  /** Absent in the mobile drawer. */
  onCollapse?: () => void;
  /** A screen was picked (the drawer closes). */
  onPick?: () => void;
}) {
  const { count } = useNeedsYou();
  const critical = useCriticalOpen();
  const crew = useCrewDown();
  const health = useHealth();
  const warm = useWarmRuleHealth();
  const healthDown = health.data?.store.ok === false || crew.down;

  const item = (screen: Screen) => {
    const dot =
      screen.to === "/cases" && critical
        ? "Critical case open"
        : screen.to === "/health" && healthDown
          ? health.data?.store.ok === false
            ? "Event store down"
            : "Crew down"
          : "";
    const to = screen.to === "/cases" && critical ? "/cases?severity=critical" : screen.to;
    const link = (
      <NavLink
        to={to}
        end={screen.to === "/"}
        className="sh-nav__item"
        onClick={onPick}
        // The screens that show rule health warm it on intent: it reads the event store.
        {...(WARMS.has(screen.to) ? { onPointerEnter: warm, onFocus: warm } : {})}
      >
        <screen.icon aria-hidden />
        <span className="sh-nav__label">{screen.label}</span>
        {screen.to === "/" && count > 0 ? (
          <span className="sh-nav__count">
            <span aria-hidden>{count}</span>
            <span className="sr-only">{count} need you</span>
          </span>
        ) : null}
        {dot ? (
          <span className="sh-nav__dot" data-tone={screen.to === "/health" ? "bad" : "critical"} role="img" aria-label={dot} />
        ) : null}
      </NavLink>
    );
    return collapsed ? (
      <Tip key={screen.to} side="right" label={dot ? `${screen.label} · ${dot.toLowerCase()}` : screen.label} kbd={keyLabel(`g ${screen.chord}`)}>
        {link}
      </Tip>
    ) : (
      <Fragment key={screen.to}>{link}</Fragment>
    );
  };

  return (
    <>
      <nav aria-label="Screens" className={cn("sh-nav", collapsed && "sh-nav--collapsed")}>
        {NAV.map((group) => (
          <Fragment key={group.label}>
            <div className="sh-nav__group">{group.label}</div>
            {group.items.map(item)}
          </Fragment>
        ))}
      </nav>
      {onCollapse ? (
        <div className={cn("sh-nav", collapsed && "sh-nav--collapsed")}>
          <Tip side={collapsed ? "right" : undefined} label={collapsed ? "Expand" : "Collapse"} kbd={keyLabel("mod+\\")}>
            <button
              type="button"
              className="sh-nav__item"
              onClick={onCollapse}
              aria-label={collapsed ? "Expand the rail" : "Collapse the rail"}
              aria-keyshortcuts="Meta+\ Control+\"
            >
              {collapsed ? <PanelLeftOpen aria-hidden /> : <PanelLeftClose aria-hidden />}
            </button>
          </Tip>
        </div>
      ) : null}
    </>
  );
}
