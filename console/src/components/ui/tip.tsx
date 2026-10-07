/**
 * A tooltip: shown after 400ms of hover or at once on keyboard focus, hidden
 * on Escape, linked to its trigger with aria-describedby. It repeats or
 * explains; it never holds the only copy of a fact. The native
 * popover="manual" puts it in the top layer, so no scroll box clips it.
 */
import {
  cloneElement,
  useEffect,
  useId,
  useRef,
  type FocusEvent,
  type MouseEvent,
  type ReactElement,
  type ReactNode,
} from "react";
import { cn } from "@/lib/cn";

type TriggerProps = {
  onMouseEnter?: (event: MouseEvent<HTMLElement>) => void;
  onMouseLeave?: (event: MouseEvent<HTMLElement>) => void;
  onFocus?: (event: FocusEvent<HTMLElement>) => void;
  onBlur?: (event: FocusEvent<HTMLElement>) => void;
  "aria-describedby"?: string;
};

/* One tip shows at a time, so one Escape listener serves them all. It listens first (window, capture) and takes
   the key: Escape over a shown tip only hides it (WCAG 1.4.13); the next one closes the dialog or leaves the page. */
let hideShown: (() => void) | null = null;
let listening = false;

function tipOpen(): boolean {
  try {
    return document.querySelector(".sh-tip:popover-open") !== null;
  } catch {
    return false;
  }
}

function listenForEscape() {
  if (listening || typeof window === "undefined") return;
  listening = true;
  window.addEventListener(
    "keydown",
    (event) => {
      if (event.key !== "Escape" || !hideShown) return;
      const shown = tipOpen();
      hideShown();
      if (!shown) return;
      event.preventDefault();
      event.stopPropagation();
    },
    true,
  );
}

const GAP = 6;
const EDGE = 8;

function keyboardFocus(el: HTMLElement): boolean {
  try {
    return el.matches(":focus-visible");
  } catch {
    return true;
  }
}

export function Tip({
  label,
  kbd,
  mono,
  side,
  children,
}: {
  label?: ReactNode;
  /** A key hint, as `keyLabel()` spells it. */
  kbd?: string;
  mono?: boolean;
  /** Beside the trigger rather than under it, so a stack of icons (the collapsed rail) stays visible. */
  side?: "right";
  children: ReactElement<TriggerProps>;
}) {
  const id = useId();
  // A span, so a tip may sit inside a paragraph (an entity chip in crew prose).
  const tip = useRef<HTMLSpanElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  if (label === undefined || label === null || label === "") return children;

  const hide = () => {
    clearTimeout(timer.current);
    try {
      tip.current?.hidePopover();
    } catch {
      /* already hidden, or no popover support */
    }
    if (hideShown === hide) hideShown = null;
  };

  const show = (anchor: HTMLElement, delay: number) => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const el = tip.current;
      if (!el || !anchor.isConnected) return;
      hideShown?.();
      try {
        el.showPopover();
      } catch {
        return;
      }
      hideShown = hide;
      listenForEscape();
      const at = anchor.getBoundingClientRect();
      const box = el.getBoundingClientRect();
      const right = side === "right" && at.right + GAP + box.width <= window.innerWidth - EDGE;
      const below = at.bottom + GAP;
      const top = right
        ? Math.min(at.top + at.height / 2 - box.height / 2, window.innerHeight - box.height - EDGE)
        : below + box.height > window.innerHeight - EDGE
          ? at.top - box.height - GAP
          : below;
      const left = right
        ? at.right + GAP
        : Math.max(EDGE, Math.min(at.left + at.width / 2 - box.width / 2, window.innerWidth - box.width - EDGE));
      el.style.top = `${Math.max(EDGE, top)}px`;
      el.style.left = `${left}px`;
    }, delay);
  };

  const own = children.props;
  const described = [own["aria-describedby"], id].filter(Boolean).join(" ");
  return (
    <>
      {cloneElement(children, {
        "aria-describedby": described,
        onMouseEnter: (event: MouseEvent<HTMLElement>) => {
          own.onMouseEnter?.(event);
          show(event.currentTarget, 400);
        },
        onMouseLeave: (event: MouseEvent<HTMLElement>) => {
          own.onMouseLeave?.(event);
          hide();
        },
        onFocus: (event: FocusEvent<HTMLElement>) => {
          own.onFocus?.(event);
          if (keyboardFocus(event.currentTarget)) show(event.currentTarget, 0);
        },
        onBlur: (event: FocusEvent<HTMLElement>) => {
          own.onBlur?.(event);
          hide();
        },
      })}
      <span ref={tip} id={id} role="tooltip" popover="manual" className={cn("sh-tip", mono && "sh-tip--mono")}>
        <span>{label}</span>
        {kbd ? <kbd className="sh-tip__kbd">{kbd}</kbd> : null}
      </span>
    </>
  );
}
