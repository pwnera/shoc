/**
 * Popover, menu and confirm. A popover is the native [popover] element in the
 * top layer: light dismiss and Escape come from the browser, and its trigger
 * names it with popovertarget, so clicking the trigger again closes it. It is
 * placed under its trigger when it opens (flipped above when it would leave
 * the screen), follows it on scroll, and places itself again when its content
 * changes size (a menu that swaps to its wider confirm). A menu takes arrow keys and type-ahead;
 * a danger item swaps the menu for a confirm that restates what will happen.
 * Every write that changes the outside world, is L2, or cannot be undone
 * confirms here; there is no hold gesture.
 */
import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { Check, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { Button } from "./button";
import { ErrorNote, Spinner } from "./misc";

export type PopTrigger = {
  popoverTarget: string;
  "aria-haspopup": "menu" | "dialog";
  "aria-expanded": boolean;
  "aria-controls": string;
};

const GAP = 4;
const EDGE = 8;

function place(pop: HTMLElement, id: string, align: "start" | "end") {
  const anchor = document.querySelector<HTMLElement>(`[popovertarget="${CSS.escape(id)}"]`);
  const box = pop.getBoundingClientRect();
  if (!anchor) {
    pop.style.top = `${Math.max(EDGE, (window.innerHeight - box.height) / 2)}px`;
    pop.style.left = `${Math.max(EDGE, (window.innerWidth - box.width) / 2)}px`;
    return;
  }
  const at = anchor.getBoundingClientRect();
  const below = at.bottom + GAP;
  const top =
    below + box.height > window.innerHeight - EDGE && at.top - box.height - GAP > EDGE
      ? at.top - box.height - GAP
      : below;
  const want = align === "end" ? at.right - box.width : at.left;
  pop.style.top = `${Math.max(EDGE, top)}px`;
  pop.style.left = `${Math.max(EDGE, Math.min(want, window.innerWidth - box.width - EDGE))}px`;
}

/**
 * A floating panel under its trigger. `trigger` receives the props that tie
 * a button to the popover; spread them on it. Children render only while the
 * popover is open, so its state starts fresh each time. Pass `open` and
 * `onOpenChange` to open it from a key.
 */
export function Popover({
  trigger,
  children,
  label,
  menu,
  align = "start",
  pad,
  open,
  onOpenChange,
  className,
}: {
  trigger: (props: PopTrigger) => ReactNode;
  children: ReactNode | ((close: () => void) => ReactNode);
  label?: string;
  /** Holds a role="menu" list. */
  menu?: boolean;
  align?: "start" | "end";
  /** 12px padding for content that is not a list. */
  pad?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
}) {
  const id = useId();
  const pop = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);
  const change = useRef(onOpenChange);
  useLayoutEffect(() => {
    change.current = onOpenChange;
  });

  useEffect(() => {
    const el = pop.current;
    if (!el) return;
    const toggled = (event: Event) => {
      const now = (event as ToggleEvent).newState === "open";
      setShown(now);
      change.current?.(now);
    };
    el.addEventListener("toggle", toggled);
    return () => el.removeEventListener("toggle", toggled);
  }, []);

  useEffect(() => {
    const el = pop.current;
    if (!el || open === undefined) return;
    try {
      if (open && !el.matches(":popover-open")) el.showPopover();
      if (!open && el.matches(":popover-open")) el.hidePopover();
    } catch {
      /* no popover support (tests): children stay hidden */
    }
  }, [open]);

  // A popover heard as a dialog takes focus when it opens, as a dialog does: its autofocus control, its first one, or
  // itself. Native popover focus return brings it back to the trigger. Menus move focus themselves.
  useEffect(() => {
    const el = pop.current;
    if (!shown || menu || !el) return;
    const first =
      el.querySelector<HTMLElement>("[data-autofocus]") ??
      el.querySelector<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex="0"]');
    (first ?? el).focus({ preventScroll: true });
  }, [shown, menu]);

  // Placed after the children render, so their size counts; followed on scroll, resize and a change of content.
  useLayoutEffect(() => {
    const el = pop.current;
    if (!shown || !el) return;
    const follow = () => place(el, id, align);
    follow();
    window.addEventListener("scroll", follow, true);
    window.addEventListener("resize", follow);
    const grown = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(follow);
    grown?.observe(el);
    return () => {
      window.removeEventListener("scroll", follow, true);
      window.removeEventListener("resize", follow);
      grown?.disconnect();
    };
  }, [shown, id, align]);

  const close = () => {
    try {
      pop.current?.hidePopover();
    } catch {
      setShown(false);
    }
  };

  return (
    <>
      {trigger({
        popoverTarget: id,
        "aria-haspopup": menu ? "menu" : "dialog",
        "aria-expanded": shown,
        "aria-controls": id,
      })}
      <div
        ref={pop}
        id={id}
        popover="auto"
        role={menu ? undefined : "dialog"}
        aria-label={label}
        tabIndex={menu ? undefined : -1}
        className={cn("sh-pop", pad && "sh-pop--pad", className)}
      >
        {shown ? (typeof children === "function" ? children(close) : children) : null}
      </div>
    </>
  );
}

export type MenuEntry =
  | {
      label: string;
      onSelect: (note: string) => void | Promise<unknown>;
      icon?: LucideIcon;
      /** As `keyLabel()` spells it. */
      kbd?: string;
      count?: number;
      danger?: boolean;
      disabled?: boolean;
      /** A radio or checkbox item; `checked` draws the tick. */
      check?: "radio" | "checkbox";
      checked?: boolean;
      /** Swap the menu for a confirm before `onSelect` runs. */
      confirm?: Omit<ConfirmProps, "onConfirm" | "onCancel">;
      /** Leave the menu open after the pick (a submenu step). */
      keepOpen?: boolean;
    }
  | { sep: true }
  | { group: string };

/** The items of a menu, for a popover that builds its own steps (the filter bar). */
export function MenuList({ items, close, label }: { items: MenuEntry[]; close: () => void; label?: string }) {
  const list = useRef<HTMLDivElement>(null);
  const [confirming, setConfirming] = useState<Extract<MenuEntry, { label: string }> | null>(null);
  const typed = useRef({ text: "", at: 0 });

  // Focus the first item on open and on the way back from a confirm; a parent that swaps the
  // items for a second step remounts the list with a new key.
  useEffect(() => {
    if (!confirming) list.current?.querySelector<HTMLElement>("[role^=menuitem]:not([aria-disabled=true])")?.focus();
  }, [confirming]);

  if (confirming?.confirm)
    return (
      <Confirm
        {...confirming.confirm}
        onCancel={() => setConfirming(null)}
        onConfirm={async (note) => {
          await confirming.onSelect(note);
          close();
        }}
      />
    );

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const all = [...(list.current?.querySelectorAll<HTMLElement>("[role^=menuitem]:not([aria-disabled=true])") ?? [])];
    const at = all.indexOf(document.activeElement as HTMLElement);
    const go = (i: number) => all[(i + all.length) % all.length]?.focus();
    if (event.key === "ArrowDown") go(at + 1);
    else if (event.key === "ArrowUp") go(at - 1);
    else if (event.key === "Home") go(0);
    else if (event.key === "End") go(all.length - 1);
    else if (event.key.length === 1 && /\S/.test(event.key) && !event.metaKey && !event.ctrlKey) {
      const now = Date.now();
      typed.current = { text: (now - typed.current.at < 600 ? typed.current.text : "") + event.key.toLowerCase(), at: now };
      const hit = all.findIndex((el) => el.textContent?.trim().toLowerCase().startsWith(typed.current.text));
      if (hit < 0) return;
      go(hit);
    } else return;
    event.preventDefault();
    event.stopPropagation();
  };

  return (
    <div ref={list} role="menu" aria-label={label} className="sh-menu" onKeyDown={onKeyDown}>
      {items.map((item, index) => {
        if ("sep" in item) return <hr key={index} className="sh-menu__sep" />;
        if ("group" in item)
          return (
            <div key={index} className="sh-menu__label" role="presentation">
              {item.group}
            </div>
          );
        const Icon = item.icon;
        return (
          <button
            key={index}
            type="button"
            role={item.check === "radio" ? "menuitemradio" : item.check === "checkbox" ? "menuitemcheckbox" : "menuitem"}
            aria-checked={item.check ? Boolean(item.checked) : undefined}
            aria-disabled={item.disabled || undefined}
            tabIndex={-1}
            className={cn("sh-menu__item", item.danger && "sh-menu__item--danger")}
            onClick={() => {
              if (item.disabled) return;
              if (item.confirm) return setConfirming(item);
              void item.onSelect("");
              if (!item.keepOpen) close();
            }}
          >
            {item.check ? (
              <span className="sh-menu__check">{item.checked ? <Check aria-hidden /> : null}</span>
            ) : Icon ? (
              <Icon aria-hidden />
            ) : null}
            <span className="sh-menu__text">{item.label}</span>
            {typeof item.count === "number" ? <span className="sh-menu__count">{item.count.toLocaleString()}</span> : null}
            {item.kbd ? <kbd className="sh-menu__kbd">{item.kbd}</kbd> : null}
          </button>
        );
      })}
    </div>
  );
}

/** A trigger and a menu of items: the "⋯" of a header or a row, every filter menu. */
export function Menu({
  trigger,
  items,
  label,
  align = "end",
  open,
  onOpenChange,
}: {
  trigger: (props: PopTrigger) => ReactNode;
  items: MenuEntry[];
  label: string;
  align?: "start" | "end";
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  return (
    <Popover trigger={trigger} menu align={align} open={open} onOpenChange={onOpenChange}>
      {(close) => <MenuList items={items} close={close} label={label} />}
    </Popover>
  );
}

export type ConfirmProps = {
  /** One mono line: act and target ("Disable AWS key · AKIA…MPLE"). */
  what: ReactNode;
  /** Chips that restate the consequences (`ActionFacts`). */
  facts?: ReactNode;
  /** The button's word ("Approve", "Remove"). */
  go: string;
  danger?: boolean;
  /** An optional note (reject, close, undo, revert); `required` keeps the button off until it is filled. */
  note?: { placeholder?: string; label?: string; required?: boolean };
  /** Irreversible acts: the input must equal this name before the button turns on. */
  typed?: string;
  busy?: boolean;
  error?: unknown;
  /** Inside a dialog footer or an approval card rather than a popover. */
  inline?: boolean;
  /** A returned promise keeps the confirm busy until it settles, and shows its error inline. */
  onConfirm: (note: string) => void | Promise<unknown>;
  onCancel: () => void;
};

/** The second step: what will happen, the facts that decide it, Enter to go, Escape to step back. */
export function Confirm({
  what,
  facts,
  go,
  danger,
  note,
  typed,
  busy,
  error,
  inline,
  onConfirm,
  onCancel,
}: ConfirmProps) {
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState<unknown>(null);
  const goRef = useRef<HTMLButtonElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const asked = Boolean(note || typed);
  useEffect(() => {
    (asked ? field.current : goRef.current)?.focus();
  }, [asked]);

  const working = busy || pending;
  const blocked = (typed !== undefined && text !== typed) || (note?.required && !text.trim());
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (working || blocked) return;
    setFailed(null);
    const result = onConfirm(text.trim());
    if (result instanceof Promise) {
      setPending(true);
      result.then(
        () => setPending(false),
        (reason: unknown) => {
          setPending(false);
          setFailed(reason ?? new Error("failed"));
        },
      );
    }
  };
  const shown = error ?? failed;

  return (
    <form
      className={cn("sh-confirm", inline && "sh-confirm--inline")}
      data-busy={working || undefined}
      onSubmit={submit}
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        event.preventDefault();
        event.stopPropagation();
        if (!working) onCancel();
      }}
    >
      <div className="sh-confirm__what">{what}</div>
      {facts ? <div className="sh-confirm__facts">{facts}</div> : null}
      {asked ? (
        <input
          ref={field}
          data-autofocus
          className="sh-input sh-input--sm sh-confirm__input"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder={typed ? typed : (note?.placeholder ?? "Note (optional)")}
          aria-label={typed ? `Type ${typed} to confirm` : (note?.label ?? "Note")}
          spellCheck={false}
        />
      ) : null}
      <div className="sh-confirm__row">
        <Button variant="ghost" size="sm" className="sh-confirm__cancel" onClick={onCancel} disabled={working}>
          Cancel
        </Button>
        <Button
          ref={goRef}
          data-autofocus={asked ? undefined : ""}
          type="submit"
          size="sm"
          variant={danger ? "danger" : "primary"}
          className="sh-confirm__go"
          disabled={Boolean(blocked) || working}
        >
          {working ? <Spinner /> : null}
          {go}
        </Button>
      </div>
      {shown ? <ErrorNote error={shown} inline /> : null}
    </form>
  );
}
