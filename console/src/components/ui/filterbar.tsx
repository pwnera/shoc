/**
 * Chips and the filter bar: a scope switch when the screen has one, text,
 * [+ Filter], chips…, clear, then the screen's own controls at the far end, as
 * a card's 40px toolbar row. State lives in the URL through `lib/filters.ts` `useFilters`;
 * every URL value renders as a chip even when it is not among the options, so
 * a stale link never filters invisibly. "/" focuses the text, which is
 * debounced by 300ms. A dimension can draw its own menu content (the tactic
 * cells); one with neither options nor a menu is set by links only and shows
 * only as a chip. With nothing to add, no text and no chip, the bar is left out.
 */
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { ChevronLeft, Plus, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { useCommand } from "@/lib/commands";
import { chipWord, type Dim } from "@/lib/filters";
import { Button } from "./button";
import { MenuList, Popover, type MenuEntry } from "./pop";

/** 24px: a label in sans, a value in mono; removable, pressable, dashed (absent) or struck (ruled out). */
export function Chip({
  label,
  value,
  count,
  active,
  dashed,
  struck,
  onClick,
  onRemove,
  className,
  children,
}: {
  label?: ReactNode;
  value?: ReactNode;
  count?: number;
  active?: boolean;
  dashed?: boolean;
  struck?: boolean;
  onClick?: () => void;
  onRemove?: () => void;
  className?: string;
  children?: ReactNode;
}) {
  const classes = cn(
    "sh-chip",
    active && "sh-chip--active",
    dashed && "sh-chip--dashed",
    struck && "sh-chip--struck",
    className,
  );
  const body = (
    <>
      {label !== undefined ? <span className="sh-chip__label">{label}</span> : null}
      {value !== undefined ? <span className="sh-chip__value">{value}</span> : null}
      {children}
      {typeof count === "number" ? <span className="sh-chip__count">{count.toLocaleString()}</span> : null}
    </>
  );
  if (onClick && !onRemove)
    return (
      <button type="button" className={classes} onClick={onClick} aria-pressed={active}>
        {body}
      </button>
    );
  return (
    <span className={classes}>
      {body}
      {onRemove ? (
        <button
          type="button"
          className="sh-chip__remove"
          onClick={onRemove}
          aria-label={`Remove filter ${typeof label === "string" ? label : ""}`.trim()}
        >
          <X aria-hidden />
        </button>
      ) : null}
    </span>
  );
}

const addable = <T,>(d: Dim<T>) => Boolean(d.options?.length || d.menu);

function AddMenu<T>({
  dims,
  value,
  onChange,
  close,
}: {
  dims: Dim<T>[];
  value: Record<string, string>;
  onChange: (id: string, value: string) => void;
  close: () => void;
}) {
  const [picked, setPicked] = useState<string | null>(null);
  const dim = dims.find((d) => d.id === picked);
  if (dim?.menu)
    return (
      <div className="sh-filterbar__menu">
        <MenuList
          key={dim.id}
          items={[{ label: "Back", icon: ChevronLeft, keepOpen: true, onSelect: () => setPicked(null) }, { group: dim.label }]}
          close={close}
          label={dim.label}
        />
        {dim.menu({
          value: value[dim.id] ?? "",
          set: (next) => onChange(dim.id, next),
          close,
        })}
      </div>
    );
  // The values come first, so Enter on a dimension and Enter again picks one; Back closes the list.
  const items: MenuEntry[] = dim
    ? [
        { group: dim.label },
        ...(dim.options ?? []).map(
          (option): MenuEntry => ({
            label: option.label ?? option.value,
            count: option.count,
            check: "radio",
            checked: value[dim.id] === option.value,
            onSelect: () => onChange(dim.id, value[dim.id] === option.value ? "" : option.value),
          }),
        ),
        { sep: true },
        { label: "Back", icon: ChevronLeft, keepOpen: true, onSelect: () => setPicked(null) },
      ]
    : dims
        .filter(addable)
        .map((d) => ({ label: d.label, keepOpen: true, onSelect: () => setPicked(d.id) }));
  return <MenuList key={picked ?? ""} items={items} close={close} label={dim?.label ?? "Filter by"} />;
}

export function FilterBar<T>({
  dims,
  value,
  onChange,
  text,
  onText,
  onClear,
  placeholder = "Filter",
  lead,
  children,
  className,
}: {
  dims: Dim<T>[];
  /** One value per dimension id, as `useFilters().values` holds them. */
  value: Record<string, string>;
  onChange: (id: string, value: string) => void;
  /** The text filter; left out when the list has none. */
  text?: string;
  onText?: (text: string) => void;
  /** Clears every dimension and the text at once (`useFilters().clear`). */
  onClear?: () => void;
  placeholder?: string;
  /** What the list is a slice of (an Open/Closed segment), first in the row. */
  lead?: ReactNode;
  /** A window control or a count at the end of the row. */
  children?: ReactNode;
  className?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState(text ?? "");
  const [seen, setSeen] = useState(text ?? "");
  if ((text ?? "") !== seen) {
    setSeen(text ?? "");
    setDraft(text ?? "");
  }
  const send = useRef(onText);
  useLayoutEffect(() => {
    send.current = onText;
  });
  useEffect(() => {
    if (draft === (text ?? "")) return;
    const timer = setTimeout(() => send.current?.(draft), 300);
    return () => clearTimeout(timer);
  }, [draft, text]);
  useCommand("shell.filter", () => input.current?.focus(), Boolean(onText));

  const chips = dims.flatMap((dim) => {
    const v = value[dim.id];
    if (!v) return [];
    return [
      <Chip key={dim.id} label={dim.label} value={chipWord(dim, v)} active onRemove={() => onChange(dim.id, "")} />,
    ];
  });
  const filtering = chips.length > 0 || Boolean(text);
  const canAdd = dims.some(addable);
  if (!canAdd && !onText && !chips.length && !children && !lead) return null;

  return (
    <div className={cn("sh-card__toolbar sh-filterbar", className)}>
      {lead}
      {onText ? (
        <input
          ref={input}
          type="search"
          className="sh-input sh-input--sm sh-filterbar__text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape" && draft) {
              event.preventDefault();
              event.stopPropagation();
              setDraft("");
            }
          }}
          placeholder={placeholder}
          aria-label={placeholder}
          aria-keyshortcuts="/"
        />
      ) : null}
      {canAdd ? (
        <Popover
          menu
          trigger={(props) => (
            <Button {...props} variant="ghost" size="sm" className="sh-filterbar__add">
              <Plus aria-hidden />
              Filter
            </Button>
          )}
        >
          {(close) => <AddMenu dims={dims} value={value} onChange={onChange} close={close} />}
        </Popover>
      ) : null}
      {chips}
      {filtering && onClear ? (
        <button type="button" className="sh-filterbar__clear" onClick={onClear}>
          Clear
        </button>
      ) : null}
      {/* Takes the free space, so the screen's own controls sit at the far end. */}
      {children ? <span className="sh-filterbar__gap" aria-hidden /> : null}
      {children}
    </div>
  );
}
