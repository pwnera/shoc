/**
 * Text as a record and text to take away. Quote shows words that are
 * themselves the record (a reason a person typed, an agent's message, a page
 * message): a person's as typed, the crew's set as `Prose`, never HTML, and
 * marked when it came from a log or a feed. Field puts a label above its input, or names a group of
 * controls (a Seg) with `group`. Copy selects a value on click and copies it
 * through `lib/copy.ts`, which falls back to the selection and execCommand
 * over plain HTTP.
 */
import {
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { Check, Copy as CopyIcon } from "lucide-react";
import { announce } from "@/lib/announce";
import { cn } from "@/lib/cn";
import { copyText, type CopyOutcome } from "@/lib/copy";
import { who, type Who } from "@/lib/crew";
import { clock } from "@/lib/format";
import { Avatar } from "./avatar";
import { Prose } from "./prose";

export function Quote({
  by,
  at,
  untrusted,
  crew,
  label,
  children,
}: {
  /** The author string, as `who()` reads it, or the identity itself. */
  by?: string | Who | null;
  at?: string | null;
  /** Where the words came from when shoc did not write them. */
  untrusted?: "log" | "feed";
  /** Draw the rule in the crew line; on by default when `by` is a crew role. */
  crew?: boolean;
  /** What the words are ("message", "reason"), before the author. */
  label?: string;
  children: string;
}) {
  const author = by ? (typeof by === "string" ? who(by) : by) : null;
  const agent = crew ?? (author?.kind === "crew" || author?.kind === "code");
  return (
    <figure className={cn("sh-quote", agent && "sh-quote--crew", untrusted && "sh-quote--untrusted")}>
      <blockquote className="sh-quote__text">{agent && !untrusted ? <Prose text={children} /> : children}</blockquote>
      {author || at || label || untrusted ? (
        <figcaption className="sh-quote__by">
          {label ? <span>{label}</span> : null}
          {author ? <Avatar who={author} size={16} tip={false} /> : null}
          {author ? <b>{author.name}</b> : null}
          {at ? <span>{clock(at)}</span> : null}
          {untrusted ? <span className="sh-badge sh-tone-faint">from a {untrusted}</span> : null}
        </figcaption>
      ) : null}
    </figure>
  );
}

type Labelled = { id?: string; "aria-describedby"?: string; "aria-invalid"?: boolean };

/**
 * A label above its input, an optional hint under it, and the error in place
 * of the hint. The label is tied to the one input by id; with `group` it names
 * a set of controls instead (a Seg, a row of switches), as `role="group"`.
 */
export function Field({
  label,
  hint,
  error,
  aside,
  group,
  className,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: ReactNode;
  /** Right of the label: a count, a "required". */
  aside?: ReactNode;
  /** The children are several controls, or one that is itself a group: no id is cloned onto them. */
  group?: boolean;
  className?: string;
  children: ReactElement<Labelled> | ReactNode;
}) {
  const auto = useId();
  const own: Labelled = !group && isValidElement<Labelled>(children) ? children.props : {};
  const id = own.id ?? auto;
  const note = `${id}-note`;
  const described = hint || error ? note : undefined;
  return (
    <div
      className={cn("sh-field", error ? "sh-field--error" : null, className)}
      role={group ? "group" : undefined}
      aria-labelledby={group ? `${id}-label` : undefined}
      aria-describedby={group ? described : undefined}
    >
      <div className="sh-field__row">
        {group ? (
          <span id={`${id}-label`} className="sh-field__label">
            {label}
          </span>
        ) : (
          <label htmlFor={id} className="sh-field__label">
            {label}
          </label>
        )}
        {aside}
      </div>
      {!group && isValidElement<Labelled>(children)
        ? cloneElement(children, {
            id,
            "aria-describedby": described ?? own["aria-describedby"],
            "aria-invalid": error ? true : own["aria-invalid"],
          })
        : children}
      {error ? (
        <span id={note} className="sh-field__error" role="alert">
          {error}
        </span>
      ) : hint ? (
        <span id={note} className="sh-field__hint">
          {hint}
        </span>
      ) : null}
    </div>
  );
}

function useOutcome(): [CopyOutcome, (outcome: CopyOutcome) => void] {
  const [outcome, setOutcome] = useState<CopyOutcome>("");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return [
    outcome,
    (next) => {
      setOutcome(next);
      // Words inside a labelled button are not voiced: the polite region (the dialog's, in one) says the outcome.
      announce(next === "copied" ? "Copied" : next === "selected" ? `Selected, press ${MAC ? "Command" : "Control"} C` : "Couldn't copy");
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setOutcome(""), 1200);
    },
  ];
}

const MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

/** A mono value, or a block with `block`; a click selects it all and copies it. */
export function Copy({
  value,
  block,
  label,
  children,
  className,
}: {
  value: string;
  block?: boolean;
  /** The accessible name ("Copy token"). */
  label?: string;
  /** What shows, when it differs from what is copied. */
  children?: ReactNode;
  className?: string;
}) {
  const text = useRef<HTMLSpanElement>(null);
  const [outcome, show] = useOutcome();
  return (
    <button
      type="button"
      className={cn("sh-copy", block && "sh-copy--block", className)}
      aria-label={label ?? `Copy ${value}`}
      onClick={async () => show(await copyText(value, text.current))}
    >
      <span ref={text} className="sh-copy__value">
        {children ?? value}
      </span>
      {outcome === "copied" ? <Check className="sh-copy__icon" aria-hidden /> : <CopyIcon className="sh-copy__icon" aria-hidden />}
      <span className="sh-copy__done" aria-hidden>
        {outcome === "copied" ? "copied" : outcome === "selected" ? `selected · ${MAC ? "⌘" : "Ctrl+"}C` : ""}
      </span>
    </button>
  );
}

/** A 20px copy glyph for a value shown elsewhere (field pivots, ids in a header). */
export function CopyButton({ value, label }: { value: string; label?: string }) {
  const [outcome, show] = useOutcome();
  return (
    <button type="button" aria-label={label ?? "Copy"} onClick={async () => show(await copyText(value))}>
      {outcome === "copied" ? <Check aria-hidden /> : <CopyIcon aria-hidden />}
    </button>
  );
}
