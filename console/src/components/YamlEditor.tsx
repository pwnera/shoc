/**
 * A YAML text area that reads like code: line numbers, the rule page's inks
 * (keys, |modifiers, values) plus muted comments, a marked line for a parse
 * error, Tab indenting by two spaces (every selected line with a selection;
 * Shift+Tab outdents) and Escape leaving for the host's next control rather
 * than closing its dialog. Edits go through the browser, so undo works. The
 * text sits over its own inked copy in one grid cell, so the box grows with
 * the text and scrolls as one, gutter included.
 */
import { useId, type KeyboardEvent } from "react";
import { cn } from "@/lib/cn";
import { INK } from "@/routes/rule/yaml";

type Tok = { text: string; className?: string };

const KEY = /^(\s*)(- )?([^\s#'"][^:#]*?)((?:\|[\w]+)*)(:)(?=\s|$)/;

/** One line as tokens: indent, dash, key, |modifiers, colon, value, # comment. */
function ink(line: string): Tok[] {
  let quote = "";
  let cut = -1;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) quote = c === quote ? "" : quote;
    else if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]!))) {
      cut = i;
      break;
    }
  }
  const body = cut < 0 ? line : line.slice(0, cut);
  const out: Tok[] = [];
  const key = KEY.exec(body);
  let rest = body;
  if (key) {
    const [all, indent, dash, name, mods, colon] = key;
    out.push({ text: indent! }, ...(dash ? [{ text: dash, className: "text-fg-4" }] : []));
    out.push({ text: name!, className: indent ? INK.key : INK.name });
    if (mods) out.push({ text: mods, className: INK.mod });
    out.push({ text: colon!, className: "text-fg-4" });
    rest = body.slice(all.length);
  } else {
    const dash = /^(\s*)(- )/.exec(body);
    if (dash) {
      out.push({ text: dash[1]! }, { text: dash[2]!, className: "text-fg-4" });
      rest = body.slice(dash[0].length);
    }
  }
  if (rest) out.push({ text: rest, className: INK.value });
  if (cut >= 0) out.push({ text: line.slice(cut), className: "text-fg-4 italic" });
  return out;
}

const CODE = "m-0 whitespace-pre px-3 py-2 [font:var(--text-mono)] [tab-size:2]";

/** Put `text` over `from`–`to` through the browser, so undo works; jsdom and older engines take the plain path. */
function replace(area: HTMLTextAreaElement, from: number, to: number, text: string) {
  area.setSelectionRange(from, to);
  let done = false;
  try {
    done = document.execCommand("insertText", false, text);
  } catch {
    done = false;
  }
  if (!done) area.setRangeText(text, from, to, "end");
}

/** The lines a selection touches, indented by two spaces or outdented by up to two, and the selection after. */
function shift(text: string, start: number, end: number, out: boolean) {
  const from = text.lastIndexOf("\n", start - 1) + 1;
  // A selection that ends at a line's start leaves that line alone.
  const to = end > start && text[end - 1] === "\n" ? end - 1 : end;
  const lines = text.slice(from, to).split("\n");
  const moved = lines.map((line) => (out ? line.replace(/^ {1,2}/, "") : `  ${line}`));
  const block = moved.join("\n");
  const first = moved[0]!.length - lines[0]!.length;
  return { from, to, block, start: start === from ? from : Math.max(from, start + first), end: from + block.length + (end - to) };
}

export function YamlEditor({
  value,
  onChange,
  label,
  errorLine,
  autoFocus,
  onEscape,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  /** 1-based line the parser stopped at. */
  errorLine?: number | null;
  autoFocus?: boolean;
  /** Where Escape sends focus: the dialog's next control, so the key never closes it. */
  onEscape?: () => void;
}) {
  const hint = useId();
  const lines = value.split("\n");

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      return onEscape?.();
    }
    if (event.key !== "Tab") return;
    event.preventDefault();
    const area = event.currentTarget;
    const { selectionStart: start, selectionEnd: end } = area;
    if (start === end && !event.shiftKey) replace(area, start, end, "  ");
    else {
      const next = shift(area.value, start, end, event.shiftKey);
      replace(area, next.from, next.to, next.block);
      area.setSelectionRange(next.start, next.end);
    }
    onChange(area.value);
  };

  return (
    <div className="flex max-h-[55vh] min-h-72 overflow-auto rounded-[var(--radius-1)] border border-line-1 bg-bg-0 focus-within:border-line-2 focus-within:shadow-[var(--focus-ring)]">
      <ol aria-hidden className={cn(CODE, "sticky left-0 z-10 list-none select-none border-r border-line-1 bg-bg-0 pr-2 text-right text-fg-4")}>
        {lines.map((_, i) => (
          <li key={i} className={cn(errorLine === i + 1 && "font-semibold text-bad")}>
            {i + 1}
          </li>
        ))}
      </ol>
      <div className="grid min-w-0 flex-1">
        <pre aria-hidden className={cn(CODE, "pointer-events-none [grid-area:1/1]")}>
          {lines.map((line, i) => (
            <span key={i} className={cn("block", errorLine === i + 1 && "bg-bad-fill")}>
              {ink(line).map((t, j) => (
                <span key={j} className={t.className}>
                  {t.text}
                </span>
              ))}
              {"\n"}
            </span>
          ))}
        </pre>
        <textarea
          aria-label={label}
          aria-describedby={hint}
          className={cn(CODE, "resize-none overflow-hidden bg-transparent text-transparent caret-fg-1 !shadow-none !outline-none [grid-area:1/1] selection:bg-[var(--line-2)] selection:text-transparent")}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={onKeyDown}
          wrap="off"
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          {...(autoFocus ? { "data-autofocus": true } : {})}
        />
        <span id={hint} className="sr-only">
          Tab indents by two spaces; Escape leaves the editor.
        </span>
      </div>
    </div>
  );
}
