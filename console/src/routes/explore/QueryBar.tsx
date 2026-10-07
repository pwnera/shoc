/**
 * The one query box. Typed `field op value` terms become chips at the next
 * space; free words stay text. A chip's × runs the query without it; a chip
 * not run yet is dashed. Field names complete from the OCSF paths and values
 * from the field rail's tops (a native datalist). Enter or ⌘↵ runs; ↑ in an
 * empty box steps back through this viewer's recent queries.
 */
import { forwardRef, useId, useImperativeHandle, useRef, useState, type KeyboardEvent } from "react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/filterbar";
import { Tip } from "@/components/ui/tip";
import { keyLabel } from "@/lib/commands";
import { FIELDS, splitTerms, term } from "@/lib/explore";
import { recentQueries } from "./query";

const TERM = /^([A-Za-z_][A-Za-z0-9_.@$-]*)(!=|>=|<=|!~|[=~<>])(.*)$/;
const balanced = (text: string) => (text.match(/"/g)?.length ?? 0) % 2 === 0 && (text.match(/'/g)?.length ?? 0) % 2 === 0;

/** A query as chips (terms) and the words left over. */
function parse(q: string): { chips: string[]; text: string } {
  const parts = splitTerms(q);
  return {
    chips: [...new Set(parts.filter((p) => TERM.test(p)))],
    text: parts.filter((p) => !TERM.test(p)).join(" "),
  };
}

const join = (chips: string[], text: string) => [...new Set([...chips, ...splitTerms(text)])].join(" ");

export type QueryBarHandle = { focus: () => void; run: () => void };

export const QueryBar = forwardRef<
  QueryBarHandle,
  { q: string; onRun: (q: string) => void; values: Record<string, string[]> }
>(function QueryBar({ q, onRun, values }, ref) {
  const input = useRef<HTMLInputElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const list = useId();
  const [draft, setDraft] = useState(() => parse(q));
  const [seen, setSeen] = useState(q);
  const recall = useRef(-1);
  // A new running query (a run, a pivot, Back, a link) replaces the draft.
  if (q !== seen) {
    setSeen(q);
    setDraft(parse(q));
  }
  useImperativeHandle(ref, () => ({ focus: () => input.current?.focus(), run: () => form.current?.requestSubmit() }), []);
  const running = new Set(splitTerms(q));

  const type = (text: string) => {
    recall.current = -1;
    // A finished term (a space after it, quotes closed) becomes a chip.
    if (/\s$/.test(text) && balanced(text)) {
      const next = parse(text);
      if (next.chips.length) return setDraft({ chips: [...new Set([...draft.chips, ...next.chips])], text: next.text ? `${next.text} ` : "" });
    }
    setDraft({ ...draft, text });
  };

  const remove = (chip: string) => {
    if (running.has(chip)) onRun(splitTerms(q).filter((t) => t !== chip).join(" "));
    else setDraft({ ...draft, chips: draft.chips.filter((c) => c !== chip) });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    // ⌘↵ runs here once; the shell then leaves the key alone.
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      form.current?.requestSubmit();
    } else if (event.key === "Backspace" && !draft.text && draft.chips.length) {
      event.preventDefault();
      const last = draft.chips.at(-1)!;
      setDraft({ chips: draft.chips.slice(0, -1), text: last });
    } else if ((event.key === "ArrowUp" || event.key === "ArrowDown") && (!draft.text || recall.current >= 0)) {
      const recent = recentQueries();
      const at = Math.max(-1, Math.min(recent.length - 1, recall.current + (event.key === "ArrowUp" ? 1 : -1)));
      if (at === recall.current) return;
      event.preventDefault();
      recall.current = at;
      setDraft(at < 0 ? parse(q) : parse(recent[at]!));
    }
  };

  // Completions for the token being typed, each the whole box value as the datalist needs it.
  const head = draft.text.replace(/\S*$/, "");
  const token = draft.text.slice(head.length);
  const m = TERM.exec(token);
  const options = m
    ? (values[m[1]!] ?? values[m[1]!.replace(/\./g, "_")] ?? [])
        .map((v) => term(m[1]!, v, m[2] as "=" | "!="))
        .filter((t) => t.startsWith(token))
    : token
      ? FIELDS.filter((f) => f.startsWith(token) && f !== token)
      : [];

  return (
    <form
      ref={form}
      role="search"
      className="flex min-h-8 flex-wrap items-center gap-1 rounded-control border border-line-3 bg-bg-2 py-1 pr-1 pl-2 focus-within:[box-shadow:var(--focus-ring)]"
      onSubmit={(event) => {
        event.preventDefault();
        onRun(join(draft.chips, draft.text));
      }}
    >
      {draft.chips.map((chip) => {
        const [, field = chip, op = "", value = ""] = TERM.exec(chip) ?? [];
        return (
          <Chip
            key={chip}
            label={field}
            value={`${op} ${value}`}
            active={running.has(chip)}
            dashed={!running.has(chip)}
            onRemove={() => remove(chip)}
          />
        );
      })}
      <input
        ref={input}
        className="h-6 min-w-[12rem] flex-1 border-0 bg-transparent text-fg-1 outline-hidden placeholder:text-fg-4 [font:var(--text-mono)] focus-visible:[box-shadow:none]"
        value={draft.text}
        onChange={(event) => type(event.target.value)}
        onKeyDown={onKeyDown}
        placeholder={draft.chips.length ? "" : "field = value"}
        aria-label="Query"
        aria-keyshortcuts="/"
        spellCheck={false}
        autoComplete="off"
        list={list}
      />
      <datalist id={list}>
        {options.slice(0, 8).map((o) => (
          <option key={o} value={`${head}${o}`} />
        ))}
      </datalist>
      <Tip label="Run" kbd={keyLabel("mod+enter")}>
        <Button type="submit" variant="primary" size="sm" aria-keyshortcuts="Meta+Enter Control+Enter">
          Run
        </Button>
      </Tip>
    </form>
  );
});
