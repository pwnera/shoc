/**
 * Merge a rule, a hunt pack or a playbook written as YAML: one editor tab per
 * part of the capability's input (Rule, Fixtures, ADS; Pack, Fixtures;
 * Playbook), a one-line reason, and above them whatever the caller links by
 * name, such as the playbook a rule hands its cases to. Check runs the gate
 * with `dry_run` and writes nothing; Merge opens once Check has passed on the
 * input as it stands. A parse error names its tab and marks its line; a
 * refusal lists each reason the gate gave, marks the tab a reason names, and
 * dims once the input changes. The draft waits in this tab's sessionStorage
 * per merge and backlog item, so Escape, the backdrop or Back never cost it;
 * a merge clears it, and Start over brings back the template.
 *
 * Capabilities used: detection.merge, hunt.merge, playbook.merge.
 */
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { GitMerge, ShieldCheck } from "lucide-react";
import { parse, YAMLParseError } from "yaml";
import { YamlEditor } from "@/components/YamlEditor";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { ErrorNote, Input, Spinner, Tabs } from "@/components/ui/misc";
import { Status } from "@/components/ui/status";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { Section } from "@/lib/merge";
import { useMerge, type MergeCapability } from "@/lib/queries";
import { go, toast } from "@/lib/toast";

type Data = Record<string, unknown>;
type Problem = { field: string; line: number | null; message: string };
type Draft = { texts: Record<string, string>; reason: string };

/** Every tab parsed into the input, or the first tab that does not parse. */
function read(sections: Section[], texts: Record<string, string>): { doc: Data; problem: Problem | null } {
  const doc: Data = {};
  for (const s of sections) {
    try {
      const value: unknown = parse(texts[s.field] ?? "");
      if (value !== null && value !== undefined) doc[s.field] = value;
    } catch (error) {
      const line = error instanceof YAMLParseError ? (error.linePos?.[0].line ?? null) : null;
      // The line is shown on its own; the parser repeats it at the end of its message.
      const message = (error instanceof Error ? error.message : String(error))
        .split("\n")[0]!
        .replace(/ at line \d+, column \d+:?$/, "");
      return { doc, problem: { field: s.field, line, message } };
    }
  }
  return { doc, problem: null };
}

/** Every reason the gate refused, one per entry; a refusal without its list is one reason, and anything else (a denial) stays one note. */
const reasons = (error: unknown) =>
  error instanceof ApiError && (error.code === "gate_refused" || error.reasons.length > 0 || /^not merged: /.test(error.message))
    ? error.reasons.length
      ? error.reasons
      : [error.message.replace(/^not merged: /, "")]
    : null;

/** The tab a refusal names, marked as a parse error marks its own. */
const NAMED: Record<string, RegExp> = { fixtures: /fixture/i, ads: /\bADS\b/ };

/** Where each merge lands once it is in. */
const OPEN: Record<MergeCapability, (d: Data) => string> = {
  "detection.merge": (d) => `/detection/rules/${encodeURIComponent(String(d.rule_id))}`,
  "hunt.merge": (d) => `/hunts?pack=${encodeURIComponent(String(d.pack_id))}`,
  "playbook.merge": (d) => `/response/playbooks/${encodeURIComponent(String(d.playbook_id))}`,
};

function load(key: string): Draft | null {
  try {
    return JSON.parse(sessionStorage.getItem(key) ?? "null") as Draft | null;
  } catch {
    return null;
  }
}

export function MergeDialog({
  title,
  capability,
  sections,
  reasonExample,
  extra,
  head,
  missing,
  facts,
  onClose,
}: {
  title: string;
  capability: MergeCapability;
  sections: Section[];
  reasonExample: string;
  /** Fields the caller sets: the backlog item, the linked playbook. */
  extra?: Data;
  /** Pickers above the editor, given the input as it parses now and what `missing` said once Check was pressed. */
  head?: (doc: Data, missing: string | null) => ReactNode;
  /** What the caller still needs before the gate can answer ("Pick a playbook"), or null. */
  missing?: () => string | null;
  /** What a passing check shows, from its data. */
  facts: (data: Data) => [string, ReactNode][];
  onClose: () => void;
}) {
  const form = useId();
  const merge = useMerge(capability);
  const check = useRef<HTMLButtonElement>(null);
  const store = `shoc.merge.${capability}.${String(extra?.item_uid ?? "")}`;
  const template = () => Object.fromEntries(sections.map((s) => [s.field, s.template]));
  const [saved] = useState(() => load(store));
  const [texts, setTexts] = useState<Record<string, string>>(() => ({ ...template(), ...saved?.texts }));
  const [tab, setTab] = useState(sections[0]!.field);
  const [reason, setReason] = useState(saved?.reason ?? "");
  const [shown, setShown] = useState<Problem | null>(null);
  const [passed, setPassed] = useState<{ key: string; data: Data } | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [tried, setTried] = useState(false);

  const { doc, problem } = read(sections, texts);
  const input: Data = { ...doc, ...(reason.trim() ? { reason: reason.trim() } : {}), ...extra };
  const key = JSON.stringify(input);
  const fresh = !problem && passed?.key === key;
  const blocked = missing?.() ?? null;
  const edited = Boolean(reason) || sections.some((s) => (texts[s.field] ?? "") !== s.template);

  // Kept as it changes, so a close of any kind leaves the draft for the next open.
  useEffect(() => {
    try {
      if (edited) sessionStorage.setItem(store, JSON.stringify({ texts, reason }));
      else sessionStorage.removeItem(store);
    } catch {
      /* storage off: the draft lasts while the dialog is open */
    }
  }, [store, texts, reason, edited]);

  const send = (dry: boolean) => {
    setShown(problem);
    if (problem) return setTab(problem.field);
    if (blocked) return setTried(true);
    if (merge.isPending) return;
    merge.mutate(
      { ...input, dry_run: dry },
      {
        onSuccess: ({ data }) => {
          if (dry) return setPassed({ key, data });
          try {
            sessionStorage.removeItem(store);
          } catch {
            /* nothing was kept */
          }
          const called = (doc[sections[0]!.field] as { title?: unknown } | undefined)?.title;
          const to = OPEN[capability](data);
          toast({
            tone: "ok",
            text: typeof called === "string" && called ? `Merged · ${called}` : "Merged",
            action: { label: "Open", to, run: () => go(to) },
          });
          onClose();
        },
        onError: () => {
          setPassed(null);
          setFailed(key);
        },
      },
    );
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    send(true);
  };
  const refused = merge.error ? reasons(merge.error) : null;
  // A refusal of an input since edited stays readable, dimmed, and marks no tab.
  const stale = failed !== null && failed !== key;
  const flagged = (field: string) => !stale && (refused ?? []).some((r) => NAMED[field]?.test(r));
  const current = sections.find((s) => s.field === tab) ?? sections[0]!;
  // A fixed problem stops showing as soon as its tab parses.
  const live = shown && problem && shown.field === problem.field ? problem : null;

  return (
    <Dialog
      title={title}
      size="wide"
      onClose={onClose}
      footer={
        <>
          {saved && edited ? (
            <Button
              variant="ghost"
              className="mr-auto"
              onClick={() => {
                setTexts(template());
                setReason("");
              }}
            >
              Start over
            </Button>
          ) : null}
          <Button ref={check} type="submit" form={form} disabled={merge.isPending}>
            {merge.isPending && merge.variables?.dry_run ? <Spinner /> : <ShieldCheck aria-hidden />}
            Check
          </Button>
          <Button variant="primary" disabled={!fresh || merge.isPending} onClick={() => send(false)}>
            {merge.isPending && !merge.variables?.dry_run ? <Spinner /> : <GitMerge aria-hidden />}
            Merge
          </Button>
        </>
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Reason">
            <Input value={reason} placeholder={reasonExample} onChange={(event) => setReason(event.target.value)} />
          </Field>
          {head?.(doc, tried ? blocked : null)}
        </div>
        {sections.length > 1 ? (
          <Tabs
            label="Parts"
            value={tab}
            onChange={setTab}
            tabs={sections.map((s) => ({
              value: s.field,
              label: s.label,
              ...(live?.field === s.field || flagged(s.field) ? { count: "!" } : {}),
            }))}
          />
        ) : null}
        <YamlEditor
          key={current.field}
          label={current.label}
          value={texts[current.field] ?? ""}
          onChange={(text) => setTexts((now) => ({ ...now, [current.field]: text }))}
          errorLine={live?.field === current.field ? live.line : null}
          onEscape={() => check.current?.focus()}
          autoFocus
        />
        {live ? (
          <ErrorNote error={`${sections.find((s) => s.field === live.field)?.label ?? live.field}${live.line ? `, line ${live.line}` : ""}: ${live.message}`} inline />
        ) : null}
        {refused ? (
          <div className={cn("flex flex-col gap-1", stale && "opacity-60")}>
            {stale ? <span className="sh-label">before your edit</span> : null}
            <ul role="alert" className="flex flex-col gap-1">
              {refused.map((r, i) => (
                <li key={i} className="sh-error sh-error--inline">
                  <span className="sh-error__text">{r}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : merge.error ? (
          <ErrorNote error={merge.error} inline />
        ) : null}
        {fresh ? (
          <div className="flex flex-col gap-2" role="status">
            <Status tone="good">Passes</Status>
            <Fields rows={facts(passed.data)} />
          </div>
        ) : null}
      </form>
    </Dialog>
  );
}
