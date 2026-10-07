/**
 * One response action, its one home: what, on what, its life from proposal to
 * undo, why it was asked for, the facts that bound it, its parameters and what
 * came back. Only words someone wrote are quoted: a playbook step, the
 * Manager's page conditions and shoc's own templates read as facts, and the
 * policy's objections as warn chips. The footer holds its controls: Undo (the one call site of
 * `action.undo`, behind a confirm with an optional note), Run now for an
 * approved action no run picked up, Decide for a proposal, Open case, Open run.
 * One mutation per open dialog, so one Undo never disables another. Opened
 * from a list (Response › Activity), it steps through that list with J and K.
 *
 * Capabilities used: action.list (the row, from the shared logs), action.undo,
 * action.run; the cached playbook.list for a step's playbook title.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { RotateCcw } from "lucide-react";
import { useCommand } from "@/lib/commands";
import { clock, stamp } from "@/lib/format";
import { actionLabel, actionState, isPage, pageState, reachLabel, stepState } from "@/lib/labels";
import { conditionWords, splitRationale } from "@/lib/policy";
import { useActionLog, usePlaybooks, useProposals, useRunAction, useUndo } from "@/lib/queries";
import { toastError } from "@/lib/toast";
import { who } from "@/lib/crew";
import { bare, parseEntity } from "@/lib/entity";
import type { Action } from "@/types";
import { RunDialog } from "./RunDialog";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Dialog, Fields, Json } from "./ui/dialog";
import { Entity } from "./ui/entity";
import { Quote } from "./ui/field";
import { Empty, ErrorNote } from "./ui/misc";
import { Confirm, Popover } from "./ui/pop";
import { Seg } from "./ui/seg";
import { Skel } from "./ui/state";
import { AutonomyBadge, Status } from "./ui/status";
import { Steps, type Step } from "./ui/steps";
import { Tip } from "./ui/tip";

/** The row by uid from the shared logs, the freshest first; `given` while they load. */
function useActionRow(uid: string, given?: Action) {
  const proposals = useProposals();
  const log = useActionLog();
  const row =
    proposals.data?.rows.find((a) => a.action_uid === uid) ??
    log.data?.rows.find((a) => a.action_uid === uid) ??
    given;
  const pending = !row && (proposals.isPending || log.isPending);
  // A list that failed cannot say the action is missing.
  const error = row || pending ? null : (proposals.error ?? log.error);
  const retry = () => {
    void proposals.refetch();
    void log.refetch();
  };
  return { row, pending, error, retry };
}

/** Parameters only the delivery reads: a page's dedup key and its notices. */
const PLUMBING = new Set(["dedup_key", "details", "notices"]);

const undoable = (a: Action) => a.state === "done" && a.reversible && !a.dry_run;

/** Why it was asked for: free words are quoted with their author; a template reads as the facts it holds. */
function Why({ row, said }: { row: Action; said: string }) {
  const playbooks = usePlaybooks();
  if (!said) return null;
  const step = /^playbook (\S+), step '(.+)'$/.exec(said);
  if (step) {
    const id = step[1]!;
    const title = playbooks.data?.playbooks.find((p) => p.id === id)?.title ?? id;
    return (
      <p className="m-0 flex min-w-0 flex-wrap items-center gap-1.5">
        <Link to={`/response/playbooks/${encodeURIComponent(id)}`} className="sh-link">
          {title}
        </Link>
        <span className="sh-mono">· {step[2]}</span>
      </p>
    );
  }
  const conditions = conditionWords(said);
  if (conditions) return <p className="sh-mono m-0">{conditions.join(" · ")}</p>;
  const fallback = /^the fallback for (\S+) on .+, which nobody approved$/.exec(said);
  if (fallback) return <p className="sh-mono m-0">fallback of {actionLabel(fallback[1]!)} · nobody approved</p>;
  // shoc's own hand (the unattended sweep, expiry, the worker) wrote a sentence nobody said.
  if (who(row.requested_by).kind === "system") return <p className="sh-mono m-0">{said}</p>;
  return (
    <Quote by={row.requested_by} at={row.created_at}>
      {said}
    </Quote>
  );
}

/** When a timed block undoes itself (the kernel's `action.expire`): executed_at + params.ttl_minutes. */
function expiry(a: Action): string | null {
  const ttl = Number(a.params?.ttl_minutes ?? 0);
  const from = a.executed_at ?? a.updated_at;
  if (!ttl || !from) return null;
  return new Date(Date.parse(from) + ttl * 60_000).toISOString();
}

/** A page reads in a page's words (delivered, not sent, withdrawn), as on both Pages lists. */
const stateOf = (a: Action) => (isPage(a) ? pageState(a) : actionState(a));

function lifecycle(a: Action): Step[] {
  const by = (author: string | null | undefined) => (author ? who(author).name : "");
  const decided = ["approved", "running", "done", "failed", "rolled_back"].includes(a.state) || Boolean(a.approved_at);
  const steps: Step[] = [
    { key: "proposed", label: "proposed", state: "done", time: a.created_at, tip: `${stamp(a.created_at)} · ${by(a.requested_by)}` },
  ];
  if (a.state === "rejected")
    steps.push({ key: "decided", label: stateOf(a).word, state: "failed", time: a.updated_at ?? null, tip: by(a.approved_by) || undefined });
  else if (a.state === "proposed") steps.push({ key: "decided", label: "approval", state: "waiting" });
  else
    steps.push({
      key: "decided",
      label: a.autonomy === "L2" ? "approved" : "allowed",
      state: decided ? "done" : "todo",
      time: a.approved_at ?? null,
      tip: a.approved_at ? `${stamp(a.approved_at)}${a.approved_by ? ` · ${by(a.approved_by)}` : ""}` : by(a.approved_by) || undefined,
    });
  steps.push({
    key: "executed",
    label: a.dry_run && (a.state === "done" || a.state === "rolled_back") ? "planned" : a.state === "failed" ? "failed" : "done",
    state: a.state === "rejected" ? "skipped" : a.state === "rolled_back" ? "done" : stepState(a.state === "approved" ? "todo" : a.state),
    time: a.executed_at ?? null,
  });
  if (a.state === "rolled_back") steps.push({ key: "undone", label: stateOf(a).word, state: "done", time: a.updated_at ?? null });
  else if (undoable(a)) {
    const until = expiry(a);
    steps.push({ key: "undone", label: until ? `undoes itself ${clock(until)}` : "undo", state: "todo", time: until });
  }
  return steps;
}

export function ActionDialog({
  action,
  uid,
  undo = false,
  onClose,
  onDecide,
  step,
}: {
  /** The row that opened it; refreshed from the shared logs. */
  action?: Action;
  /** Or only its id, from `?action=`. */
  uid?: string;
  /** Open the Undo confirm at once (`&do=undo`, the toasts' Undo, the Z key). */
  undo?: boolean;
  onClose: () => void;
  /** A proposal's Decide: hand over to ApprovalDialog. */
  onDecide?: (uid: string) => void;
  /** "3 / 25" and J/K over the list that opened it. */
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const id = action?.action_uid ?? uid ?? "";
  const { row, pending, error, retry } = useActionRow(id, action);
  const [view, setView] = useState<"details" | "result">("details");
  const [asking, setAsking] = useState(false);
  const [run, setRun] = useState(false);
  const undoIt = useUndo();
  const runIt = useRunAction();
  const [, setParams] = useSearchParams();
  // A screen's own dialog hands a proposal to the shell's ApprovalDialog through `?decide=`.
  const decide =
    onDecide ??
    ((uid: string) => {
      onClose();
      setParams((current) => {
        const out = new URLSearchParams(current);
        out.set("decide", uid);
        return out;
      });
    });
  const canUndo = row ? undoable(row) : false;

  useEffect(() => {
    if (undo && canUndo) setAsking(true);
  }, [undo, canUndo]);
  useCommand("action.undo", () => setAsking(true), canUndo);

  if (!row)
    return (
      <Dialog title="Action" id={id} onClose={onClose} step={step}>
        {pending ? (
          <Skel kind="block" />
        ) : error ? (
          <ErrorNote error={error} onRetry={retry} />
        ) : (
          <Empty kind="page" title="Not among the latest 500 actions" />
        )}
      </Dialog>
    );

  const label = actionLabel(row.type);
  const state = stateOf(row);
  // A page's words are the record: shown as a quote, not as a parameter.
  const page = isPage(row);
  const said = page ? ["summary", "message", "text"].find((k) => typeof row.params?.[k] === "string") : undefined;
  const message = said ? String(row.params[said]) : "";
  // A parameter that only repeats the target is the target chip's; delivery plumbing and a case's severity are not the reader's.
  const params = Object.entries(row.params ?? {}).filter(
    ([k, v]) =>
      k !== said &&
      !PLUMBING.has(k) &&
      !(k === "severity" && row.case_uid) &&
      !(typeof v === "string" && v && (v === row.target || v === bare(row.target))),
  );
  const reach = row.blast_radius?.principals;
  const why = splitRationale(row.rationale ?? "", row);

  const facts: ReactNode[] = [
    // The head badge already says "planned" or "plan undone" for a dry run that finished.
    row.dry_run && !state.word.startsWith("plan") ? (
      <Badge key="dry" tone="idle">
        dry run
      </Badge>
    ) : null,
    <AutonomyBadge key="level" level={row.autonomy} />,
    parseEntity(row.target) ? (
      <Entity key="target" value={row.target} button />
    ) : row.target && row.target !== message ? (
      <span key="target" className="sh-mono sh-mono--strong max-w-full truncate">
        {row.target}
      </span>
    ) : null,
    reach === undefined || reach === 0 ? null : (
      <Badge key="reach" tone={reach < 0 ? "warn" : undefined}>
        {reachLabel(reach)}
      </Badge>
    ),
    row.reversible ? <Badge key="rev" tone="idle">↺ reversible</Badge> : <Badge key="rev" tone="bad">⊘ one-way</Badge>,
    row.fallback ? <Badge key="fallback">→ {actionLabel(row.fallback)}</Badge> : null,
    row.grounded === false ? (
      <Badge key="grounded" tone="warn">
        target from a log line
      </Badge>
    ) : null,
    row.chased_at ? (
      <Badge key="paged" tone="idle">
        paged {clock(row.chased_at)}
      </Badge>
    ) : null,
    ...why.guards.map((guard) => (
      <Badge key={`guard:${guard}`} tone="warn">
        {guard}
      </Badge>
    )),
  ];

  const footer = (
    <>
      {row.case_uid ? (
        <Link to={`/cases/${row.case_uid}`} className="sh-btn sh-btn--ghost sh-btn--md">
          Open case
        </Link>
      ) : null}
      {row.run_uid ? (
        <Button variant="ghost" onClick={() => setRun(true)}>
          Open run
        </Button>
      ) : null}
      {row.state === "proposed" ? (
        <Button variant="crew" onClick={() => decide(row.action_uid)}>
          Decide
        </Button>
      ) : null}
      {row.state === "approved" ? (
        <Button
          disabled={runIt.isPending}
          onClick={() => runIt.mutate(row, { onError: (error) => toastError(error, "Run failed") })}
        >
          Run now
        </Button>
      ) : null}
      {canUndo ? (
        <Popover
          open={asking}
          onOpenChange={setAsking}
          label={`Undo ${label}`}
          align="end"
          trigger={(props) => (
            <Tip label="Undo" kbd="U">
              <Button {...props} variant="danger" aria-keyshortcuts="U" disabled={undoIt.isPending}>
                <RotateCcw aria-hidden />
                Undo
              </Button>
            </Tip>
          )}
        >
          <Confirm
            what={`Undo ${label} · ${bare(row.target)}`}
            go="Undo"
            danger
            note={{ placeholder: "Note (optional)" }}
            onConfirm={(note) =>
              undoIt.mutateAsync({ action_uid: row.action_uid, ...(note ? { note } : {}) }).then(() => setAsking(false))
            }
            onCancel={() => setAsking(false)}
          />
        </Popover>
      ) : null}
    </>
  );

  return (
    <>
      <Dialog
        title={label}
        id={row.action_uid}
        onClose={onClose}
        step={step}
        head={
          // "waits" is the crew asking: the status mark in crew ink.
          <Status tone={state.tone} badge>
            {state.word}
          </Status>
        }
        footer={footer}
      >
        <Steps steps={lifecycle(row)} label="Lifecycle" />
        <div className="flex flex-wrap items-center gap-1.5">{facts}</div>
        <Why row={row} said={why.said} />
        {message ? (
          <Quote label="message" crew={who(row.requested_by).kind === "crew"}>
            {message}
          </Quote>
        ) : null}
        {row.error ? <p className="sh-mono m-0 text-bad">{row.error}</p> : null}
        <Seg
          label="View"
          className="self-start"
          value={view}
          options={[
            { value: "details", label: "Details" },
            { value: "result", label: "Result" },
          ]}
          onChange={setView}
        />
        {view === "details" ? (
          params.length ? (
            <Fields
              ruled
              rows={params.map(([k, v]): [string, ReactNode] => [
                k.replace(/_/g, " "),
                <span className="sh-mono sh-mono--strong">{typeof v === "string" ? v : JSON.stringify(v)}</span>,
              ])}
            />
          ) : (
            <Empty title={Object.keys(row.params ?? {}).length ? "No other parameters" : "No parameters"} />
          )
        ) : Object.keys(row.result ?? {}).length ? (
          <Json value={row.result} />
        ) : (
          <Empty title="Nothing came back yet" />
        )}
      </Dialog>
      {run && row.run_uid ? <RunDialog runUid={row.run_uid} onClose={() => setRun(false)} /> : null}
    </>
  );
}
