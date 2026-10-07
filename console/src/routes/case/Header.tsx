/**
 * The case's header: crumbs, title, severity and the crew's state on it, Close
 * and the ⋯ menu, the lifecycle stepper and the strip. The current step opens
 * a Move menu (M) of the moves the kernel allows; an allowed later step asks
 * for a note and moves there; closed opens the close dialog; other steps are
 * history or out of reach. A closed case locks the stepper and offers Reopen.
 * Under 768px the steps are dots with the current one named beside them;
 * where the stepper still scrolls sideways, it opens on the current step.
 *
 * Capabilities used: case.set_state, case.investigate, slack.notify (their
 * hooks toast what came back).
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Compass, Copy, MessageSquare, MoreHorizontal, RotateCcw, Undo2 } from "lucide-react";
import { CrewState } from "@/components/ui/avatar";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Confirm, MenuList, Popover, type MenuEntry } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Steps, type Step } from "@/components/ui/steps";
import { Tip } from "@/components/ui/tip";
import { copyAndSay } from "@/lib/copy";
import { shortId, stamp } from "@/lib/format";
import { CASE_STATES, caseStateLabel } from "@/lib/labels";
import { useInvestigate, useNotifySlack, useSetCaseState } from "@/lib/queries";
import { toast, toastError } from "@/lib/toast";
import { exploreOf } from "./links";
import type { Case, CaseState } from "@/types";

export type MenuAsk = "slack" | "reopen" | null;

type HeaderProps = {
  record: Case;
  waiting: boolean;
  stalled: boolean;
  /** The crew is on it now: Re-investigate waits. */
  working: boolean;
  window?: { window_start: string; window_end: string };
  strip: ReactNode;
  onClose: () => void;
  /** The ⋯ menu: open, and the confirm it opens on (a palette hand-off). */
  menu: { open: boolean; ask: MenuAsk };
  onMenu: (menu: { open: boolean; ask: MenuAsk }) => void;
  moving: boolean;
  onMoving: (open: boolean) => void;
};

/**
 * With no record yet, the header is a skeleton title (or the short id once
 * the case failed to load). The page draws it in every state, so the heading
 * the shell focused while the case loaded is the one that stays.
 */
export function Header(props: HeaderProps | { uid: string; record?: undefined; pending?: boolean }) {
  if (!props.record)
    return (
      <PageHeader
        title={props.pending ? <Skel kind="text" width="18em" /> : shortId(props.uid)}
        id={props.uid}
        copy
      />
    );
  const { record, waiting, stalled, working, window, strip, onClose, menu, onMenu, moving, onMoving } = props;
  const closed = record.state === "closed";
  return (
    <PageHeader
      title={record.title}
      id={record.case_uid}
      copy
      badges={
        <>
          <SeverityBadge severity={record.severity} />
          {closed ? null : <CrewState row={record} variant="full" waiting={waiting} stalled={stalled} />}
        </>
      }
      aside={
        <>
          {closed ? null : (
            <Tip label="Close case" kbd="C">
              <Button variant="primary" onClick={onClose} aria-keyshortcuts="C">
                <Check aria-hidden />
                Close
              </Button>
            </Tip>
          )}
          <CaseMenu record={record} working={working} window={window} menu={menu} onMenu={onMenu} />
        </>
      }
      strip={
        <>
          <Stepper record={record} onClose={onClose} moving={moving} onMoving={onMoving} />
          {strip}
        </>
      }
    />
  );
}

/** The moves `case.set_state` accepts (`shoc/cases/engine.py` ALLOWED); reopening lives in ⋯. */
const NEXT: Record<CaseState, readonly CaseState[]> = {
  triage: ["analysis", "containment", "closed"],
  analysis: ["containment", "closed"],
  containment: ["eradication", "closed"],
  eradication: ["recovery", "closed"],
  recovery: ["post_incident", "closed"],
  post_incident: ["closed"],
  closed: [],
};

function Stepper({
  record,
  onClose,
  moving,
  onMoving,
}: {
  record: Case;
  onClose: () => void;
  moving: boolean;
  onMoving: (open: boolean) => void;
}) {
  const setState = useSetCaseState();
  const at = CASE_STATES.indexOf(record.state);
  const closed = record.state === "closed";
  const box = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = box.current;
    const step = el?.querySelector('[aria-current="step"]')?.getBoundingClientRect();
    if (!el || !step || el.scrollWidth <= el.clientWidth) return;
    const view = el.getBoundingClientRect();
    el.scrollLeft += step.left + step.width / 2 - (view.left + view.width / 2);
  }, [record.state]);
  const move = (state: CaseState, note: string) =>
    setState
      .mutateAsync({ case_uid: record.case_uid, state, ...(note ? { note } : {}) })
      .then(() => toast({ tone: "ok", text: `Moved to ${caseStateLabel(state)}` }));

  const items: MenuEntry[] = NEXT[record.state].map((state) =>
    state === "closed"
      ? { label: "closed…", onSelect: onClose }
      : {
          label: caseStateLabel(state),
          onSelect: (note: string) => move(state, note),
          confirm: { what: `Move to ${caseStateLabel(state)}`, go: "Move", note: { placeholder: "Note (optional)" } },
        },
  );

  const steps: Step[] = CASE_STATES.map((state, i) => ({
    key: state,
    label: caseStateLabel(state),
    state: closed ? (state === "closed" ? "current" : "done") : i < at ? "done" : i === at ? "current" : "todo",
    time: state === "triage" ? record.opened_at : state === "closed" ? record.closed_at : null,
  }));
  const body = (step: Step, props: { className: string; children: ReactNode }) => {
    const state = step.key as CaseState;
    const i = CASE_STATES.indexOf(state);
    const label = caseStateLabel(state);
    // Past steps and a closed case's steps are history; a step the kernel refuses is out of reach.
    if (closed || i < at || (i > at && !NEXT[record.state].includes(state)))
      return (
        <Tip label={step.time ? stamp(step.time) : undefined}>
          <span {...props} />
        </Tip>
      );
    if (i === at)
      return (
        <Popover
          menu
          open={moving}
          onOpenChange={onMoving}
          trigger={(trigger) => (
            <Tip label="Move to…" kbd="M">
              <button {...trigger} {...props} type="button" aria-keyshortcuts="M" />
            </Tip>
          )}
        >
          {(close) => <MenuList items={items} close={close} label="Move to" />}
        </Popover>
      );
    if (state === "closed") return <button {...props} type="button" onClick={onClose} />;
    return (
      <Popover
        label={`Move to ${label}`}
        trigger={(trigger) => <button {...trigger} {...props} type="button" />}
      >
        {(close) => (
          <Confirm
            what={`Move to ${label}`}
            go="Move"
            note={{ placeholder: "Note (optional)" }}
            onConfirm={(note) => move(state, note).then(close)}
            onCancel={close}
          />
        )}
      </Popover>
    );
  };

  return (
    // A closed case's steps are all history, no button among them: the box itself takes focus, so it scrolls by key.
    // Under 768px a step's word is for screen readers only; the name after the dots says it for the current one.
    <div className="flex items-center gap-3">
      <div
        ref={box}
        className="min-w-0 flex-1 overflow-x-auto scrollbar-thin md:[&>.sh-steps]:min-w-[34rem] max-md:[&_.sh-steps\_\_body]:w-full max-md:[&_.sh-steps\_\_label]:sr-only"
        {...(closed ? { role: "group", "aria-label": "Lifecycle", tabIndex: 0 } : {})}
      >
        <Steps steps={steps} label="Lifecycle" body={body} />
      </div>
      <span className="shrink-0 font-mono text-xs text-fg-1 tabular md:hidden" aria-hidden>
        {caseStateLabel(record.state)} · {at + 1}/{CASE_STATES.length}
      </span>
    </div>
  );
}

function CaseMenu({
  record,
  working,
  window,
  menu,
  onMenu,
}: {
  record: Case;
  working: boolean;
  window?: { window_start: string; window_end: string };
  menu: { open: boolean; ask: MenuAsk };
  onMenu: (menu: { open: boolean; ask: MenuAsk }) => void;
}) {
  return (
    <Popover
      menu
      align="end"
      label="More"
      open={menu.open}
      onOpenChange={(open) => onMenu({ open, ask: open ? menu.ask : null })}
      trigger={(props) => (
        <Tip label="More" kbd=".">
          <Button {...props} variant="ghost" size="icon" aria-label="More" aria-keyshortcuts=".">
            <MoreHorizontal aria-hidden />
          </Button>
        </Tip>
      )}
    >
      {(close) => <MenuBody record={record} working={working} window={window} ask={menu.ask} close={close} />}
    </Popover>
  );
}

function MenuBody({
  record,
  working,
  window,
  ask: asked,
  close,
}: {
  record: Case;
  working: boolean;
  window?: { window_start: string; window_end: string };
  ask: MenuAsk;
  close: () => void;
}) {
  const navigate = useNavigate();
  const investigate = useInvestigate();
  const notify = useNotifySlack();
  const setState = useSetCaseState();
  const [ask, setAsk] = useState<MenuAsk>(asked);
  const id = shortId(record.case_uid);
  const closed = record.state === "closed";

  if (ask === "slack")
    return (
      <Confirm
        what={`Post ${id} to Slack`}
        go="Post"
        onConfirm={() => notify.mutateAsync(record.case_uid).then(close)}
        onCancel={() => setAsk(null)}
      />
    );
  if (ask === "reopen")
    return (
      <Confirm
        what={`Reopen ${id}`}
        go="Reopen"
        note={{ placeholder: "Why (optional)" }}
        onConfirm={(note) =>
          setState
            .mutateAsync({ case_uid: record.case_uid, state: "triage", ...(note ? { note } : {}) })
            .then(() => {
              toast({ tone: "ok", text: `Reopened ${id}` });
              close();
            })
        }
        onCancel={() => setAsk(null)}
      />
    );

  const items: MenuEntry[] = [
    ...(closed
      ? []
      : [
          {
            label: "Re-investigate",
            icon: RotateCcw,
            disabled: working || investigate.isPending,
            onSelect: () =>
              investigate.mutate(record.case_uid, { onError: (error) => toastError(error, "Re-investigate failed") }),
          },
        ]),
    { label: "Post to Slack", icon: MessageSquare, keepOpen: true, onSelect: () => setAsk("slack") },
    { label: "Copy id", icon: Copy, onSelect: () => void copyAndSay(record.case_uid, id) },
    { label: "Events in Explore", icon: Compass, onSelect: () => navigate(exploreOf(record, window)) },
    ...(closed ? [{ sep: true } as const, { label: "Reopen", icon: Undo2, keepOpen: true, onSelect: () => setAsk("reopen") }] : []),
  ];
  return <MenuList items={items} close={close} label="More" />;
}
