/**
 * The approval card, the one call site of `action.approve` and
 * `action.reject`. Approve opens a confirm that restates autonomy,
 * reversibility, dry run, blast radius, the fallback and whether the target
 * came from a log line; Enter approves. Reject takes an optional note. Both
 * are optimistic: a compact row leaves at once and comes back, with the
 * hook's error toast, when the call fails. A screen's A and R keys reach it through `ref`.
 * Countdowns re-render from the shared 15s tick (`lib/now.ts`). In the
 * dialog's phone sheet (`pair`) Reject | Approve sit at its foot and the
 * confirm takes their place.
 */
import { useImperativeHandle, useState, type Ref } from "react";
import { Link } from "react-router-dom";
import { Bell, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/cn";
import { who } from "@/lib/crew";
import { bare } from "@/lib/entity";
import { clock, left } from "@/lib/format";
import { actionLabel, reachLabel } from "@/lib/labels";
import { usePhone } from "@/lib/media";
import { useNow } from "@/lib/now";
import { useApprove, useRejectAction } from "@/lib/queries";
import type { Action, Case } from "@/types";
import { Badge, SeverityBadge } from "./badge";
import { Button } from "./button";
import { Entity } from "./entity";
import { Confirm, Popover } from "./pop";
import { AutonomyBadge } from "./status";
import { Tip } from "./tip";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * Time left as "1h52" and a 3px bar: neutral above an hour, warn under one,
 * bad under 15 minutes, "expired" after. `elapsed` fills the bar as time
 * passes instead (suppression and token lifetimes), neutral to the end unless
 * `warnUnder` or `badUnder` (ms left) say otherwise: a suppression in warn
 * under 24h, a token in bad under 7 days.
 */
export function Countdown({
  until,
  from,
  to,
  elapsed,
  warnUnder,
  badUnder,
}: {
  until?: string | null;
  /** The start, for the bar's scale. */
  from?: string | null;
  /** The end, with `from`, for an elapsed countdown. */
  to?: string | null;
  elapsed?: boolean;
  /** Warn with less than this left (ms); an hour unless `elapsed`. */
  warnUnder?: number;
  /** Bad with less than this left (ms); 15 minutes unless `elapsed`. */
  badUnder?: number;
}) {
  const now = useNow();
  const endText = until ?? to;
  if (!endText) return null;
  const end = Date.parse(endText);
  if (Number.isNaN(end)) return null;
  const rest = end - now;
  if (rest <= 0)
    return (
      <span className={cn("sh-countdown", elapsed && "sh-countdown--elapsed")} data-tone="idle">
        expired
      </span>
    );
  const start = from ? Date.parse(from) : end - 4 * HOUR;
  const span = Math.max(1, end - start);
  const share = Math.max(0, Math.min(1, elapsed ? (now - start) / span : rest / span));
  const bad = badUnder ?? (elapsed ? 0 : 15 * MINUTE);
  const warn = warnUnder ?? (elapsed ? 0 : HOUR);
  const tone = rest < bad ? "bad" : rest < warn ? "warn" : undefined;
  const text = left(endText, now);
  return (
    <span
      className={cn("sh-countdown", elapsed && "sh-countdown--elapsed")}
      data-tone={tone}
      role="timer"
      aria-label={`${text} left`}
    >
      {text}
      <span className="sh-countdown__bar" aria-hidden>
        <i style={{ width: `${share * 100}%` }} />
      </span>
    </span>
  );
}

/** The chips that decide an approval: autonomy, reversible or one-way, dry run, blast radius, fallback, grounding. */
export function ActionFacts({
  action,
  autonomy,
  fallback = true,
}: {
  action: Action;
  autonomy?: string;
  /** Off where the countdown line already names the fallback. */
  fallback?: boolean;
}) {
  // Distinct accounts behind the target; -1 when the kernel could not see them.
  const reach = action.blast_radius?.principals;
  return (
    <>
      <AutonomyBadge level={autonomy ?? action.autonomy} />
      {action.reversible ? <Badge tone="idle">↺ reversible</Badge> : <Badge tone="bad">⊘ one-way</Badge>}
      {action.dry_run ? <Badge tone="idle">dry run</Badge> : null}
      {reach === undefined || reach === 0 ? null : <Badge tone={reach < 0 ? "warn" : undefined}>{reachLabel(reach)}</Badge>}
      {fallback && action.fallback ? <Badge>→ {actionLabel(action.fallback)}</Badge> : null}
      {action.grounded === false ? <Badge tone="warn">target from a log line</Badge> : null}
    </>
  );
}

/** What became of a decided action, in place of the buttons. */
function outcome(row: Action): string | null {
  if (row.state === "proposed") return null;
  const by = row.approved_by ? who(row.approved_by) : null;
  if (row.state === "rejected") {
    if (by?.key === "unattended") return row.fallback ? `fell back to ${actionLabel(row.fallback)}` : "expired";
    return by ? `rejected by ${by.name}${row.updated_at ? ` · ${clock(row.updated_at)}` : ""}` : "rejected";
  }
  if (by) return `approved by ${by.name}${row.approved_at ? ` · ${clock(row.approved_at)}` : ""}`;
  return row.state.replace(/_/g, " ");
}

export type ApprovalHandle = { approve: () => void; reject: () => void };

export function ApprovalCard({
  action,
  caseRow,
  run,
  variant = "full",
  autonomy,
  onOpen,
  active,
  pair,
  ref,
}: {
  action: Action;
  /** The action's case, for its severity badge and the Open case link. */
  caseRow?: Pick<Case, "case_uid" | "severity" | "title"> | null;
  /** The waiting run the approval resumes, by its playbook's title. */
  run?: { title: string } | null;
  /** full: the dialog; compact: a 40px inbox row; case: the decision bar (no severity, no Open case). */
  variant?: "full" | "compact" | "case";
  /** From `policy.show` for the action type; the row's own level otherwise. */
  autonomy?: string;
  /** A compact row's click: the ApprovalDialog. */
  onOpen?: () => void;
  active?: boolean;
  /** The ApprovalDialog: under 768px, 48px Reject | Approve at the sheet's foot instead of the card's own buttons. */
  pair?: boolean;
  ref?: Ref<ApprovalHandle>;
}) {
  const approve = useApprove();
  const reject = useRejectAction();
  const [asking, setAsking] = useState<"approve" | "reject" | null>(null);
  const [gone, setGone] = useState<"approved" | "rejected" | null>(null);
  const label = actionLabel(action.type);
  const what = `${label} · ${bare(action.target)}`;
  const decided = outcome(action);
  const open = !decided && !gone;
  const phone = usePhone();
  const sheet = Boolean(pair) && phone && open;

  useImperativeHandle(ref, () => ({
    approve: () => open && setAsking("approve"),
    reject: () => open && setAsking("reject"),
  }));

  // The hooks put the row back and raise the critical toast; the card only reopens.
  const failed = () => setGone(null);
  const doApprove = () => {
    setAsking(null);
    setGone("approved");
    approve.mutate(action.action_uid, { onError: failed });
  };
  const doReject = (note: string) => {
    setAsking(null);
    setGone("rejected");
    reject.mutate({ action_uid: action.action_uid, ...(note ? { note } : {}) }, { onError: failed });
  };

  if (variant === "compact" && gone) return null;

  const severity = variant !== "case" && caseRow ? <SeverityBadge severity={caseRow.severity} /> : null;
  const deadline = open && action.decide_by ? (
    <span className="sh-approval__deadline">
      <Countdown until={action.decide_by} from={action.created_at} />
      <span>→ {action.fallback ? actionLabel(action.fallback) : "expires"}</span>
      {action.chased_at ? (
        <Tip label={`paged ${clock(action.chased_at)}`}>
          <Bell role="img" aria-label="paged" />
        </Tip>
      ) : null}
    </span>
  ) : null;

  const confirmApprove = (
    <Confirm
      what={what}
      facts={<ActionFacts action={action} autonomy={autonomy} />}
      go="Approve"
      inline={sheet}
      onConfirm={doApprove}
      onCancel={() => setAsking(null)}
    />
  );
  const confirmReject = (
    <Confirm
      what={what}
      go="Reject"
      note={{ placeholder: "Why (optional)" }}
      inline={sheet}
      onConfirm={doReject}
      onCancel={() => setAsking(null)}
    />
  );

  const buttons = open ? (
    <span className="sh-approval__actions" onClick={(event) => event.stopPropagation()}>
      {sheet ? null : (
        <>
          <Popover
            open={asking === "approve"}
            onOpenChange={(now) => setAsking(now ? "approve" : null)}
            label={`Approve ${label}`}
            align="end"
            trigger={(props) => (
              <Tip label="Approve" kbd="A">
                <Button {...props} variant="primary" size="sm" aria-keyshortcuts="A" data-approve="">
                  Approve
                </Button>
              </Tip>
            )}
          >
            {confirmApprove}
          </Popover>
          <Popover
            open={asking === "reject"}
            onOpenChange={(now) => setAsking(now ? "reject" : null)}
            label={`Reject ${label}`}
            align="end"
            trigger={(props) => (
              <Tip label="Reject" kbd="R">
                <Button {...props} variant="ghost" size="sm" aria-keyshortcuts="R">
                  Reject
                </Button>
              </Tip>
            )}
          >
            {confirmReject}
          </Popover>
        </>
      )}
      {variant === "full" && action.case_uid ? (
        <Link className="sh-btn sh-btn--ghost sh-btn--sm" to={`/cases/${action.case_uid}?decide=${action.action_uid}`}>
          Open case
        </Link>
      ) : null}
    </span>
  ) : (
    <span className="sh-approval__settled">
      {gone ? `${gone} by you · ${clock(new Date().toISOString())}` : decided}
    </span>
  );

  if (variant === "compact")
    return (
      <div
        className={cn("sh-approval sh-approval--compact", !open && "sh-approval--settled")}
        data-active={active ? "" : undefined}
        role={onOpen ? "button" : undefined}
        tabIndex={onOpen ? 0 : undefined}
        onClick={onOpen}
        onKeyDown={(event) => {
          if (!onOpen || event.target !== event.currentTarget) return;
          if (event.key !== "Enter" && event.key !== " ") return;
          event.preventDefault();
          onOpen();
        }}
      >
        <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-crew" aria-hidden />
        {severity}
        <span className="sh-approval__head">
          <span className="sh-approval__title">{label}</span>
          <Entity value={action.target} />
        </span>
        {deadline}
        {buttons}
      </div>
    );

  return (
    <>
      <section
        className={cn("sh-approval", !open && "sh-approval--settled", (approve.isPending || reject.isPending) && "sh-approval--busy")}
        aria-label={label}
      >
        <div className="sh-approval__head">
          <h3 className="sh-approval__title">{label}</h3>
          <Entity value={action.target} button />
          {severity}
        </div>
        {variant === "full" ? (
          <div className="sh-approval__facts">
            <ActionFacts action={action} autonomy={autonomy} fallback={!deadline} />
          </div>
        ) : null}
        <div className="sh-approval__foot">
          {deadline}
          {run ? <span className="sh-approval__resumes">resumes {run.title}</span> : null}
          {buttons}
        </div>
      </section>
      {sheet ? (
        <div className="sh-approval__pair" role="group" aria-label="Decide">
          {asking === "approve" ? (
            confirmApprove
          ) : asking === "reject" ? (
            confirmReject
          ) : (
            <>
              <Button onClick={() => setAsking("reject")}>Reject</Button>
              <Button variant="primary" onClick={() => setAsking("approve")}>
                Approve
              </Button>
            </>
          )}
        </div>
      ) : null}
    </>
  );
}
