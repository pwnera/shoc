/**
 * Needs you: every decision only a person can make, one row each, ordered by
 * severity, then the deadline, then how long it has waited. An approval is a
 * compact approval card (A approves and R rejects through its confirm); a
 * verdict, an expired approval, a case closed without its containment and a
 * credential open where they are decided.
 * A list that failed to load gets its own error row, so a failure never reads
 * as an empty inbox; one whose refresh failed keeps its rows and the head says
 * how old they are. Under 768px a row is two lines and an approval opens its
 * dialog, which carries Reject | Approve. Rows open, so the list is a grid to
 * assistive tech, as every table whose rows open is.
 *
 * Capabilities used: action.list, case.list, source.list (through
 * `useNeedsYou`), policy.show (an approval's autonomy), action.approve and
 * action.reject through the approval card.
 */
import { useId, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { KeyRound, Scale, ShieldOff, Telescope, TimerOff, type LucideIcon } from "lucide-react";
import { ApprovalCard, type ApprovalHandle } from "@/components/ui/approval";
import { SeverityBadge } from "@/components/ui/badge";
import { Card, CardHeader } from "@/components/ui/card";
import { Entity } from "@/components/ui/entity";
import { ProductLogo } from "@/components/ui/logo";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { useCommand, useListNav } from "@/lib/commands";
import { huntTitle } from "@/lib/cases";
import { useFlash } from "@/lib/flash";
import { bare } from "@/lib/entity";
import { age, clock } from "@/lib/format";
import { actionLabel } from "@/lib/labels";
import type { Needs } from "@/lib/needs";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { usePolicy } from "@/lib/queries";
import { connectorOf, sourceName } from "@/lib/sources";
import type { NeedsItem } from "@/types";
import { useInboxLists } from "./lists";

const LISTS = { approvals: "Approvals", actions: "Actions", cases: "Cases", closed: "Closed cases", sources: "Sources" } as const;


export function Inbox({ needs }: { needs: Needs }) {
  const navigate = useNavigate();
  const location = useLocation();
  const titleId = useId();
  const hint = useId();
  const policy = usePolicy();
  const { lists, failed, asOf } = useInboxLists(needs);
  const { page, pager, prev, next } = usePaged(needs.items, 25);

  // "?decide=" opens the dialog over Overview, whose URL holds nothing else; a page opened here comes back on Escape.
  const nav = useListNav(page, (item) => item.key, {
    onOpen: (item) => navigate(item.to, { state: { back: `${location.pathname}${location.search}` } }),
    onPrevPage: prev,
    onNextPage: next,
  });

  // A and R act on the active row, or the first one before any row was picked.
  const target = page.find((item) => item.key === nav.activeKey) ?? page[0];
  const card = useRef<ApprovalHandle>(null);
  const deciding = target?.kind === "approval";
  useCommand("overview.approve", () => card.current?.approve(), deciding);
  useCommand("overview.reject", () => card.current?.reject(), deciding);

  const fresh = useFlash(needs.pending ? undefined : needs.items.map((item) => [item.key, ""]));

  return (
    <Card aria-labelledby={titleId}>
      <CardHeader
        title={<span id={titleId}>Needs you</span>}
        subtitle={asOf ? <span className="sh-strip__stale">as of {clock(asOf)}</span> : null}
      />
      {failed.map((name) => (
        // pr-4 offsets Retry's -4px margin, so it ends on the Open column's edge.
        <div key={name} className="flex items-center gap-2 border-b border-line-1 pl-3 pr-4">
          <span className="sh-label">{LISTS[name]}</span>
          <div className="min-w-0 flex-1">
            <ErrorNote inline error={lists[name].error} onRetry={() => void lists[name].refetch()} />
          </div>
        </div>
      ))}
      {needs.pending ? (
        <div aria-busy="true">
          <span role="status" className="sr-only">
            loading
          </span>
          {[62, 48, 55].map((w) => (
            <div key={w} className="flex h-10 items-center border-b border-line-1 px-3 last:border-b-0">
              <Skel kind="row" width={`${w}%`} />
            </div>
          ))}
        </div>
      ) : page.length ? (
        <div role="grid" aria-labelledby={titleId} aria-readonly aria-describedby={hint} className="sh-inbox">
          <span id={hint} hidden>
            Enter opens the row
          </span>
          {page.map((item) => {
            const active = item.key === nav.activeKey;
            return (
              <div
                key={item.key}
                role="row"
                aria-selected={active}
                className="md:col-span-full md:grid md:grid-cols-subgrid"
                data-new={fresh.has(item.key) ? "" : undefined}
                {...nav.rowProps(item)}
              >
                <div role="gridcell" className="md:col-span-full md:grid md:grid-cols-subgrid">
                  {item.kind === "approval" && item.action ? (
                    <ApprovalCard
                      ref={item === target ? card : undefined}
                      variant="compact"
                      action={item.action}
                      caseRow={item.case ?? null}
                      autonomy={autonomyOf(policy.data?.data.actions, item.action.type)}
                      active={active}
                    />
                  ) : (
                    <Row item={item} active={active} />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : failed.length ? null : (
        // The heading already says "Nothing needs you"; the row adds only when a person last decided.
        <Empty kind="clear" title={needs.lastDecision ? `Last decision ${age(needs.lastDecision)} ago` : "No decisions yet"} />
      )}
      {needs.pending ? null : pager}
    </Card>
  );
}

function autonomyOf(actions: Record<string, Record<string, unknown>> | undefined, type: string): string | undefined {
  const level = actions?.[type]?.autonomy;
  return typeof level === "string" ? level : undefined;
}

const GLYPH: Record<Exclude<NeedsItem["kind"], "approval">, { icon: LucideIcon; crew?: boolean }> = {
  verdict: { icon: Scale, crew: true },
  expired: { icon: TimerOff },
  unacknowledged: { icon: ShieldOff },
  credential: { icon: KeyRound },
  rejected_credential: { icon: KeyRound },
};

/** A row that opens where its decision is made: glyph, badge, name, one time and the word for what to do. */
function Row({ item, active }: { item: NeedsItem; active: boolean }) {
  const now = useNow();
  const { icon: Icon, crew } = GLYPH[item.kind as keyof typeof GLYPH];
  const c = item.case;
  let title = "";
  let hunt = false;
  let entity: string | null = null;
  if ((item.kind === "verdict" || item.kind === "unacknowledged") && c) {
    // A hunt-born case trades its "Hunt:" prefix for a telescope, as on Cases and Findings.
    const bareTitle = huntTitle(c.title);
    hunt = bareTitle !== null;
    title = bareTitle ?? c.title;
    if (item.kind === "unacknowledged") title = `Not contained: ${title}`;
    entity = c.title.includes(bare(c.entity_key)) ? null : c.entity_key;
  } else if (item.kind === "expired" && item.action) {
    title = `Decide again: ${actionLabel(item.action.type)}`;
    entity = item.action.target;
  } else title = `${sourceName(item.source ?? "")} ${item.kind === "credential" ? "needs a credential" : "credential rejected"}`;
  // Under 768px the name's parts join the row, so the entity and the time share the second line.
  const second = "max-md:ml-[26px]";
  return (
    <div
      className={cn(
        "flex h-10 cursor-pointer items-center gap-3 border-b border-line-1 px-3 hover:bg-bg-2",
        "md:col-span-full md:grid md:grid-cols-subgrid md:[&>.sh-badge]:justify-self-start",
        "max-md:h-auto max-md:flex-wrap max-md:gap-y-1 max-md:py-2",
        active && "bg-bg-2 shadow-[inset_2px_0_0_var(--fg-1)]",
      )}
    >
      <span className="flex shrink-0 items-center gap-1">
        <Icon className={cn("h-3.5 w-3.5", crew ? "text-crew" : "text-fg-3")} aria-hidden />
        {item.source ? <ProductLogo product={connectorOf(item.source)} /> : null}
      </span>
      {item.severity ? <SeverityBadge severity={item.severity} /> : null}
      <span className="flex min-w-0 items-center gap-2 text-fg-1 max-md:contents md:col-start-3 md:h-5 md:flex-wrap md:overflow-hidden">
        {/* The telescope follows the title, so every name starts on one edge, and shares its item, so the
            wrapping name never strands it on the clipped line. */}
        <span className="flex min-w-0 items-center gap-2 max-md:flex-1">
          <span className="truncate">{title}</span>
          {hunt ? (
            <Tip label="From a hunt">
              <Telescope className="h-3.5 w-3.5 shrink-0 text-fg-3" role="img" aria-label="hunt" />
            </Tip>
          ) : null}
        </span>
        <span className="hidden basis-full max-md:block" aria-hidden />
        {entity ? (
          <span className={cn("flex max-w-max grow basis-[88px]", second)}>
            <Entity value={entity} />
          </span>
        ) : null}
      </span>
      <span className={cn("shrink-0 font-mono text-xs text-fg-3 tabular md:col-start-4 md:justify-self-end", !entity && second)}>{age(item.at, now)}</span>
      <span className="sh-btn sh-btn--ghost sh-btn--sm shrink-0 max-md:hidden md:col-start-5 md:justify-self-end" aria-hidden>
        {item.kind === "credential" || item.kind === "rejected_credential" ? "Fix" : "Open"}
      </span>
    </div>
  );
}
