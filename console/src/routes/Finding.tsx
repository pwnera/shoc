/**
 * One finding: why it fired, on what, and whether it is handled. The header
 * holds the status control; the strip the finding's own facts (entity, span,
 * events, case); the main column the match, the entity graph, a tick per kept
 * event and the events themselves (but one event the match already lays
 * out); the rail the rule (its id's one home), the siblings and the
 * Sentinel's decision. Opened from a list, J and K step through it and Escape
 * goes back to it with its filters.
 *
 * Capabilities used: finding.get (the finding, its kept events and its rule),
 * finding.list (siblings over 14 days), finding.set_status.
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { EventDialog } from "@/components/EventDialog";
import { EventTable } from "@/components/EventTable";
import { ConfidenceBar, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Entity } from "@/components/ui/entity";
import { Graph, type Ring } from "@/components/ui/graph";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Skel } from "@/components/ui/state";
import { Strip, type StripFact } from "@/components/ui/strip";
import { TimeBar } from "@/components/ui/timebar";
import { Tip } from "@/components/ui/tip";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { rememberRow, useCommand, useEscBack } from "@/lib/commands";
import { bare, exploreQuery, parseEntity } from "@/lib/entity";
import { exploreHref, term, word } from "@/lib/explore";
import { day, num, shortId, span, time } from "@/lib/format";
import { findingCase } from "@/lib/labels";
import { useNewFindings } from "@/lib/live";
import { useClaim, usePopParam, usePopValue } from "@/lib/popup";
import { useCaseLog, useFinding } from "@/lib/queries";
import { attackGraph, LANE_LABELS, LAYERS } from "@/lib/story";
import type { Finding as FindingRow, OcsfEvent, Rule } from "@/types";
import { hm } from "./explore/query";
import { Match } from "./findings/Match";
import { Rail } from "./findings/Rail";
import { FindingStatus } from "./findings/Status";

/** What a list passes when it opens a finding: the uids in its order, where this one sits, and its URL. */
type Opened = { uids?: string[]; keys?: string[]; index?: number; back?: string };

/** The events of this finding's entity: its group for an aggregate, the rule's entity field, else the value. */
function entityQuery(finding: FindingRow, rule: Rule | undefined): string {
  const group = finding.evidence?.group;
  if (finding.evidence?.kind === "aggregate" && group && typeof group === "object")
    return Object.entries(group as Record<string, unknown>)
      .map(([column, value]) => term(column, String(value)))
      .join(" ");
  const value = bare(finding.entity_key);
  if (rule?.entity && !finding.entity_key.includes("|")) return term(rule.entity, value);
  const parsed = parseEntity(finding.entity_key);
  return parsed ? exploreQuery(parsed) : word(value);
}

/** "Thu 25 Sep 13:07 → 13:09 · 2m"; one instant to the second. */
function seen(first: string, last: string): string {
  const a = Date.parse(first);
  const b = Date.parse(last);
  if (!(b > a)) return `${day(first)} ${time(first)}`;
  const sameDay = day(first) === day(last);
  return `${day(first)} ${hm(first)} → ${sameDay ? "" : `${day(last)} `}${hm(last)} · ${span((b - a) / 1000)}`;
}

export function Finding() {
  const { findingUid = "" } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const opened = (location.state ?? {}) as Opened;
  const detail = useFinding(findingUid);
  const status = useRef<HTMLSpanElement>(null);
  // The evidence opens its own `?event=`, stepping through its rows; the shell's copy stays shut.
  useClaim("event");

  // A new finding may be this one firing again; it is cheap to look.
  const [fresh] = useNewFindings();
  const refetch = useRef(detail.refetch);
  useLayoutEffect(() => {
    refetch.current = detail.refetch;
  });
  useEffect(() => {
    if (fresh) void refetch.current();
  }, [fresh]);

  const uids = opened.uids ?? [];
  const index = opened.index ?? -1;
  const step = (to: number) => {
    const uid = uids[to];
    if (!uid) return;
    navigate(`/findings/${encodeURIComponent(uid)}`, { replace: true, state: { ...opened, index: to } });
    if (opened.back && opened.keys?.[to]) rememberRow(opened.back, opened.keys[to]);
  };
  useCommand("finding.next", () => step(index + 1), index >= 0 && index < uids.length - 1);
  useCommand("finding.prev", () => step(index - 1), index > 0);
  useEscBack("/findings");

  const finding = detail.data?.finding;
  const rule = detail.data?.rule && Object.keys(detail.data.rule).length ? detail.data.rule : undefined;
  const caseUid = finding ? findingCase(finding) : null;
  const explore = finding
    ? exploreHref({ q: entityQuery(finding, rule), since: finding.first_seen, until: new Date(Date.parse(finding.last_seen) + 1000).toISOString() })
    : "";
  useCommand("finding.status", () => status.current?.querySelector<HTMLElement>('[role="radio"][tabindex="0"]')?.focus(), Boolean(finding));
  useCommand("finding.open-case", () => caseUid && navigate(`/cases/${encodeURIComponent(caseUid)}`), Boolean(caseUid));
  useCommand("finding.explore", () => navigate(explore), Boolean(finding));

  const stepper =
    uids.length > 1 && index >= 0 ? (
      <span className="inline-flex items-center gap-1 sh-mono">
        <Tip label="Previous" kbd="K">
          <Button variant="ghost" size="sm" disabled={index <= 0} onClick={() => step(index - 1)} aria-label="Previous finding" aria-keyshortcuts="K">
            <ChevronLeft aria-hidden />
          </Button>
        </Tip>
        {index + 1} / {uids.length}
        <Tip label="Next" kbd="J">
          <Button variant="ghost" size="sm" disabled={index >= uids.length - 1} onClick={() => step(index + 1)} aria-label="Next finding" aria-keyshortcuts="J">
            <ChevronRight aria-hidden />
          </Button>
        </Tip>
      </span>
    ) : null;

  if (!finding) {
    const missing = detail.error instanceof ApiError && detail.error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        {detail.isPending ? (
          // The loaded header's rows (title, status control, badges, the strip's facts) held open, so nothing below moves.
          <PageHeader
            title={
              <span className="flex flex-col gap-2 py-1">
                <Skel kind="text" width="min(360px, 80%)" />
                <Skel kind="text" width="50%" className="md:hidden" />
              </span>
            }
            id={findingUid}
            copy
            badges={<Skel kind="badge" />}
            aside={
              <>
                {stepper}
                <Skel kind="badge" width={280} className="!h-6" />
              </>
            }
            strip={<Strip loading stateless facts={[{ key: "entity", label: "", value: null }, { key: "seen", label: "", value: null }, { key: "events", label: "events", value: null }]} />}
          />
        ) : (
          <PageHeader title={shortId(findingUid)} id={findingUid} copy aside={stepper} />
        )}
        {detail.isPending ? (
          <div className="sh-layout--aside" aria-busy="true">
            <span role="status" className="sr-only">
              loading
            </span>
            <div className="sh-layout__main">
              <Skel kind="block" />
              <Skel kind="block" />
            </div>
            <div className="sh-layout__aside">
              <Skel kind="block" />
            </div>
          </div>
        ) : missing ? (
          <Empty kind="page" title={`No finding ${shortId(findingUid)}`} action={<Link className="sh-link" to={opened.back ?? "/findings"}>Findings</Link>} />
        ) : (
          <ErrorNote error={detail.error} onRetry={() => void detail.refetch()} />
        )}
      </div>
    );
  }

  const events = detail.data?.events ?? [];
  const facts: StripFact[] = [
    {
      key: "entity",
      label: "",
      value: (
        <span className="inline-flex flex-wrap gap-1">
          {finding.entity_key.split("|").map((part) => (
            <Entity key={part} value={part} button />
          ))}
        </span>
      ),
    },
    { key: "seen", label: "", value: seen(finding.first_seen, finding.last_seen) },
    // Not a link: Explore can show the entity's events over the span, not the rule's matches.
    { key: "events", label: finding.event_count === 1 ? "event" : "events", value: finding.event_count },
    ...(caseUid ? [{ key: "case", label: "case", value: shortId(caseUid), to: `/cases/${encodeURIComponent(caseUid)}`, tip: <CaseTitle uid={caseUid} /> }] : []),
  ];

  return (
    // The facts wrap rather than scroll out of sight (a span wider than a phone wraps inside), a
    // long title wraps rather than push the severity and confidence off the line, and wrapped facts sit close.
    <div className="flex flex-col gap-4 [&_.sh-page\_\_badges]:shrink-0 [&_.sh-page\_\_title]:whitespace-normal [&_.sh-strip\_\_facts]:flex-wrap [&_.sh-strip\_\_facts]:gap-y-1 [&_.sh-strip\_\_facts]:overflow-visible [&_.sh-strip\_\_fact]:max-w-full [&_.sh-strip\_\_fact]:whitespace-normal">
      <PageHeader
        title={finding.title}
        id={finding.finding_uid}
        copy
        badges={
          <>
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBar value={finding.confidence} plain />
          </>
        }
        aside={
          <>
            {stepper}
            <FindingStatus ref={status} uid={finding.finding_uid} status={finding.status} />
          </>
        }
        strip={<Strip facts={facts} />}
      />
      {/* One column below lg: the rail comes after the match and before the event rows. */}
      <div className="sh-layout--aside max-lg:gap-4">
        <div className="sh-layout__main max-lg:contents">
          <Match finding={finding} rule={rule} />
          <Evidence finding={finding} events={events} explore={explore} />
        </div>
        <aside className="sh-layout__aside max-lg:order-1" aria-label="Rule, siblings and Sentinel">
          <Rail finding={finding} />
        </aside>
      </div>
    </div>
  );
}

/** The case's title for the strip chip's tip, from the shared case list when it holds the case. */
function CaseTitle({ uid }: { uid: string }) {
  const cases = useCaseLog();
  return <>{cases.data?.rows.find((c) => c.case_uid === uid)?.title ?? uid}</>;
}

/** Who touched what, a tick per kept event, and the events; the entity's events over the span are in Explore. */
function Evidence({ finding, events, explore }: { finding: FindingRow; events: OcsfEvent[]; explore: string }) {
  const openEntity = usePopParam("entity", ["view"]);
  // The event opens in `?event=`. A tick steps in time order, as the ticks run; the table steps in its own order.
  const [eventUid, popEvent] = usePopValue("event");
  const [order, setOrder] = useState<"time" | "table">("time");
  const chrono = [...events].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  const steps = order === "time" ? chrono : events;
  const at = steps.findIndex((e) => e.event_uid === eventUid);
  const graph = attackGraph(events, [finding]);
  const lanes = LAYERS.filter((l) => graph.nodes.some((n) => n.kind === l));
  const busiest = Math.max(1, ...lanes.map((l) => Math.min(10, graph.nodes.filter((n) => n.kind === l).length)));
  // The finding names one entity, or a group of them ("AKIA…|203.0.113.55"): each is ringed, the first focused.
  const named = new Set(finding.entity_key.split("|").map(bare));
  const ringed = graph.nodes.filter((n) => named.has(n.label));
  const severe = finding.severity === "critical" || finding.severity === "high" || finding.severity === "medium";
  const rings: Record<string, Ring> = severe ? Object.fromEntries(ringed.map((n) => [n.id, finding.severity as Ring])) : {};
  const first = Date.parse(finding.first_seen);
  const last = Math.max(first, Date.parse(finding.last_seen));
  const pad = Math.max(30_000, (last - first) * 0.05);
  const kept = finding.event_uids.length;
  // finding.get returns 20 events at most, one table page.
  const more = finding.event_count > kept && events.length <= 20;
  // One event the match card already lays out: the graph and Explore carry it, not a row saying it a third time.
  const once = events.length === 1 && finding.event_count === 1 && Boolean(finding.evidence?.sample) && graph.nodes.length > 1;

  return (
    <Card className="max-lg:order-2">
      <CardHeader
        title="Evidence"
        action={
          <Tip label="Events in Explore" kbd="E">
            <Link className="sh-link" to={explore}>
              Explore
            </Link>
          </Tip>
        }
      />
      {graph.nodes.length > 1 ? (
        // The edges' operation names collide with the nodes once a lane stacks, and a phone has no room
        // for them; the rows below carry them.
        <CardBody
          className={cn(
            "border-b border-line-1",
            busiest > 1
              ? String.raw`[&_.sh-graph\_\_edge-label]:hidden`
              : String.raw`max-sm:[&_.sh-graph\_\_edge-label]:hidden`,
          )}
        >
          <Graph
            layout="layered"
            nodes={graph.nodes}
            edges={graph.edges}
            lanes={lanes}
            laneLabel={(lane) => (lane === "key" ? graph.keyLane : LANE_LABELS[lane as keyof typeof LANE_LABELS])}
            focus={ringed[0]?.id}
            rings={rings}
            height={Math.max(120, 40 + busiest * 44)}
            onOpen={(node) => openEntity(node.id)}
            name={(node) => `${node.kind} ${node.label}, ${num(node.events)} events`}
            label="Who touched what in this finding's events"
          />
        </CardBody>
      ) : null}
      {/* One event, or one instant, has no spread for ticks to show. */}
      {events.length > 1 && last > first ? (
        <CardBody className="border-b border-line-1">
          <TimeBar
            from={new Date(first - pad).toISOString()}
            to={new Date(last + pad).toISOString()}
            marks={events.map((e) => ({
              key: e.event_uid,
              at: e.time,
              kind: "event" as const,
              label: `${e.api_operation ?? e.activity_name ?? "event"} · ${time(e.time)}`,
            }))}
            onPick={(mark) => {
              setOrder("time");
              popEvent(mark.key);
            }}
            label="Kept events over the finding's span"
          />
        </CardBody>
      ) : null}
      {/* The kept count is the one footer; the table's own "1–20 of 20" would say it twice. */}
      {once ? null : (
        <div className={more ? "[&_.sh-pager]:hidden" : undefined}>
          <EventTable
            rows={events}
            empty="No longer in the store"
            label="Kept events"
            size={20}
            onOpen={(row) => {
              setOrder("table");
              popEvent(String(row.event_uid));
            }}
            followed={eventUid}
          />
        </div>
      )}
      {more ? (
        <div className="sh-pager">
          <span className="sh-pager__range">
            <b>{num(kept)}</b> of {num(finding.event_count)} kept as evidence
          </span>
        </div>
      ) : null}
      {eventUid ? (
        <EventDialog
          event={steps[at]}
          uid={eventUid}
          onClose={() => popEvent(null)}
          step={
            at >= 0
              ? {
                  index: at,
                  total: steps.length,
                  onPrev: at > 0 ? () => popEvent(steps[at - 1]!.event_uid, true) : undefined,
                  onNext: at < steps.length - 1 ? () => popEvent(steps[at + 1]!.event_uid, true) : undefined,
                }
              : undefined
          }
        />
      ) : null}
    </Card>
  );
}
