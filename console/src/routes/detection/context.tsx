/**
 * An item's context as rows of its dialog's fields (D133): what the report
 * said the attacker did, the kinds of logs that would show it (each with the
 * products we receive it from, or none), the sources to connect for the rest,
 * the rules and packs on the same techniques, and on their siblings when they
 * read a product we receive (one that reads nothing we receive is dashed, and
 * says so in its tip), the cases that named them, and the other reports that
 * did. An item no report raised quotes another report's words beside a link
 * to it, and says nothing of why it matters. The detection and hunt backlog
 * dialogs share it.
 */
import type { ReactNode } from "react";
import { productName } from "@/components/brands";
import { Clamped } from "@/components/ui/clamped";
import { Chip } from "@/components/ui/filterbar";
import { Tip } from "@/components/ui/tip";
import { attackUrl } from "@/lib/attack";
import { truncate } from "@/lib/format";
import type { ItemContext } from "@/types";
import { LinkChip } from "./parts";

type Row = [string, ReactNode];

const CONNECT = 4;
const TECHNIQUES = 6;

const chips = (nodes: ReactNode[]) => (nodes.length ? <span className="flex flex-wrap gap-1">{nodes}</span> : null);

const reportHref = (uid: string) => `/intel?tab=reports&report=${encodeURIComponent(uid)}`;

/** The report that raised the item; none when no report did. */
const raisedBy = (context: ItemContext, reportUid: string) =>
  reportUid ? context.reports.find((r) => r.report_uid === reportUid) : undefined;

const procedures = (said: ItemContext["reports"][number]["said"]) => said.map((s) => s.procedure).join(" ");

/** What the raising report said the attacker did; another report's, with a link to it, when it said nothing. */
export function saidIn(context: ItemContext | undefined, reportUid = ""): ReactNode {
  if (!context) return null;
  const raised = raisedBy(context, reportUid);
  if (raised?.said.length) return procedures(raised.said);
  const other = context.reports.find((r) => r.said.length);
  if (!other) return null;
  return (
    <span className="flex flex-col items-start gap-1">
      {procedures(other.said)}
      <LinkChip to={reportHref(other.report_uid)} label="Report" value={other.title} />
    </span>
  );
}

/** The techniques by name, each to its ATT&CK page; the first six. */
export function techniqueChips(ids: string[], context: ItemContext | undefined) {
  const names = new Map((context?.techniques ?? []).map((t) => [t.id, t.name]));
  return chips(
    ids.slice(0, TECHNIQUES).map((id) => {
      const name = names.get(id);
      return <LinkChip key={id} external to={attackUrl(id)} label={name ? id : "ATT&CK"} value={name || id} />;
    }),
  );
}

export function contextRows(
  context: ItemContext | undefined,
  {
    reportUid = "",
    said = true,
    relevance = false,
  }: {
    reportUid?: string;
    said?: boolean;
    /** Why the raising report matters here; a string is the item's own words for when the report gives none. */
    relevance?: boolean | string;
  } = {},
): Row[] {
  if (!context) return [];
  const raised = raisedBy(context, reportUid);
  const why = relevance ? raised?.relevance || (typeof relevance === "string" ? relevance : "") : "";
  const unseen = context.seen_in.filter((s) => !s.received.length);
  const connect = [...new Map(unseen.flatMap((s) => s.products).map((p) => [p.source, p])).values()].slice(0, CONNECT);
  return [
    ["in the report", said ? saidIn(context, reportUid) : null],
    ["why it matters", why ? <Clamped text={why} /> : null],
    [
      "shows in",
      chips(
        context.seen_in.map((s) => (
          <Chip
            key={s.kind}
            label={s.label}
            value={s.received.length ? s.received.map(productName).join(", ") : "not received"}
            dashed={!s.received.length}
          />
        )),
      ),
    ],
    [
      "connect",
      chips(
        connect.map((p) => (
          <LinkChip key={p.source} to={`/connections?add=${encodeURIComponent(p.source)}`} value={productName(p.product)} />
        )),
      ),
    ],
    [
      "rules",
      chips(
        context.rules.map((r) => (
          <Tip key={r.id} label={r.live ? r.id : `${r.id} · reads nothing we receive`} mono={r.live}>
            <span className="inline-flex min-w-0">
              <LinkChip to={`/detection/rules/${encodeURIComponent(r.id)}`} value={r.title} dashed={!r.live} />
            </span>
          </Tip>
        )),
      ),
    ],
    [
      "packs",
      chips(
        context.packs.map((p) =>
          p.live ? (
            <LinkChip key={p.id} to={`/hunts?pack=${encodeURIComponent(p.id)}`} value={p.title} />
          ) : (
            <Tip key={p.id} label="reads nothing we receive">
              <span className="inline-flex min-w-0">
                <LinkChip to={`/hunts?pack=${encodeURIComponent(p.id)}`} value={p.title} dashed />
              </span>
            </Tip>
          ),
        ),
      ),
    ],
    [
      "cases",
      chips(context.cases.map((c) => <LinkChip key={c.case_uid} to={`/cases/${c.case_uid}`} value={truncate(c.title, 48)} />)),
    ],
    [
      "also in",
      chips(
        context.reports
          .filter((r) => r !== raised)
          .map((r) => (
            <LinkChip key={r.report_uid} to={reportHref(r.report_uid)} value={r.title} />
          )),
      ),
    ],
  ];
}
