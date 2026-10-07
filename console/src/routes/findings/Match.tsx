/**
 * What fired, as data. A rule match shows the matched row's fields, an
 * aggregate its group and threshold, an indicator hit the indicator and the
 * users it touched, a hunt the values it surfaced (its tuple, or the
 * observations an older hunt wrote as "field=value, …") and the hunter's
 * verdict word, never its triage prose. A finding intake set aside shows the
 * source and the credential, never the kernel's sentence; its status is the
 * header's. Each value pivots into Explore over the finding's window, an hour
 * either side. With nothing kept, there is no card.
 */
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Fields, type Pivot } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Copy } from "@/components/ui/field";
import { Chip } from "@/components/ui/filterbar";
import { ProductLogo } from "@/components/ui/logo";
import { Cites } from "@/components/Citations";
import { around, exploreHref, fieldPath, fieldWord, term } from "@/lib/explore";
import { intelSourceLabel } from "@/lib/labels";
import { sourceName } from "@/lib/sources";
import type { Finding, Rule } from "@/types";
import type { ReactNode } from "react";
import { observed } from "./group";

type Row = [string, ReactNode, Pivot | undefined];

/** The field behind a matched column, as Explore names it: a source path when the rule names one, else the OCSF path. */
function fieldOf(column: string, rule: Rule | undefined): string {
  const alias = (path: string) => path.replace(/[^A-Za-z0-9_]/g, "_").toLowerCase();
  return rule?.fields?.find((f) => /^(raw|unmapped)\./.test(f) && alias(f) === column) ?? fieldPath(column);
}

const shown = (value: unknown) =>
  value !== null && value !== undefined && value !== "" ? (typeof value === "string" ? value : JSON.stringify(value)) : "";

/** "use: a token shoc requested with its google_workspace credential 1081…": the source and the credential. */
const OWN = /(?:with its|the) (\S+) credential (\S+)/;

/** Where the set-aside sentence names them, the source and the credential. */
function ownOf(finding: Finding): { source?: string; credential?: string } {
  const own = finding.evidence?.own as { why?: string } | undefined;
  const intake = finding.evidence?.intake as { because?: string } | undefined;
  const [, source, credential] = OWN.exec(own?.why ?? intake?.because ?? "") ?? [];
  return { source, credential };
}

/** "SUSPICIOUS: The logs show…": the hunter's verdict word, lower case. */
const verdictOf = (triage: unknown) => /^([A-Z][A-Z_ ]+):/.exec(String(triage ?? ""))?.[1]?.toLowerCase();

export function Match({ finding, rule }: { finding: Finding; rule?: Rule }) {
  const navigate = useNavigate();
  const ev = finding.evidence ?? {};
  const range = around(finding.first_seen, finding.last_seen);
  const pivot = (field: string, value: string): Pivot => ({
    in: () => navigate(exploreHref({ q: term(field, value), ...range })),
    out: () => navigate(exploreHref({ q: term(field, value, "!="), ...range })),
    copy: value,
  });
  const value = (text: string) => <span className="sh-mono sh-mono--strong">{text}</span>;
  const aside = finding.status === "self" || finding.status === "suppressed";
  // The credential is the set-aside chip; a matched column holding it again is left out.
  const credential = aside ? ownOf(finding).credential : undefined;
  const pairs = (record: Record<string, unknown>, skip: string[] = []): Row[] =>
    Object.entries(record).flatMap(([column, raw]): Row[] => {
      const text = shown(raw);
      if (!text || skip.includes(column) || text === credential) return [];
      const field = fieldOf(column, rule);
      return [[fieldWord(field), value(text), pivot(field, text)]];
    });

  const rows: Row[] = [];
  const kind = String(ev.kind ?? "");
  if (ev.sample && typeof ev.sample === "object") rows.push(...pairs(ev.sample as Record<string, unknown>, ["time", "event_uid"]));
  if (kind === "aggregate" && ev.group && typeof ev.group === "object") {
    rows.push(...pairs(ev.group as Record<string, unknown>));
    if (ev.threshold) rows.push(["threshold", value(`${String(ev.threshold)} · ${finding.event_count}`), undefined]);
    if (ev.distinct) rows.push(["distinct", value(String(ev.distinct)), undefined]);
  }
  const indicator = ev.indicator as { type?: string; value?: string; source?: string } | undefined;
  if (indicator?.value) {
    rows.push([
      "indicator",
      <span className="inline-flex min-w-0 items-center gap-2">
        {indicator.type ? <Badge>{indicator.type}</Badge> : null}
        <Entity value={indicator.value} button />
      </span>,
      undefined,
    ]);
    if (indicator.source) rows.push(["feed", value(intelSourceLabel(indicator.source)), undefined]);
  }
  const users = Array.isArray(ev.users) ? (ev.users as string[]) : [];
  if (users.length)
    rows.push([
      "users",
      <span className="flex flex-wrap gap-1">
        {users.map((u) => (
          <Entity key={u} value={`user:${u}`} button />
        ))}
      </span>,
      undefined,
    ]);
  if (kind === "hunt" && ev.tuple && typeof ev.tuple === "object" && !Array.isArray(ev.tuple))
    rows.push(...pairs(ev.tuple as Record<string, unknown>));
  if (kind === "hunt")
    for (const [field, text] of observed(ev.observations)) rows.push([fieldWord(field), value(text), pivot(field, text)]);
  const verdict = kind === "hunt" ? verdictOf(ev.triage) : undefined;

  const set = aside ? setAside(finding) : null;
  if (!rows.length && !set && !verdict) return null;
  return (
    <Card>
      <CardHeader title="Match" />
      <CardBody className="flex flex-col gap-3">
        {set}
        {verdict ? <Chip label="triage" value={verdict} className="self-start" /> : null}
        {rows.length ? (
          // A known path reads as its word, any other as the path Explore takes, so labels keep their case; on a phone each sits over its value.
          <div className="[&_dt]:normal-case [&_dt]:tracking-normal max-sm:[&_.sh-fields]:grid-cols-1 max-sm:[&_dt]:border-0">
            <Fields rows={rows} ruled />
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

/** Set aside by intake: shoc's own credential at work, or a suppression; null when the evidence names neither. */
function setAside(finding: Finding): ReactNode {
  const own = finding.evidence?.own as { citations?: string[] } | undefined;
  const { source, credential } = ownOf(finding);
  if (!source && !credential && !own?.citations?.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {source ? (
        <span className="sh-chip">
          <ProductLogo product={source} />
          <span className="sh-chip__value">{sourceName(source)}</span>
        </span>
      ) : null}
      {credential ? <Copy value={credential} label="Copy credential id" /> : null}
      {own?.citations?.length ? <Cites uids={own.citations} /> : null}
    </div>
  );
}
