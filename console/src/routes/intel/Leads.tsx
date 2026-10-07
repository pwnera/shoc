/**
 * Intel › Leads: values the Hunter thinks are worth sweeping this week
 * (`hunt.suggest`). A row is the severity of the finding behind it, the
 * priority, the value as an entity chip (its glyph says its kind: the field it
 * would search, when the kernel names one; `auto` is its default and says
 * nothing) and the title of the rule that found it. `hunt.suggest` gives no
 * time, so the row ends with none. The lead dialog (`?lead=`) links that rule,
 * with Sweep 90 days (`hunt.run`) and the entity it names. Value sweeps live
 * here, beside the indicators; Hunts stays behavioural. The text (`?lq=`)
 * matches the value, the reason and the rule's title; a chip keeps one field.
 *
 * Capabilities used: hunt.suggest (read by the page), hunt.run; rule.list names the rule.
 */
import type { ReactNode } from "react";
import { Search } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Quote } from "@/components/ui/field";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, Spinner } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { severityLabel } from "@/lib/labels";
import { usePaged } from "@/lib/paged";
import { useFollow, usePopParam } from "@/lib/popup";
import { useRules, useRunHunt } from "@/lib/queries";
import type { HuntSuggestion, Severity } from "@/types";
import { entityKey } from "./feeds";
import { Swept } from "./IndicatorDialog";

const keyOf = (lead: HuntSuggestion) => `${lead.field}:${lead.value}`;

/** The field in words; `auto` (the kernel picks) has none. */
const FIELD: Record<string, string> = { src_ip: "IP", actor: "user", domain: "domain" };
const fieldWord = (field: string) => (field === "auto" ? null : (FIELD[field] ?? field.replace(/_/g, " ")));

/** The Hunter's reason, "behind a high finding from <rule_id> this week", as the finding's severity and rule. */
const BEHIND = /behind an? (\w+) finding from (\S+)/;
const SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);

function behind(lead: HuntSuggestion): { severity: Severity; rule: string } | null {
  const m = BEHIND.exec(lead.reason);
  return m && SEVERITIES.has(m[1]!) ? { severity: m[1] as Severity, rule: m[2]! } : null;
}

function LeadDialog({
  lead,
  ruleTitle,
  onClose,
  step,
}: {
  lead: HuntSuggestion;
  ruleTitle: (id: string) => ReactNode;
  onClose: () => void;
  step: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const from = behind(lead);
  const openEntity = usePopParam("entity", ["view"]);
  const sweep = useRunHunt();
  const mine = sweep.variables?.value === lead.value;
  const entity = entityKey(lead.value, lead.field);
  const field = fieldWord(lead.field);
  return (
    <Dialog
      title={lead.value}
      onClose={onClose}
      step={step}
      head={
        <>
          <Badge>P{lead.priority}</Badge>
          {field ? <Badge tone="faint">{field}</Badge> : null}
        </>
      }
      footer={
        <>
          {entity ? (
            <Button
              variant="ghost"
              onClick={() => openEntity(entity)}
            >
              Open entity
            </Button>
          ) : null}
          <Button
            disabled={sweep.isPending}
            onClick={() => sweep.mutate({ value: lead.value, field: lead.field, days: 90 })}
          >
            {sweep.isPending && mine ? <Spinner /> : <Search aria-hidden />}
            Sweep 90 days
          </Button>
        </>
      }
    >
      {from ? (
        <Fields
          rows={[
            [
              "finding",
              <span className="inline-flex min-w-0 items-center gap-2">
                <SeverityBadge severity={from.severity} />
                <Tip label={from.rule} mono>
                  <Link to={`/detection/rules/${encodeURIComponent(from.rule)}`} className="sh-chip min-w-0">
                    <span className="sh-chip__value">{ruleTitle(from.rule)}</span>
                  </Link>
                </Tip>
              </span>,
            ],
          ]}
        />
      ) : (
        <Quote by="Hunter" crew>
          {lead.reason}
        </Quote>
      )}
      {mine ? <Swept sweep={sweep} value={lead.value} /> : null}
    </Dialog>
  );
}

export function Leads({
  leads,
  loading,
  error,
  onRetry,
}: {
  leads: HuntSuggestion[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const [params] = useSearchParams();
  const rules = useRules();
  const titles = new Map((rules.data?.rules ?? []).map((r) => [r.id, r.title]));
  // A rule's id shows only once rule.list failed; while it loads, the title's place holds.
  const ruleTitle = (id: string): ReactNode => titles.get(id) ?? (rules.isPending ? <Skel kind="text" width="8em" /> : id);
  const fields = [...new Set(leads.map((l) => l.field))].filter((f) => fieldWord(f)).sort();
  const dims: Dim<HuntSuggestion>[] = [
    {
      id: "field",
      label: "field",
      options: fields.map((f) => ({ value: f, label: fieldWord(f)!, count: leads.filter((l) => l.field === f).length })),
      test: (l, v) => l.field === v,
    },
  ];
  // Its own text parameter: Indicators, a tab away, keeps `q`.
  const filters = useFilters(dims, {
    text: "lq",
    match: (l, text) =>
      `${l.value} ${l.reason} ${titles.get(behind(l)?.rule ?? "") ?? ""}`.toLowerCase().includes(text),
  });
  const rows = leads.filter(filters.keep).sort((a, b) => a.priority - b.priority);
  const paged = usePaged(rows, 25);
  const pop = usePopParam("lead");
  const open = (lead: HuntSuggestion | undefined, replace = false) => pop(lead && keyOf(lead), replace);
  const nav = useListNav(paged.page, keyOf, {
    onOpen: (lead) => open(lead),
    copy: (lead) => lead.value,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // J and K in the dialog move the list's row too, so Escape lands on the lead stepped to.
  useFollow(nav, params.get("lead") ?? "");
  const at = rows.findIndex((lead) => keyOf(lead) === params.get("lead"));

  const columns: Column<HuntSuggestion>[] = [
    {
      label: "",
      fit: true,
      cell: (lead) => {
        const severity = behind(lead)?.severity;
        return (
          <span className="inline-flex items-center gap-2">
            {severity ? <Mark tone={severity} label={severityLabel(severity)} /> : <span className="inline-block w-1.5" aria-hidden />}
            <Badge>P{lead.priority}</Badge>
          </span>
        );
      },
    },
    {
      label: "",
      truncate: false,
      cell: (lead) => {
        const rule = behind(lead)?.rule;
        return (
          <span className="flex min-w-0 items-center gap-2">
            {/* Its kind from its pattern or the field it would search. */}
            <Entity value={entityKey(lead.value, lead.field) ?? lead.value} className="max-w-[55%] shrink-0" />
            {rule ? <span className="min-w-0 truncate text-fg-3">{ruleTitle(rule)}</span> : null}
          </span>
        );
      },
    },
  ];

  return (
    <>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter leads"
      />
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={keyOf}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Leads"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No lead matches" onClear={filters.clear} />
          ) : (
            "No leads this week"
          )
        }
      />
      {paged.pager}
      {at >= 0 ? (
        <LeadDialog
          lead={rows[at]!}
          ruleTitle={ruleTitle}
          onClose={() => open(undefined, true)}
          step={{
            index: at,
            total: rows.length,
            onPrev: at > 0 ? () => open(rows[at - 1], true) : undefined,
            onNext: at < rows.length - 1 ? () => open(rows[at + 1], true) : undefined,
          }}
        />
      ) : null}
    </>
  );
}
