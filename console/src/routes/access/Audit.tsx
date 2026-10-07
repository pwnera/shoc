/**
 * Access › Audit: the last 200 audited calls, hash-linked to the ones before.
 * A row is the caller, a bad mark when the call failed, the capability and
 * the caller's name, and when; seq and hash are in its dialog (`?seq=`). Filters (caller kind
 * or exact id, errors only, area) and the text (`?aq=`: capability, caller id,
 * error) narrow the loaded rows. A broken chain heads
 * the tab with the head hash and Verify now.
 *
 * Capabilities used: health.audit.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy } from "@/components/ui/field";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, Spinner } from "@/components/ui/misc";
import { Banner, Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { who } from "@/lib/crew";
import { useFilters, type Dim } from "@/lib/filters";
import { age, num, stamp } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, useOpen } from "@/lib/popup";
import { useAudit } from "@/lib/queries";
import type { AuditRow } from "@/types";
import { areaOf, PRINCIPALS } from "./parts";

const principal = (row: AuditRow) => `${row.principal_kind}:${row.principal_id}`;

/**
 * The rows, and the dialog a row opens; shared with the capability dialog's
 * Recent view. `param` keeps the open row in the URL (the tab's `?seq=`);
 * inside the capability dialog it is local.
 */
export function AuditTable({
  rows,
  loading,
  error,
  onRetry,
  empty,
  bounded,
  paged,
  param,
}: {
  rows: AuditRow[];
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  empty: React.ReactNode;
  bounded?: boolean;
  /** A pager over the loaded rows, and how many were loaded; the strip holds the chain's total. */
  paged?: { loaded: number };
  param?: string;
}) {
  const now = useNow();
  const [, setParams] = useSearchParams();
  const dialog = useOpen(param ?? null, rows.map((r) => String(r.seq)));
  // The loaded rows are the chain's newest: the footer says so in the pager's own words.
  const pages = usePaged(rows, 25, {
    newest: true,
    of: paged && rows.length !== paged.loaded ? `${num(rows.length)} · newest ${num(paged.loaded)}` : undefined,
  });
  const { page, start, prev, next } = pages;
  const list = paged ? page : rows;
  const nav = useListNav(list, (r) => String(r.seq), { onOpen: (r) => dialog.open(String(r.seq)), onPrevPage: prev, onNextPage: next });
  // J and K in the dialog turn the pager when they step past its page, and the active row follows.
  useFollow(nav, dialog.value, paged ? { keys: rows.map((r) => String(r.seq)), size: 25, go: pages.go } : undefined);
  const picked = rows[dialog.at];
  const columns: Column<AuditRow>[] = [
    { label: "", width: 32, truncate: false, cell: (r) => <Avatar who={principal(r)} size={16} /> },
    // Only a failure is marked: a column of green squares says nothing.
    { label: "", width: 20, truncate: false, cell: (r) => (r.error ? <Mark tone="bad" label="failed" /> : null) },
    {
      label: "",
      cell: (r) => (
        <>
          <span className="sh-mono sh-mono--strong">{r.capability}</span>
          <span className="sh-mono text-fg-4"> · {who(principal(r)).name}</span>
        </>
      ),
    },
    { label: "", width: 64, align: "right", mono: true, cell: (r) => age(r.ts, now) },
  ];
  return (
    <>
      <Table
        label="Audited calls"
        columns={columns}
        rows={list}
        start={paged ? start : 0}
        rowKey={(r) => String(r.seq)}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        empty={empty}
        bounded={bounded}
      />
      {paged ? pages.pager : null}
      {picked ? (
        <Dialog
          key={picked.seq}
          title={<span className="font-mono">{picked.capability}</span>}
          id={`#${picked.seq}`}
          step={dialog.step}
          onClose={dialog.close}
          footer={
            <Button
              variant="ghost"
              onClick={() =>
                setParams((current) => {
                  const out = new URLSearchParams(current);
                  out.set("cap", picked.capability);
                  return out;
                })
              }
            >
              Open capability
            </Button>
          }
        >
          <Fields
            ruled
            rows={[
              ["When", `${stamp(picked.ts)} · ${age(picked.ts, now)}`],
              [
                "Caller",
                <span className="inline-flex items-center gap-2">
                  <Avatar who={principal(picked)} size={16} tip={false} />
                  {who(principal(picked)).name}
                </span>,
              ],
              ["Error", picked.error ? <span className="sh-mono text-bad">{picked.error}</span> : null],
              ["Hash", <Copy value={picked.hash} label="Copy the hash" />],
            ]}
          />
        </Dialog>
      ) : null}
    </>
  );
}

function dims(rows: AuditRow[]): Dim<AuditRow>[] {
  const areas = [...new Set(rows.map((r) => areaOf(r.capability)))].sort();
  return [
    {
      id: "principal",
      label: "caller",
      options: PRINCIPALS.map((p) => ({
        value: p.id,
        label: p.label,
        count: rows.filter((r) => r.principal_kind === p.id).length,
      })),
      // A kind ("agent"), or one caller exactly ("agent:Investigator"), as the Crew tab links it.
      test: (r, v) =>
        v.includes(":") ? principal(r) === v || `${r.principal_kind}:${who(principal(r)).key}` === v : r.principal_kind === v,
    },
    {
      id: "errors",
      label: "outcome",
      options: [{ value: "yes", label: "failed", count: rows.filter((r) => r.error).length }],
      test: (r) => Boolean(r.error),
    },
    {
      id: "area",
      label: "area",
      options: areas.map((a) => ({ value: a, count: rows.filter((r) => areaOf(r.capability) === a).length })),
      test: (r, v) => areaOf(r.capability) === v,
    },
  ];
}

export function Audit() {
  const [head, setHead] = useState("");
  const audit = useAudit(head ? { limit: 200, head } : { limit: 200 });
  const rows = audit.data?.recent ?? [];
  // Its own text parameter: Registry, a tab away, keeps `q`.
  const filters = useFilters(dims(rows), {
    text: "aq",
    match: (r, text) => `${r.capability} ${r.principal_id} ${r.error ?? ""}`.toLowerCase().includes(text),
  });
  const kept = rows.filter(filters.keep);
  const broken = audit.data && !audit.data.chain_ok;
  return (
    <>
      {broken ? (
        <Banner
          tone="bad"
          action={
            <button
              type="button"
              className="sh-banner__action"
              disabled={audit.isFetching}
              onClick={() => (head ? void audit.refetch() : setHead(audit.data!.head))}
            >
              {audit.isFetching ? <Spinner /> : null}
              Verify now
            </button>
          }
        >
          Chain broken · <span className="font-mono">{audit.data!.head}</span>
        </Banner>
      ) : null}
      <FilterBar
        dims={dims(rows)}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter calls"
      />
      <AuditTable
        rows={kept}
        loading={audit.isPending}
        error={audit.isLoadingError ? audit.error : undefined}
        onRetry={() => void audit.refetch()}
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No call matches" onClear={filters.clear} />
          ) : (
            "No calls recorded"
          )
        }
        paged={{ loaded: rows.length }}
        param="seq"
      />
    </>
  );
}
