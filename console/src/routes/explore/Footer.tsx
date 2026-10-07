/**
 * The results footer: "1–50 of 200 loaded" ("1–26 of 26" once every match is
 * loaded; the match total is the strip's), the SQL the query became (a dialog
 * with copy), the loaded rows as NDJSON with their original records, and the
 * pages. Load more appears when the store says there is more; until the kernel
 * reports that (`truncated` is always false today), a full page reads "1–50
 * of first 100".
 */
import { useState } from "react";
import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Copy } from "@/components/ui/field";
import { Spinner } from "@/components/ui/misc";
import { callData } from "@/lib/api";
import { num } from "@/lib/format";
import { toastError } from "@/lib/toast";
import type { EventRow } from "@/types";

export function Footer({
  rows,
  start,
  shown,
  pages,
  page,
  onPage,
  limit,
  matched,
  truncated,
  onMore,
  sql,
}: {
  rows: EventRow[];
  start: number;
  shown: number;
  pages: number;
  page: number;
  onPage: (page: number) => void;
  limit: number;
  matched?: number;
  truncated: boolean;
  onMore: () => void;
  sql?: string;
}) {
  const [showSql, setShowSql] = useState(false);
  const [saving, setSaving] = useState(false);
  const capped = !truncated && rows.length >= limit && (matched ?? 0) > rows.length;
  return (
    <div className="sh-pager h-auto min-h-8 flex-wrap py-1">
      {/* A phone gives the range its own line and keeps the numbers only. */}
      <span className="sh-pager__range max-sm:basis-full">
        <b>
          {start + 1}–{start + shown}
        </b>{" "}
        of {capped ? `newest ${num(rows.length)}` : num(rows.length)}
        {!capped && matched !== undefined && matched !== rows.length ? " loaded" : null}
      </span>
      {truncated ? (
        <Button variant="ghost" size="sm" onClick={onMore}>
          Load more
        </Button>
      ) : null}
      {sql ? (
        <Button variant="ghost" size="sm" onClick={() => setShowSql(true)}>
          SQL
        </Button>
      ) : null}
      <Button
        variant="ghost"
        size="sm"
        disabled={saving || !rows.length}
        onClick={() => {
          setSaving(true);
          download(rows)
            .catch((error: unknown) => toastError(error, "Download failed"))
            .finally(() => setSaving(false));
        }}
      >
        {saving ? <Spinner /> : <Download aria-hidden />}
        NDJSON
      </Button>
      {pages > 1 ? (
        <>
          <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
            <ChevronLeft aria-hidden />
          </Button>
          <Button variant="ghost" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
            <ChevronRight aria-hidden />
          </Button>
        </>
      ) : null}
      {showSql && sql ? (
        <Dialog title="SQL" onClose={() => setShowSql(false)}>
          <Copy value={sql} block label="Copy SQL" />
        </Dialog>
      ) : null}
    </div>
  );
}

/** The loaded rows with every column and the original record, as the file every other tool reads. */
async function download(rows: EventRow[]) {
  const full = await callData<{ rows: EventRow[] }>("events.query", {
    event_uids: rows.map((row) => String(row.event_uid)),
    limit: rows.length,
    include_raw: true,
  });
  const blob = new Blob([full.rows.map((row) => JSON.stringify(row)).join("\n")], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `shoc-events-${new Date().toISOString().slice(0, 19)}.ndjson`;
  link.click();
  // Revoked once the download has started, not in the same tick.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
