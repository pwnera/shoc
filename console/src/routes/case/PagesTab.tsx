/**
 * The pages sent to the on-call person about this case: who sent it, what
 * became of it in a page's words (delivered, planned on a dry run, not sent,
 * withdrawn), when. A burst of pages in one state from
 * one sender is one row with ×N, as the timeline folds a burst, and opens the
 * newest. The message is the record's, so it shows in ActionDialog, never here.
 *
 * Capabilities used: none of its own (`action.list {case_uid}`, read by the page).
 */
import { Avatar } from "@/components/ui/avatar";
import { Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { age, count, num } from "@/lib/format";
import { who } from "@/lib/crew";
import { pageState } from "@/lib/labels";
import { conditionWords } from "@/lib/policy";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import type { Action } from "@/types";
import type { Open } from "./moments";

type Burst = { key: string; pages: Action[]; word: string };

/** Neighbouring pages (newest first) in one state from one sender, as one row. */
function bursts(rows: Action[]): Burst[] {
  const kind = (a: Action) => `${a.state}|${pageState(a).word}|${a.requested_by}`;
  const out: Burst[] = [];
  for (const a of rows) {
    const last = out.at(-1);
    if (last && kind(last.pages[0]!) === kind(a)) last.pages.push(a);
    else out.push({ key: a.action_uid, pages: [a], word: pageState(a).word });
  }
  return out;
}

export function PagesTab({
  rows,
  loading,
  error,
  onRetry,
  open,
}: {
  rows: Action[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  open: Open;
}) {
  const now = useNow();
  const why = (page: Action) => conditionWords(page.rationale ?? "")?.join(" · ") || page.target || who(page.requested_by).name;
  const list = bursts(rows);
  const paged = usePaged(list, 25, {
    of: list.length === rows.length ? undefined : `${count(list.length, "group")} · ${count(rows.length, "page")}`,
  });
  const nav = useListNav(paged.page, (b) => b.key, {
    onOpen: (b) => open.action(b.pages[0]!, list.map((x) => x.pages[0]!)),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const columns: Column<Burst>[] = [
    { label: "", width: 28, truncate: false, cell: (b) => <Avatar who={b.pages[0]!.requested_by} size={16} tip={false} /> },
    {
      label: "",
      fit: true,
      cell: (b) => {
        const { word, tone } = pageState(b.pages[0]!);
        return (
          <Status tone={tone} badge>
            {word}
          </Status>
        );
      },
    },
    // Why it went out names the row (the avatar is who paged); the time ends its one free cell, as on every object list.
    {
      label: "",
      truncate: false,
      cell: (b) => (
        <span className="flex min-w-0 items-center gap-3">
          <span className="flex min-w-0 flex-1 items-baseline gap-2">
            <span className="sh-cell min-w-0">{why(b.pages[0]!)}</span>
            {b.pages.length > 1 ? <span className="sh-tl__count shrink-0">×{num(b.pages.length)}</span> : null}
          </span>
          <span className="shrink-0 font-mono text-xs text-fg-3 tabular">{age(b.pages[0]!.created_at, now)}</span>
        </span>
      ),
    },
  ];
  return (
    <>
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(b) => b.key}
        rowProps={nav.rowProps}
        loading={loading}
        error={error ?? undefined}
        onRetry={onRetry}
        empty="Nobody was paged"
        label="Pages"
      />
      {paged.pager}
    </>
  );
}
