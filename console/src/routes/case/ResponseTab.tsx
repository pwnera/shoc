/**
 * What was done on the case, neither proposals (they wait in the decision bar)
 * nor pages (their own tab): the platform and who asked as glyphs, one state
 * badge (a dry run reads "planned"), the action and its target (the target
 * gives way first, and under 640px it is left to ActionDialog), when it last
 * changed. A row opens ActionDialog, where Undo lives. New action (P) opens
 * the propose dialog.
 *
 * Capabilities used: none of its own (`action.list {case_uid}`, read by the page).
 */
import { useSearchParams } from "react-router-dom";
import { Plus } from "lucide-react";
import { Avatar } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { CardToolbar } from "@/components/ui/card";
import { Entity } from "@/components/ui/entity";
import { ProductLogo } from "@/components/ui/logo";
import { Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { parseEntity } from "@/lib/entity";
import { age } from "@/lib/format";
import { actionLabel, actionState } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow } from "@/lib/popup";
import { useSort } from "@/lib/sort";
import type { Action } from "@/types";
import type { Open } from "./moments";

/** A state badge in status tones; "waits" is never drawn here, so crew never shows. */
export function ActionStatus({ action, word }: { action: Action; word?: string }) {
  const state = actionState(action);
  return (
    <Status tone={state.tone} badge>
      {word ?? state.word}
    </Status>
  );
}

export function ResponseTab({
  rows: given,
  loading,
  error,
  onRetry,
  fresh,
  closed,
  open,
}: {
  rows: Action[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  /** The action just proposed, which flashes once. */
  fresh: string | null;
  closed: boolean;
  open: Open;
}) {
  const now = useNow();
  const columns: Column<Action>[] = [
    {
      label: "Platform",
      width: 48,
      truncate: false,
      sort: (a) => a.type.split(".")[0],
      cell: (a) => {
        return (
          <span className="flex items-center gap-1.5">
            <ProductLogo product={a.type.split(".")[0]} size={16} named />
            <Avatar who={a.requested_by} size={16} />
          </span>
        );
      },
    },
    { label: "State", fit: true, sort: (a) => actionState(a).word, cell: (a) => <ActionStatus action={a} /> },
    {
      label: "Action",
      strong: true,
      truncate: false,
      sort: (a) => actionLabel(a.type),
      cell: (a) => (
        <span className="flex min-w-0 items-center gap-2">
          <span className="max-w-full shrink-0 truncate">{actionLabel(a.type)}</span>
          {parseEntity(a.target) ? (
            <Entity value={a.target} className="max-sm:hidden" />
          ) : (
            <span className="sh-mono truncate text-fg-3 max-sm:hidden">{a.target}</span>
          )}
        </span>
      ),
    },
    {
      label: "When",
      width: 72,
      align: "right",
      mono: true,
      sort: (a) => a.updated_at ?? a.created_at,
      cell: (a) => age(a.updated_at ?? a.created_at, now),
    },
  ];
  const sorted = useSort(given, columns);
  const rows = sorted.rows;
  const paged = usePaged(rows, 25);
  const nav = useListNav(paged.page, (a) => a.action_uid, {
    onOpen: (a) => open.action(a, rows),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // The action dialog's J and K turn the page and move the active row with them.
  const [params] = useSearchParams();
  useFollow(nav, params.get("action") ?? "", { keys: rows.map((a) => a.action_uid), size: 25, go: paged.go });

  return (
    <>
      {closed ? null : (
        <CardToolbar>
          <Tip label="New action" kbd="P">
            <Button size="sm" className="ml-auto" onClick={() => open.propose()} aria-keyshortcuts="P">
              <Plus aria-hidden />
              New action
            </Button>
          </Tip>
        </CardToolbar>
      )}
      <Table
        columns={columns}
        rows={paged.page}
        sort={sorted.sort}
        onSort={paged.first}
        rowKey={(a) => a.action_uid}
        rowProps={nav.rowProps}
        isNew={(a) => a.action_uid === fresh}
        loading={loading}
        error={error ?? undefined}
        onRetry={onRetry}
        empty="Nothing ran"
        label="Response"
      />
      {paged.pager}
    </>
  );
}
