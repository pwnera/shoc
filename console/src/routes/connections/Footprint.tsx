/**
 * Connections › shoc's own: what shoc reads as its own or its people's activity
 * rather than a stranger's (RFC 0021): its credentials and addresses, the
 * operator, the company's automation. Findings call the same records "shoc's
 * own". A row opens its dialog, where Remove confirms; Add is L2, so its
 * confirm says "you".
 *
 * Capabilities used: own.list, own.add, own.remove.
 */
import { useState, type ReactNode } from "react";
import { Bot, Globe, KeyRound, Plus, User, type LucideIcon } from "lucide-react";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, Input } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { AutonomyBadge } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { who } from "@/lib/crew";
import { useFilters, type Dim } from "@/lib/filters";
import { age, stamp } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, useOpen, type Step } from "@/lib/popup";
import { useAddOwn, useOwn, useRemoveOwn } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import type { OwnIdentity } from "@/types";
import { Logo } from "./parts";

type Kind = OwnIdentity["kind"];
const KINDS: Record<Kind, { icon: LucideIcon; word: string }> = {
  credential: { icon: KeyRound, word: "credential" },
  address: { icon: Globe, word: "address" },
  operator: { icon: User, word: "operator" },
  automation: { icon: Bot, word: "automation" },
};
const keyOf = (row: OwnIdentity) => `${row.kind}:${row.value}`;
const upper = (word: string) => word.charAt(0).toUpperCase() + word.slice(1);
/* The note the worker writes on a credential it reads with says no more than the kind and the source. */
const kernelNote = (row: OwnIdentity) => row.note === `the credential ${row.source} is read with`;

/**
 * The rows, paged; `source` narrows them to one source (the source dialog's
 * view). The tab keeps its open row in `?own=` and has a filter bar (`?oq=`:
 * value, source, note; a kind chip) holding `toolbar`; inside the source
 * dialog the open row is the dialog's own state and there is no bar.
 */
export function FootprintTable({
  source,
  bounded,
  toolbar,
}: {
  source?: string;
  bounded?: boolean | number;
  toolbar?: ReactNode;
}) {
  const own = useOwn();
  const now = useNow();
  const all = (own.data?.rows ?? []).filter((row) => !source || row.source === source);
  const dims: Dim<OwnIdentity>[] = [
    {
      id: "kind",
      label: "kind",
      options: (Object.keys(KINDS) as Kind[])
        .map((k) => ({ value: k, label: KINDS[k].word, count: all.filter((row) => row.kind === k).length }))
        .filter((o) => o.count),
      test: (row, v) => row.kind === v,
    },
  ];
  const filters = useFilters(source ? [] : dims, {
    text: "oq",
    match: (row, text) => `${row.value} ${sourceName(row.source)} ${row.note}`.toLowerCase().includes(text),
  });
  const rows = source ? all : all.filter(filters.keep);
  const dialog = useOpen(source ? null : "own", rows.map(keyOf));
  const { page, pager, start, prev, next } = usePaged(rows);
  const nav = useListNav(page, keyOf, { onOpen: (row) => dialog.open(keyOf(row)), onPrevPage: prev, onNextPage: next });
  useFollow(nav, dialog.value);
  const picked = rows[dialog.at];

  const columns: Column<OwnIdentity>[] = [
    {
      label: "",
      width: 52,
      truncate: false,
      cell: (row) => {
        const Icon = KINDS[row.kind]?.icon ?? KeyRound;
        return (
          <span className="flex items-center gap-1.5 text-fg-3">
            <Icon className="h-3.5 w-3.5" aria-hidden />
            {row.source ? <Logo name={row.source} /> : null}
          </span>
        );
      },
    },
    { label: "", fit: true, cell: (row) => <Badge tone="muted">{KINDS[row.kind]?.word ?? row.kind}</Badge> },
    { label: "", mono: true, strong: true, cell: (row) => row.value },
    { label: "", width: 72, align: "right", mono: true, hide: "md", cell: (row) => age(row.created_at, now) },
  ];

  return (
    <>
      {source ? null : (
        <FilterBar
          dims={dims}
          value={filters.values}
          onChange={filters.set}
          text={filters.text}
          onText={filters.setText}
          onClear={filters.clear}
          placeholder="Filter identities"
        >
          {toolbar}
        </FilterBar>
      )}
      <Table
        label={source ? `${sourceName(source)}: shoc's own` : "shoc's own"}
        columns={columns}
        rows={page}
        start={start}
        rowKey={keyOf}
        rowProps={nav.rowProps}
        loading={own.isPending}
        error={own.isLoadingError ? own.error : undefined}
        onRetry={() => void own.refetch()}
        empty={
          filters.active && !source ? (
            <Empty kind="filtered" title="No identity matches" onClear={filters.clear} />
          ) : (
            "Nothing recorded"
          )
        }
        bounded={bounded}
      />
      {pager}
      {picked ? <OwnDialog key={keyOf(picked)} row={picked} step={dialog.step} onClose={dialog.close} /> : null}
    </>
  );
}

/** The tab: an Add control in the table's filter bar. */
export function Footprint() {
  const [adding, setAdding] = useState(false);
  return (
    <>
      <FootprintTable
        toolbar={
          <Button size="sm" onClick={() => setAdding(true)}>
            <Plus aria-hidden />
            Add identity
          </Button>
        }
      />
      {adding ? <AddOwnDialog onClose={() => setAdding(false)} /> : null}
    </>
  );
}

function OwnDialog({ row, step, onClose }: { row: OwnIdentity; step: Step; onClose: () => void }) {
  const remove = useRemoveOwn();
  const [asking, setAsking] = useState(false);
  const by = who(row.created_by);
  return (
    <Dialog
      title={upper(KINDS[row.kind]?.word ?? row.kind)}
      id={row.value}
      size="sm"
      step={step}
      onClose={onClose}
      footer={
        asking ? null : (
          <Button variant="danger" onClick={() => setAsking(true)}>
            Remove
          </Button>
        )
      }
    >
      <Fields
        rows={[
          [
            "Source",
            row.source ? (
              <span className="inline-flex items-center gap-2">
                <Logo name={row.source} />
                {sourceName(row.source)}
              </span>
            ) : null,
          ],
          ["Scope", row.scope ? <span className="sh-mono break-all">{row.scope}</span> : null],
          ["Note", kernelNote(row) ? null : row.note],
          [
            "By",
            row.created_by ? (
              <span className="inline-flex items-center gap-2">
                <Avatar who={by} size={16} tip={false} />
                {by.name}
              </span>
            ) : null,
          ],
          ["Added", stamp(row.created_at)],
        ]}
      />
      {asking ? (
        <Confirm
          inline
          what={`Remove ${KINDS[row.kind]?.word ?? row.kind} · ${row.value}`}
          go="Remove"
          danger
          onConfirm={() => remove.mutateAsync({ kind: row.kind, value: row.value }).then(onClose)}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}

function AddOwnDialog({ onClose }: { onClose: () => void }) {
  const add = useAddOwn();
  const [kind, setKind] = useState<Kind>("operator");
  const [value, setValue] = useState("");
  const [source, setSource] = useState("");
  const [scope, setScope] = useState("");
  const [note, setNote] = useState("");
  const [asking, setAsking] = useState(false);
  const input = { kind, value: value.trim(), source: source.trim(), scope: scope.trim(), note: note.trim() };

  return (
    <Dialog
      title="Add to shoc's own"
      size="sm"
      onClose={onClose}
      footer={
        asking ? null : (
          <Button variant="primary" disabled={!input.value} onClick={() => setAsking(true)}>
            Add
          </Button>
        )
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (input.value) setAsking(true);
        }}
      >
        <Seg
          label="Kind"
          value={kind}
          onChange={setKind}
          options={(Object.keys(KINDS) as Kind[]).map((k) => ({ value: k, label: KINDS[k].word }))}
        />
        <Field label="Value">
          <Input mono data-autofocus value={value} onChange={(event) => setValue(event.target.value)} spellCheck={false} />
        </Field>
        <Field label="Source">
          <Input mono value={source} onChange={(event) => setSource(event.target.value)} spellCheck={false} />
        </Field>
        <Field label="Scope">
          <Input mono value={scope} onChange={(event) => setScope(event.target.value)} spellCheck={false} />
        </Field>
        <Field label="Note">
          <Input value={note} onChange={(event) => setNote(event.target.value)} />
        </Field>
      </form>
      {asking ? (
        <Confirm
          inline
          what={`Add ${KINDS[kind].word} · ${input.value}`}
          facts={<AutonomyBadge level="L2" />}
          go="Add"
          onConfirm={() => add.mutateAsync(input).then(onClose)}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}
