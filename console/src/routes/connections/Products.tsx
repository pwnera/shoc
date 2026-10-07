/**
 * Connections › Products: one row per product (logo, how its logs deliver,
 * whether shoc can act on it, its name, when it last delivered) and a ⋯ menu
 * outside the row's click target with each of its sources' and credentials'
 * own acts. Pulls run per source, so one never disables another; P pulls the
 * active row's source. A row opens the product dialog.
 *
 * Capabilities used: source.sync, source.configure (pause, resume),
 * source.remove, credential.remove.
 */
import { useState } from "react";
import { MoreHorizontal, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CardToolbar } from "@/components/ui/card";
import { ProductLogo } from "@/components/ui/logo";
import { Meter } from "@/components/ui/meter";
import { Empty, Spinner } from "@/components/ui/misc";
import { Menu, type MenuEntry } from "@/components/ui/pop";
import { Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { credentialName } from "@/lib/credentials";
import { age } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow } from "@/lib/popup";
import { useRemoveCredential, useRemoveSource, useSyncSource, useToggleSource } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import { toastError } from "@/lib/toast";
import type { ConfiguredSource } from "@/types";
import { productLogo, productName, RESPONSE_TONE, responseState, type Product } from "./products";
import { deliveryTone, useSourceState, worstDelivery } from "./state";

export function Products({
  rows,
  current,
  filtered,
  loading,
  error,
  onRetry,
  onOpen,
  onAdd,
  onClear,
}: {
  rows: Product[];
  /** The product whose dialog is open: the active row follows it. */
  current: string;
  /** A filter from the strip is on. */
  filtered: boolean;
  loading: boolean;
  error?: Error;
  onRetry: () => void;
  onOpen: (key: string, view?: string, source?: string) => void;
  onAdd: () => void;
  onClear: () => void;
}) {
  const model = useSourceState();
  const now = useNow();
  const sync = useSyncSource();
  const toggle = useToggleSource();
  const remove = useRemoveSource();
  const disconnect = useRemoveCredential();
  const [pulling, setPulling] = useState<ReadonlySet<string>>(new Set());
  const { page, pager, start, prev, next } = usePaged(rows);
  const nav = useListNav(page, (row) => row.key, {
    onOpen: (row) => onOpen(row.key),
    onPrevPage: prev,
    onNextPage: next,
  });
  useFollow(nav, current);

  const pull = (source: string) => {
    if (pulling.has(source)) return;
    setPulling((s) => new Set(s).add(source));
    sync
      .mutateAsync(source)
      .catch((error: unknown) => toastError(error, `Pull ${sourceName(source)}`))
      .finally(() =>
        setPulling((s) => {
          const out = new Set(s);
          out.delete(source);
          return out;
        }),
      );
  };
  const polled = (row: Product) => row.sources.find((s) => model.mode(s) === "poll");
  const active = page.find((row) => row.key === nav.activeKey);
  const activePolled = active && polled(active);
  useCommand("source.pull", () => activePolled && pull(activePolled.source), Boolean(activePolled));

  const logs = (row: Product) => worstDelivery(row.sources.map(model.state));

  /** One source's own acts; with several sources each item names its source. */
  const sourceItems = (row: Product, s: ConfiguredSource): MenuEntry[] => {
    const named = (label: string) => (row.sources.length > 1 ? `${label} · ${sourceName(s.source)}` : label);
    return [
      ...(model.mode(s) === "poll" ? [{ label: named("Pull now"), kbd: keyLabel("p"), onSelect: () => pull(s.source) }] : []),
      s.enabled
        ? {
            label: named("Pause"),
            onSelect: () =>
              toggle.mutateAsync({ source: s.source, enabled: false, interval_seconds: s.interval_seconds, settings: s.settings }),
            confirm: {
              what: `Pause ${sourceName(s.source)}`,
              // The worker stops polling; the ingest endpoint still takes what a sender pushes.
              facts: <span className="sh-badge">{model.mode(s) === "poll" ? "no pulls until resumed" : "pushes still land"}</span>,
              go: "Pause",
            },
          }
        : {
            label: named("Resume"),
            onSelect: () =>
              void toggle
                .mutateAsync({ source: s.source, enabled: true, interval_seconds: s.interval_seconds, settings: s.settings })
                .catch((error: unknown) => toastError(error, `Resume ${sourceName(s.source)}`)),
          },
    ];
  };
  const items = (row: Product): MenuEntry[] => [
    ...row.sources.flatMap((s) => sourceItems(row, s)),
    { label: "Configure", onSelect: () => onOpen(row.key, row.sources.length ? "settings" : "credential") },
    { sep: true },
    ...row.sources.map(
      (s): MenuEntry => ({
        label: row.sources.length > 1 || row.credentials.length ? `Remove ${sourceName(s.source)}` : "Remove",
        danger: true,
        onSelect: () => remove.mutateAsync(s.source),
        confirm: {
          what: `Remove ${sourceName(s.source)}`,
          facts: <span className="sh-badge">its events stay</span>,
          typed: s.source,
          go: "Remove",
          danger: true,
        },
      }),
    ),
    ...row.credentials.map(
      (c): MenuEntry => ({
        label: `Disconnect ${credentialName(c.name)}`,
        danger: true,
        onSelect: () => disconnect.mutateAsync(c.name),
        confirm: {
          what: `Disconnect ${credentialName(c.name)}`,
          facts: <span className="sh-badge">shoc stops acting with it</span>,
          typed: c.name,
          go: "Disconnect",
          danger: true,
        },
      }),
    ),
  ];

  // When it last delivered, and for one polled source how far into its interval it is.
  const last = (row: Product) =>
    row.sources.reduce<string | null>((newest, s) => (s.last_ok_at && (!newest || s.last_ok_at > newest) ? s.last_ok_at : newest), null);
  const time: Column<Product> = {
    label: "",
    width: 104,
    hide: "md",
    align: "right",
    truncate: false,
    cell: (row) => {
      const one = row.sources.length === 1 ? row.sources[0]! : undefined;
      return (
        <span className="inline-flex items-center justify-end gap-2 font-mono text-fg-3">
          {age(last(row), now)}
          {one && model.mode(one) === "poll" && one.last_ok_at ? (
            <Meter
              value={Math.min(1, (now - Date.parse(one.last_ok_at)) / 1000 / Math.max(60, one.interval_seconds))}
              showValue={false}
              width={24}
              label="Since the last pull, against its interval"
            />
          ) : null}
        </span>
      );
    },
  };
  const columns: Column<Product>[] = [
    // Sized to the mark and its padding. Under 1024px it goes, so a 390px phone keeps both sides' words and the name. An image's max-width would let the cell shrink it to nothing.
    { label: "", width: 40, hide: "md", truncate: false, cell: (row) => <ProductLogo product={productLogo(row)} size={16} className="max-w-none" /> },
    {
      label: "Logs",
      fit: true,
      cell: (row) => {
        const word = logs(row);
        return (
          <Status tone={deliveryTone(word)} badge>
            {word}
          </Status>
        );
      },
    },
    // Empty for a product shoc has no act on.
    {
      label: "Response",
      fit: true,
      cell: (row) => {
        const word = responseState(row);
        return word ? (
          <Status tone={RESPONSE_TONE[word] ?? "idle"} badge>
            {word}
          </Status>
        ) : null;
      },
    },
    // Under 1024px the age moves into the name cell, without the meter: one more column would push a phone's row sideways.
    {
      label: "",
      strong: true,
      truncate: false,
      cell: (row) => (
        <span className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate">{productName(row)}</span>
          <span className="font-mono text-fg-3 lg:hidden">{age(last(row), now)}</span>
        </span>
      ),
    },
    time,
    {
      label: "",
      width: 40,
      menu: true,
      // The popover is the cell's child: left-aligned, or its confirm inherits the cell's right alignment.
      cell: (row) => (
        <span className="inline-block text-left">
          <Menu
            label={`${productName(row)} actions`}
            items={items(row)}
            trigger={(props) => (
              <Button {...props} variant="ghost" size="icon" aria-label={`${productName(row)} actions`}>
                {row.sources.some((s) => pulling.has(s.source)) ? <Spinner /> : <MoreHorizontal aria-hidden />}
              </Button>
            )}
          />
        </span>
      ),
    },
  ];

  return (
    <>
      {/* A create control sits in its list's toolbar, as on every screen. */}
      <CardToolbar className="justify-end">
        <Button size="sm" aria-keyshortcuts="N" onClick={onAdd}>
          <Plus aria-hidden />
          Add source
        </Button>
      </CardToolbar>
      <Table
        label="Products"
        columns={columns}
        rows={page}
        start={start}
        rowKey={(row) => row.key}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        empty={
          filtered ? (
            <Empty kind="filtered" title="No product in that state" onClear={onClear} />
          ) : (
            <Empty kind="row" title="Nothing connected" />
          )
        }
      />
      {pager}
    </>
  );
}
