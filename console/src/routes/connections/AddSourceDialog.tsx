/**
 * Add an intel source (`intel.configure`): a report source shoc knows by name, any
 * RSS or Atom feed by URL, or a lookup source that needs an account, which
 * opens its own dialog for the key. Each names the host it will contact; none
 * is on until added here, since each is an outbound connection (D57). Sources
 * already added are not offered, and a list row leaves once `intel.list`
 * says it is configured.
 */
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Empty, ErrorNote, Input, Spinner } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { useAddReportSource } from "@/lib/queries";
import type { IntelLookup, IntelPreset } from "@/types";
import { feedName, hostOf } from "../intel/feeds";

type Kind = "preset" | "feed" | "lookup";

/** A name, the host it calls, and one act. */
function Row({ name, host, children }: { name: string; host: string; children: ReactNode }) {
  return (
    <li className="flex min-h-8 items-center gap-2 border-b border-line-1 py-1 last:border-0">
      <span className="min-w-0 flex-1 truncate">{name}</span>
      <span className="sh-mono min-w-0 truncate text-fg-4">{host}</span>
      <span className="flex w-20 shrink-0 justify-end">{children}</span>
    </li>
  );
}

export function AddSourceDialog({
  presets,
  lookups,
  onLookup,
  onClose,
}: {
  /** The presets and lookups not configured yet. */
  presets: IntelPreset[];
  lookups: IntelLookup[];
  onLookup: (source: string) => void;
  onClose: () => void;
}) {
  const form = useId();
  const add = useAddReportSource();
  const [kind, setKind] = useState<Kind>("preset");
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const host = hostOf(url);
  const adding = add.isPending && add.variables && "preset" in add.variables ? add.variables.preset : "";

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!host || add.isPending) return;
    add.mutate({ feed: name.trim() || host, parser: "rss", settings: { url: url.trim() } }, { onSuccess: onClose });
  };

  return (
    <Dialog
      title="Add intel source"
      size="sm"
      onClose={onClose}
      footer={
        kind === "feed" ? (
          <Button type="submit" form={form} variant="primary" disabled={!host || add.isPending}>
            {add.isPending ? <Spinner /> : null}
            Add
          </Button>
        ) : undefined
      }
    >
      <Seg
        label="Kind"
        className="self-start"
        value={kind}
        onChange={setKind}
        options={[
          { value: "preset", label: "Report sources" },
          { value: "feed", label: "By URL" },
          { value: "lookup", label: "Lookups" },
        ]}
      />
      {kind === "preset" ? (
        presets.length ? (
          <ul className="m-0 flex list-none flex-col p-0" aria-label="Report sources">
            {presets.map((p) => (
              <Row key={p.name} name={feedName(p.name)} host={p.host}>
                <Button size="sm" variant="ghost" className="-mr-2" disabled={add.isPending} onClick={() => add.mutate({ preset: p.name })}>
                  {adding === p.name ? <Spinner /> : null}
                  Add
                </Button>
              </Row>
            ))}
          </ul>
        ) : (
          <Empty title="All added" />
        )
      ) : kind === "lookup" ? (
        lookups.length ? (
          <ul className="m-0 flex list-none flex-col p-0" aria-label="Lookups">
            {lookups.map((l) => (
              <Row key={l.source} name={feedName(l.source)} host={l.hosts.join(", ")}>
                <Button size="sm" variant="ghost" className="-mr-2" onClick={() => onLookup(l.source)}>
                  Set up
                </Button>
              </Row>
            ))}
          </ul>
        ) : (
          <Empty title="All set up" />
        )
      ) : (
        <form id={form} onSubmit={submit} className="flex flex-col gap-3">
          <Field label="URL" hint={host ? `contacts ${host}` : undefined}>
            <Input
              mono
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://"
            />
          </Field>
          <Field label="Name">
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder={host} />
          </Field>
        </form>
      )}
      {add.error ? <ErrorNote error={add.error} inline /> : null}
    </Dialog>
  );
}
