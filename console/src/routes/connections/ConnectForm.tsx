/**
 * The form that saves a source, for a connected source (its Settings view) and
 * for a connector picked in the catalog: visible labels, stored credentials
 * kept until replaced, the vendor's click path (before the source is
 * connected), verification, and for a push source the URL and the one-time key.
 *
 * Capabilities used: source.configure (with verify), source.push_key, and
 * source.list and health.sources while waiting for the first event.
 */
import { useEffect, useState } from "react";
import { Check, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Fields } from "@/components/ui/dialog";
import { Copy, Field } from "@/components/ui/field";
import { Empty, ErrorNote, Input, Label } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { Skel } from "@/components/ui/state";
import { Status } from "@/components/ui/status";
import { apiBase } from "@/lib/api";
import { readWord } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useConnectSource, usePushKey } from "@/lib/queries";
import { connectorOf, modes, sourceError, sourceName } from "@/lib/sources";
import type { ConfiguredSource } from "@/types";
import { useSourceState, words } from "./state";

/** "Admin → Security → API": a vendor's click path, one numbered step per line. */
export function ClickPath({ path }: { path: string }) {
  // Arrows inside a parenthesis belong to its aside, not to the path.
  const steps: string[] = [];
  let depth = 0;
  let step = "";
  for (const ch of path) {
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === "→" && !depth) {
      steps.push(step.trim());
      step = "";
    } else step += ch;
  }
  steps.push(step.trim());
  const shown = steps.filter(Boolean);
  if (!shown.length) return null;
  return (
    <ol className="m-0 flex list-none flex-col gap-1 p-0" aria-label="Where">
      {shown.map((s, i) => (
        <li key={i} className="grid grid-cols-[3ch_minmax(0,1fr)] items-baseline gap-2">
          <span className="sh-mono text-right text-fg-4" aria-hidden>
            {i + 1}
          </span>
          <span className="break-words text-fg-2">{s}</span>
        </li>
      ))}
    </ol>
  );
}

/* How long a save waits for the first event before it says what went wrong. */
const WAIT = 3 * 60_000;

/** Text for a setting's input; a list reads as comma-separated. */
function shown(value: unknown): string {
  if (value === undefined || value === null) return "";
  return Array.isArray(value) ? value.join(", ") : String(value);
}

/**
 * The form that saves a source. On a connected source it edits: settings start
 * from what is saved, and a stored credential reads "stored ••••" until
 * Replace. Save verifies against the vendor and shows ✓ or ✕, then waits for
 * the first event, three minutes at most: a run that fails, or no event by
 * then, ends the wait on the source's last error. A push source shows where
 * to send and the key to sign with; rotating the key breaks the sender, so it
 * asks for the source's name. Once
 * the source exists (saved from here a moment ago), a save keeps what the form
 * does not show (its other settings, cadence and pause) and the key only rotates.
 * With `formId` the host draws the submit button (a dialog footer).
 */
export function ConnectForm({
  source,
  current,
  formId,
}: {
  source: string;
  current?: ConfiguredSource;
  formId?: string;
}) {
  const model = useSourceState();
  const connect = useConnectSource();
  const key = usePushKey();
  const connector = connectorOf(source);
  const needs = model.list.data?.needs[connector];
  const can = modes(source, model.push);
  const [mode, setMode] = useState<"poll" | "push">(
    current ? model.mode(current) : can === "push" ? "push" : "poll",
  );
  const saved = Object.fromEntries((needs?.settings ?? []).map((name) => [name, shown(current?.settings[name])]));
  const [settings, setSettings] = useState<Record<string, string>>(saved);
  const [secret, setSecret] = useState<Record<string, string>>({});
  const [replacing, setReplacing] = useState(!current?.has_secret);
  const [savedAt, setSavedAt] = useState(0);
  const [rotating, setRotating] = useState(false);
  const polled = mode === "poll";

  // After a save, poll until the source's first delivery lands, a run fails, or three minutes pass.
  const now = useNow();
  const live = current ?? model.configured.find((r) => r.source === source);
  const after = (iso: string | null | undefined, slack = 0) => Boolean(iso && Date.parse(iso) >= savedAt - slack);
  const delivered = savedAt > 0 && after(live?.last_ok_at, 60_000);
  // No slack here: the failed run that a save means to fix is often a minute old.
  const failed = savedAt > 0 && Boolean(live?.last_error) && after(live?.last_run_at);
  const waiting = savedAt > 0 && !delivered && !failed && now - savedAt < WAIT;
  const stopped = savedAt > 0 && !delivered && !waiting;
  useEffect(() => {
    if (!waiting) return;
    const timer = setInterval(() => {
      void model.health.refetch();
      void model.list.refetch();
    }, 5_000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [waiting]);

  if (model.list.isPending) return <Skel kind="block" />;
  if (model.list.isLoadingError) return <ErrorNote error={model.list.error} onRetry={() => void model.list.refetch()} />;
  if (!needs) return <Empty title={`shoc has no connector named ${connector}`} />;

  const save = () => {
    // Only what changed replaces what is saved; a blank credential keeps the stored one.
    if (connect.isPending) return;
    const changed = Object.entries(settings).filter(([name, value]) => value !== saved[name]);
    void connect
      .mutateAsync({
        source,
        settings: { ...live?.settings, ...Object.fromEntries(changed) },
        secret: Object.fromEntries(Object.entries(secret).filter(([, value]) => value)),
        ...(live ? { interval_seconds: live.interval_seconds, enabled: live.enabled } : {}),
        verify: true,
      })
      .then(() => setSavedAt(Date.now()))
      .catch(() => {});
  };
  // A new push source is saved first, so the Integrator takes it up; the key call never touches settings.
  const generate = () =>
    void connect
      .mutateAsync({ source, settings: {}, secret: {} })
      .then(() => key.mutate({ source }))
      .catch(() => {});
  const result = connect.data?.data;
  const pushed = key.data?.data;

  return (
    <div className="flex flex-col gap-3">
      {!current && can === "poll or push" ? (
        <Seg
          label="Mode"
          className="self-start"
          value={mode}
          onChange={setMode}
          options={[
            { value: "poll", label: "shoc polls it" },
            { value: "push", label: "It pushes to shoc" },
          ]}
        />
      ) : null}
      {polled && needs.permission ? (
        <div className="flex flex-col gap-1">
          <Label>grant</Label>
          <span className="text-fg-2">{needs.permission}</span>
        </div>
      ) : null}
      {/* A connected source keeps its path on Onboarding, so Settings opens on its fields. */}
      {!current && (polled ? needs.where : needs.push_where) ? (
        <div className="flex flex-col gap-1">
          <Label>where</Label>
          <ClickPath path={polled ? needs.where : needs.push_where} />
        </div>
      ) : null}

      {polled ? (
        <form
          id={formId}
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            save();
          }}
        >
          {needs.settings.map((name) => (
            <Field key={name} label={words(name)}>
              <Input
                mono
                autoComplete="off"
                spellCheck={false}
                value={settings[name] ?? ""}
                onChange={(event) => setSettings({ ...settings, [name]: event.target.value })}
              />
            </Field>
          ))}
          {needs.secret.length && !replacing ? (
            <Field
              label={needs.secret.map(words).join(", ")}
              aside={
                <Button size="sm" variant="ghost" onClick={() => setReplacing(true)}>
                  Replace
                </Button>
              }
            >
              <Input mono readOnly value="stored ••••" />
            </Field>
          ) : (
            needs.secret.map((name) => (
              <Field key={name} label={words(name)}>
                <Input
                  mono
                  type="password"
                  autoComplete="off"
                  value={secret[name] ?? ""}
                  onChange={(event) => setSecret({ ...secret, [name]: event.target.value })}
                />
              </Field>
            ))
          )}
          {formId && !result && !waiting && !stopped ? null : (
            <div className="flex flex-wrap items-center gap-3">
              {formId ? null : (
                <Button type="submit" variant="primary" disabled={connect.isPending}>
                  {live ? "Save" : "Connect"}
                </Button>
              )}
              {result ? <Verified verified={result.verified} detail={result.verify_error} /> : null}
              {waiting ? <Status tone="running">waiting for the first event</Status> : null}
              {stopped ? (
                live?.last_error ? (
                  <span className="sh-mono min-w-0 break-words text-bad">{sourceError(live.last_error)}</span>
                ) : (
                  <Status tone="warn">no event in 3 min</Status>
                )
              ) : null}
            </div>
          )}
          {connect.error ? <ErrorNote error={connect.error} inline /> : null}
        </form>
      ) : (
        <div className="flex flex-col gap-3">
          <Field label="Send to">
            <Copy value={`${apiBase}/ingest/${source}`} label="Copy the ingest URL" />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            {live ? (
              <Popover
                open={rotating}
                onOpenChange={setRotating}
                label={`Rotate the ${sourceName(source)} key`}
                trigger={(props) => (
                  <Button {...props} variant="danger" disabled={key.isPending}>
                    Rotate key
                  </Button>
                )}
              >
                <Confirm
                  what={`Rotate the push key · ${sourceName(source)}`}
                  // source.list does not say whether a key was ever issued, so the fact holds either way.
                  facts={<span className="sh-badge sh-tone-bad">a sender with the old key stops</span>}
                  typed={source}
                  go="Rotate"
                  danger
                  onConfirm={() => key.mutateAsync({ source, rotate: true }).then(() => setRotating(false))}
                  onCancel={() => setRotating(false)}
                />
              </Popover>
            ) : (
              <Button variant="primary" disabled={connect.isPending || key.isPending} onClick={generate}>
                Generate key
              </Button>
            )}
          </div>
          {pushed?.push_key ? (
            <div className="flex flex-col gap-2">
              <Field label={connector === "github" ? "Webhook secret" : "Push key"} hint="Shown once">
                <Copy value={pushed.push_key} block label="Copy the push key" />
              </Field>
              {connector === "github" ? null : (
                <Fields
                  rows={[
                    ["Timestamp", <span className="sh-mono">{pushed.timestamp_header}</span>],
                    ["Signature", <span className="sh-mono">{pushed.signature_header}</span>],
                  ]}
                />
              )}
            </div>
          ) : null}
          {key.error ? <ErrorNote error={key.error} inline /> : null}
          {connect.error ? <ErrorNote error={connect.error} inline /> : null}
        </div>
      )}
    </div>
  );
}

/**
 * What a save's one read said, in `readWord`'s words: ✓ and what it read, ✕
 * and the refusal, or `none`: a source saved without a new secret is not
 * checked, a credential with nothing to read has no read to try.
 */
export function Verified({ verified, detail, none = "not checked" }: { verified: boolean | null; detail?: string | null; none?: string }) {
  if (verified === null) return <Badge tone="idle">{none}</Badge>;
  return verified ? (
    <span className="inline-flex min-w-0 items-center gap-1 text-good">
      <Check className="h-4 w-4 shrink-0" aria-hidden />
      {readWord(true).word}
      {detail ? <span className="sh-mono min-w-0 truncate text-fg-3">{detail}</span> : null}
    </span>
  ) : (
    <span className="inline-flex min-w-0 items-center gap-1 text-bad">
      <X className="h-4 w-4 shrink-0" aria-hidden />
      <span className="sh-mono min-w-0 break-words text-bad">{detail || readWord(false).word}</span>
    </span>
  );
}
