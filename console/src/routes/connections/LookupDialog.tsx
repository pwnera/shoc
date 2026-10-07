/**
 * One lookup source that needs an account (`?lookup=<name>`, RFC 0030): what
 * it answers (its title's tip), today's calls against its daily quota, until
 * when a 429 rate-limits it, the hosts it calls, and the form that sets its
 * key, its quota and, where the free tier is non-commercial, the person's
 * word that the key is under a commercial licence. The key is write-only:
 * left empty, the stored one stays. The switch, Save and Remove (behind a
 * confirm) call `intel.configure {lookup}`, which replaces the settings
 * whole, so each sends them all.
 */
import { useId, useState, type FormEvent } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Meter } from "@/components/ui/meter";
import { ErrorNote, Input, Spinner, Switch } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Status } from "@/components/ui/status";
import { Tip } from "@/components/ui/tip";
import { num, stamp } from "@/lib/format";
import { lookupState } from "@/lib/labels";
import { useNow } from "@/lib/now";
import type { Step } from "@/lib/popup";
import { useConfigureLookup } from "@/lib/queries";
import type { IntelLookup } from "@/types";
import { feedName } from "../intel/feeds";

export function LookupDialog({ lookup, step, onClose }: { lookup: IntelLookup; step?: Step; onClose: () => void }) {
  const form = useId();
  const now = useNow();
  const configure = useConfigureLookup();
  const state = lookupState(lookup, now);
  const [key, setKey] = useState("");
  const [perDay, setPerDay] = useState(String(lookup.per_day));
  // Set up once means the person said so already; the kernel still asks on every save.
  const [licensed, setLicensed] = useState(lookup.configured);
  const [asking, setAsking] = useState(false);
  const name = feedName(lookup.source);
  const licence = lookup.licence_needed ? { commercial_licence: true } : {};
  const ready = (lookup.configured || key.trim()) && (!lookup.licence_needed || licensed) && Number(perDay) >= 1;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || configure.isPending) return;
    configure.mutate(
      {
        lookup: lookup.source,
        enabled: lookup.configured ? lookup.enabled : true,
        settings: { per_day: Math.round(Number(perDay)), ...licence },
        ...(key.trim() ? { secret: { [lookup.secret_field]: key.trim() } } : {}),
      },
      { onSuccess: onClose },
    );
  };
  const toggle = (enabled: boolean) =>
    configure.mutate({ lookup: lookup.source, enabled, settings: { per_day: lookup.per_day, ...licence } });
  const paused = lookup.paused_until && Date.parse(lookup.paused_until) > now ? lookup.paused_until : null;

  return (
    <Dialog
      title={
        <Tip label={lookup.answers}>
          <span>{name}</span>
        </Tip>
      }
      id={lookup.source}
      size="sm"
      step={step}
      onClose={onClose}
      head={
        <Status tone={state.tone} badge>
          {state.word}
        </Status>
      }
      footer={
        <>
          {lookup.configured ? (
            <Popover
              open={asking}
              onOpenChange={setAsking}
              label={`Remove ${name}`}
              trigger={(props) => (
                <Button {...props} variant="ghost" className="mr-auto">
                  <Trash2 aria-hidden />
                  Remove
                </Button>
              )}
            >
              <Confirm
                what={`Remove ${name} · its key`}
                go="Remove"
                danger
                onConfirm={() =>
                  configure.mutateAsync({ lookup: lookup.source, remove: true }).then(() => {
                    setAsking(false);
                    onClose();
                  })
                }
                onCancel={() => setAsking(false)}
              />
            </Popover>
          ) : null}
          <Button type="submit" form={form} variant="primary" disabled={!ready || configure.isPending}>
            {configure.isPending ? <Spinner /> : null}
            Save
          </Button>
        </>
      }
    >
      {lookup.configured ? (
        <Switch checked={lookup.enabled} onChange={toggle} disabled={configure.isPending}>
          On
        </Switch>
      ) : null}
      <Fields
        rows={[
          [
            "calls today",
            lookup.configured ? (
              <Meter
                value={lookup.calls_today}
                max={lookup.per_day}
                tone={(v) => (v >= lookup.per_day ? "warn" : "neutral")}
                label="Calls today against the daily quota"
                format={(v) => `${num(v)}/${num(lookup.per_day)}`}
                width={96}
              />
            ) : null,
          ],
          ["rate-limited until", paused ? <span className="sh-mono">{stamp(paused)}</span> : null],
          ["hosts", <span className="sh-mono">{lookup.hosts.join(", ")}</span>],
        ]}
      />
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Field label={lookup.secret_field.replace(/_/g, " ")}>
          <Input
            mono
            type="password"
            autoComplete="off"
            value={key}
            onChange={(event) => setKey(event.target.value)}
            placeholder={lookup.configured ? "stored ••••" : undefined}
            data-autofocus
          />
        </Field>
        <Field label="Calls a day">
          <Input type="number" min={1} step={1} value={perDay} onChange={(event) => setPerDay(event.target.value)} />
        </Field>
        {lookup.licence_needed ? (
          <Switch checked={licensed} onChange={setLicensed}>
            Key under a commercial licence
          </Switch>
        ) : null}
      </form>
      {configure.error ? <ErrorNote error={configure.error} inline /> : null}
    </Dialog>
  );
}
