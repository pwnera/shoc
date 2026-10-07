/**
 * The form that saves a response credential, on a product's Response ›
 * Settings, for the credential shown or a new one: for a new one what to grant
 * on the vendor's side and where to click,
 * the accounts it acts in (the ones its sources saw and nothing covers yet
 * offered as chips), its settings, and its secret, which reads "stored ••••"
 * until Replace. A blank secret field keeps the stored one. A second credential
 * of a provider takes a label: `aws:staging`. Save asks the L2 confirm, then
 * makes one read with it and says what came back.
 *
 * Capabilities used: credential.configure.
 */
import { useState } from "react";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/filterbar";
import { Field } from "@/components/ui/field";
import { Empty, Input, Label } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { AutonomyBadge, Status } from "@/components/ui/status";
import { credentialName, providerOf, vendorName } from "@/lib/credentials";
import { readWord } from "@/lib/labels";
import { useConfigureCredential } from "@/lib/queries";
import type { ProviderNeeds, ResponseCredential } from "@/types";
import { ClickPath, Verified } from "./ConnectForm";
import { words } from "./state";

/** Text for a setting's input; a list reads as comma-separated. */
const shown = (value: unknown) =>
  value === undefined || value === null ? "" : Array.isArray(value) ? value.join(", ") : String(value);

const list = (text: string) =>
  text
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);

export function CredentialForm({
  provider,
  need,
  current,
  taken,
  suggest = [],
  formId,
  onSaved,
}: {
  provider: string;
  need: ProviderNeeds | undefined;
  /** The credential the form edits; a new one when absent. */
  current?: ResponseCredential;
  /** Credential names already stored: a new one must not overwrite one. */
  taken: string[];
  /** Accounts its sources' events named that no credential claims. */
  suggest?: string[];
  /** With an id the host draws the submit button (a dialog footer). */
  formId?: string;
  onSaved?: (name: string) => void;
}) {
  const save = useConfigureCredential();
  const fields = [...(need?.settings ?? []), ...(need?.optional ?? [])];
  const savedSettings = Object.fromEntries(fields.map((f) => [f, shown(current?.settings[f])]));
  const [label, setLabel] = useState("");
  const [accounts, setAccounts] = useState((current?.accounts ?? []).join(", "));
  const [settings, setSettings] = useState<Record<string, string>>(savedSettings);
  const [secret, setSecret] = useState<Record<string, string>>({});
  const [replacing, setReplacing] = useState(!current?.has_secret);
  const [asking, setAsking] = useState(false);

  if (!need) return <Empty title={`shoc cannot act on ${vendorName(provider)}`} />;

  const name = current?.name ?? (label.trim() ? `${provider}:${label.trim().toLowerCase()}` : provider);
  // A plain name a credential already holds would replace it; the one just saved is this form's own.
  const clash = !current && taken.includes(name) && !(save.isSuccess && save.variables?.provider === name);
  const typed = list(accounts);
  const offered = suggest.filter((a) => !typed.includes(a));
  const secrets = replacing ? [...need.secret, ...need.alternative] : [];
  const given = Object.fromEntries(Object.entries(secret).filter(([, v]) => v));

  const submit = () => {
    if (!save.isPending && !clash) setAsking(true);
  };
  const send = () => {
    const filled = Object.fromEntries(Object.entries(settings).filter(([, v]) => v.trim()));
    return save
      .mutateAsync({
        provider: name,
        settings: {
          ...Object.fromEntries(Object.entries(current?.settings ?? {}).filter(([k]) => !fields.includes(k))),
          ...filled,
          ...(typed.length ? { accounts: typed } : {}),
        },
        secret: given,
      })
      .then(() => {
        setAsking(false);
        onSaved?.(name);
      });
  };
  const result = save.data?.data;

  return (
    <>
      <form
        id={formId}
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        {/* A credential stored keeps these on its Onboarding view, so Settings opens on its fields. */}
        {current ? null : (
          <>
            <div className="flex flex-col gap-1">
              <Label>grant</Label>
              <span className="text-fg-2">{need.grant}</span>
            </div>
            {need.where ? (
              <div className="flex flex-col gap-1">
                <Label>where</Label>
                <ClickPath path={need.where} />
              </div>
            ) : null}
          </>
        )}
        {current ? null : (
          <Field
            label="label"
            hint={taken.some((t) => providerOf(t) === provider) ? "another tenant of the same provider" : undefined}
            error={clash ? `${name} is connected: give this one a label` : undefined}
          >
            <Input mono autoComplete="off" spellCheck={false} value={label} placeholder="optional" onChange={(e) => setLabel(e.target.value)} />
          </Field>
        )}
        <Field label="accounts" hint={typed.length ? undefined : "every account no other credential claims"} group>
          <div className="flex flex-col gap-1.5">
            <Input mono autoComplete="off" spellCheck={false} value={accounts} onChange={(e) => setAccounts(e.target.value)} />
            {offered.length ? (
              <span className="flex flex-wrap gap-1">
                {offered.map((a) => (
                  <Chip key={a} dashed onClick={() => setAccounts([...typed, a].join(", "))}>
                    <Plus className="h-3 w-3" aria-hidden />
                    <span className="sh-mono">{a}</span>
                  </Chip>
                ))}
              </span>
            ) : null}
          </div>
        </Field>
        {fields.map((f) => (
          <Field key={f} label={words(f)} aside={need.optional.includes(f) ? <span className="text-fg-4">optional</span> : undefined}>
            <Input mono autoComplete="off" spellCheck={false} value={settings[f] ?? ""} onChange={(e) => setSettings({ ...settings, [f]: e.target.value })} />
          </Field>
        ))}
        {!replacing ? (
          <Field
            label={need.secret.map(words).join(", ")}
            aside={
              <Button size="sm" variant="ghost" onClick={() => setReplacing(true)}>
                Replace
              </Button>
            }
          >
            <Input mono readOnly value="stored ••••" />
          </Field>
        ) : (
          secrets.map((f) => (
            <Field key={f} label={words(f)} aside={need.alternative.includes(f) ? <span className="text-fg-4">or</span> : undefined}>
              <Input mono type="password" autoComplete="off" value={secret[f] ?? ""} onChange={(e) => setSecret({ ...secret, [f]: e.target.value })} />
            </Field>
          ))
        )}
        <div className="flex flex-wrap items-center gap-3">
          {formId || asking ? null : (
            <Button type="submit" variant="primary" disabled={save.isPending || clash}>
              {current ? "Save" : "Connect"}
            </Button>
          )}
          {result && !asking ? (
            result.missing.length ? (
              <Status tone="warn">needs {result.missing.map(words).join(", ")}</Status>
            ) : (
              <Verified verified={result.verified ?? null} detail={result.verify_detail} none={readWord(null).word} />
            )
          ) : null}
        </div>
      </form>
      {/* Its own form beside this one: a form inside a form is not one. */}
      {asking ? (
        <Confirm
          inline
          what={`${current ? "Save" : "Connect"} ${credentialName(name)}`}
          facts={
            <>
              <AutonomyBadge level="L2" />
              <span className="sh-badge">acts in: {typed.length ? typed.join(", ") : "every account"}</span>
              {Object.keys(given).length ? <span className="sh-badge">new secret</span> : null}
            </>
          }
          go={current ? "Save" : "Connect"}
          onConfirm={send}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </>
  );
}
