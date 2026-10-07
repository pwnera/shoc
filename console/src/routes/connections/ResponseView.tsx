/**
 * A product's Response side, as its Logs side is laid out: Review (the acts
 * its credential unlocks, each opening its policy on Response › Autonomy,
 * which says how far shoc may take it; then the credential, what it acts in
 * and covers, and its last check), Settings (the credential's form, which
 * makes one read with it on Save) and Onboarding (how far it got, what to
 * grant and where to make it). A product with several credentials picks one
 * (`?credential=`, `+` for another account).
 *
 * Capabilities used: credential.list, credential.check (Check now), and the
 * form's credential.configure.
 */
import { useState } from "react";
import { Plus } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Fields } from "@/components/ui/dialog";
import { Chip } from "@/components/ui/filterbar";
import { Empty, Label, Spinner } from "@/components/ui/misc";
import { Status } from "@/components/ui/status";
import { Steps, type Step } from "@/components/ui/steps";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { credentialName, labelOf } from "@/lib/credentials";
import { age, stamp } from "@/lib/format";
import { actionLabel, readWord } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useCheckCredential } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import type { CredentialList, ResponseCredential } from "@/types";
import { ClickPath } from "./ConnectForm";
import { CredentialForm } from "./CredentialForm";
import type { Product } from "./products";
import { words } from "./state";

/* The act's name only: its autonomy and whether it can be undone are Response › Autonomy's. */
const COLUMNS: Column<string>[] = [{ label: "", strong: true, cell: (type) => actionLabel(type) }];

const NEW = "+";

/** The credential the views show: the one asked for, a new one (`+`), else the first. */
function useCredentialPick(product: Product) {
  const [params, setParams] = useSearchParams();
  const asked = params.get("credential") ?? "";
  const current = product.credentials.find((c) => c.name === asked) ?? (asked === NEW ? undefined : product.credentials[0]);
  const pick = (name: string) =>
    setParams(
      (now) => {
        const out = new URLSearchParams(now);
        out.set("credential", name);
        return out;
      },
      { replace: true },
    );
  return { asked, current, pick, adding: asked === NEW };
}

/** One chip per credential when there are several; Settings (`onAdd`) adds another account. */
function Picker({ product, onAdd }: { product: Product; onAdd?: () => void }) {
  const { current, pick, adding } = useCredentialPick(product);
  if (!product.credentials.length) return null;
  return (
    <span className="flex flex-wrap items-center gap-1" role="group" aria-label="Credential">
      {product.credentials.length > 1 || adding
        ? product.credentials.map((c) => (
            <Chip key={c.name} active={c.name === current?.name} onClick={() => pick(c.name)}>
              {labelOf(c.name) || credentialName(c.name)}
            </Chip>
          ))
        : null}
      {onAdd ? (
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            onAdd();
            pick(NEW);
          }}
          disabled={adding}
        >
          <Plus aria-hidden />
          Another account
        </Button>
      ) : null}
    </span>
  );
}

/** "works · 3h · signed in as …", "refused · … · the vendor's words", or never. */
function LastCheck({ credential }: { credential: ResponseCredential }) {
  const now = useNow();
  if (!credential.checked_at) return <span className="text-fg-3">never</span>;
  const { tone, word } = readWord(credential.check_ok);
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-2">
      <Status tone={tone} badge>
        {word}
      </Status>
      <Tip label={stamp(credential.checked_at)}>
        <span className="sh-mono text-fg-3">{age(credential.checked_at, now)}</span>
      </Tip>
      {credential.check_detail ? <span className="sh-mono min-w-0 break-words text-fg-2">{credential.check_detail}</span> : null}
    </span>
  );
}

/** Review: the acts, then the credential and its last check. */
export function ResponseReview({
  product,
  credentials,
  onSetUp,
}: {
  product: Product;
  credentials: CredentialList | undefined;
  onSetUp: () => void;
}) {
  const navigate = useNavigate();
  const { current } = useCredentialPick(product);
  const check = useCheckCredential();
  const types = [...(credentials?.providers[product.provider]?.actions ?? [])].sort((a, b) => actionLabel(a).localeCompare(actionLabel(b)));
  const nav = useListNav(types, (t) => t, {
    onOpen: (t) => navigate(`/response?tab=autonomy&policy=${encodeURIComponent(t)}`),
  });
  const need = product.need;
  return (
    <div className="flex flex-col gap-4">
      <section className="flex flex-col gap-1" aria-label="Acts">
        <span className="flex items-center justify-between gap-2">
          <Label>acts</Label>
          {types.length ? (
            <Link to={`/response?tab=autonomy&product=${encodeURIComponent(product.provider)}`} className="sh-link">
              Autonomy
            </Link>
          ) : null}
        </span>
        {types.length ? (
          <Table label="Acts" columns={COLUMNS} rows={types} rowKey={(t) => t} rowProps={nav.rowProps} bounded={240} />
        ) : (
          <Empty kind="row" title="No act on this product" />
        )}
      </section>
      <section className="flex flex-col gap-2" aria-label="Credential">
        <Picker product={product} />
        {current ? (
          <Fields
            ruled
            rows={[
              [
                "Last check",
                <span className="flex flex-wrap items-center gap-2">
                  <LastCheck credential={current} />
                  {current.missing.length ? null : (
                    <Button size="sm" variant="ghost" disabled={check.isPending} onClick={() => check.mutate(current.name)}>
                      {check.isPending ? <Spinner /> : null}
                      Check now
                    </Button>
                  )}
                </span>,
              ],
              [
                "Acts in",
                current.accounts.length ? (
                  <span className="flex flex-wrap gap-1">
                    {current.accounts.map((a) => (
                      <Chip key={a}>
                        <span className="sh-mono">{a}</span>
                      </Chip>
                    ))}
                  </span>
                ) : (
                  <span className="text-fg-3">every account</span>
                ),
              ],
              ["Not covered", need?.missing.length ? <span className="sh-mono text-warn">{need.missing.join(", ")}</span> : null],
              [
                "Covers",
                current.sources.length ? (
                  <span className="flex flex-wrap gap-x-3 gap-y-1">
                    {current.sources.map((s) => (
                      <Link key={s} to={`?source=${encodeURIComponent(s)}`} className="underline">
                        {sourceName(s)}
                      </Link>
                    ))}
                  </span>
                ) : null,
              ],
              ["Incomplete", current.missing.length ? <span className="text-warn">{current.missing.map(words).join(", ")}</span> : null],
            ]}
          />
        ) : (
          <div className="flex items-center gap-3">
            <span className="text-fg-2">No credential yet</span>
            <Button size="sm" onClick={onSetUp}>
              Set it up
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}

/** Settings: the credential's form; a new one shows what to grant and where. */
export function CredentialSettings({
  product,
  credentials,
  formId,
}: {
  product: Product;
  credentials: CredentialList | undefined;
  formId: string;
}) {
  const { asked, current, pick } = useCredentialPick(product);
  // Another account, once saved, lands on its own chip and keeps its form and what the read said; each Another account starts afresh.
  const [added, setAdded] = useState("");
  const [round, setRound] = useState(0);
  const kept = Boolean(added) && asked === added;
  return (
    <div className="flex flex-col gap-3">
      <Picker
        product={product}
        onAdd={() => {
          setAdded("");
          setRound(round + 1);
        }}
      />
      <CredentialForm
        // Keyed by what was asked, not by what it resolved to: a first save keeps its form, and what the read said.
        key={kept || asked === NEW ? `${product.key}:${NEW}${round}` : `${product.key}:${asked}`}
        provider={product.provider}
        need={credentials?.providers[product.provider]}
        current={kept ? product.credentials.find((c) => c.name === added) : current}
        taken={credentials?.configured.map((c) => c.name) ?? []}
        suggest={product.need?.missing}
        formId={formId}
        onSaved={(name) => {
          if (asked !== NEW) return;
          setAdded(name);
          pick(name);
        }}
      />
    </div>
  );
}

/** Onboarding: how far the credential got, what to grant, and where to make it. */
export function ResponseOnboarding({ product, credentials }: { product: Product; credentials: CredentialList | undefined }) {
  const { current } = useCredentialPick(product);
  const need = credentials?.providers[product.provider];
  const done = [
    Boolean(current?.has_secret),
    Boolean(current && !current.missing.length),
    // Read and not refused: PagerDuty's key has no read to try, so trying is the step.
    Boolean(current?.checked_at && current.check_ok !== false),
    Boolean(current && !product.need?.missing.length),
  ];
  const at = done.indexOf(false);
  const steps: Step[] = ["stored", "complete", "checked", "covered"].map((label, i) => ({
    key: label,
    label,
    state: done[i] ? "done" : i !== at ? "todo" : i === 2 && current?.check_ok === false ? "failed" : "current",
  }));
  return (
    <>
      <Steps steps={steps} label="Response onboarding" />
      <Fields
        ruled
        rows={[
          ["Grant", need?.grant ? <span className="text-fg-2">{need.grant}</span> : null],
          ["Last check", current ? <LastCheck credential={current} /> : null],
        ]}
      />
      {need?.where ? (
        <div className="flex flex-col gap-1">
          <Label>where</Label>
          <ClickPath path={need.where} />
        </div>
      ) : null}
    </>
  );
}
