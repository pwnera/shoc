/**
 * One product, its one home, on two sides laid out alike. Logs: how its
 * logs deliver and which credentials act on what they see (Review), what a
 * source reads with (Settings), how far the Integrator got and where to click
 * (Onboarding), and what of it shoc treats as its own. Response: what shoc can
 * do there and the credential it does it with (Review), the credential's form
 * (Settings), and how far it got, what to grant and where (Onboarding). One
 * dialog that steps through the Products list with J and K; switching side
 * keeps the view. A product with several sources picks one (`?source=`); one
 * with none shows the connectors that would bring its logs in.
 *
 * Capabilities used: source.list, health.sources, source.sync, source.sample,
 * mapping.test, own.list, credential.list, credential.check, and the forms'
 * source.configure, source.push_key and credential.configure.
 */
import { useEffect, useId, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dialog, Fields, Json } from "@/components/ui/dialog";
import { Chip } from "@/components/ui/filterbar";
import { ProductLogo } from "@/components/ui/logo";
import { Empty, ErrorNote, Label } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Status } from "@/components/ui/status";
import { Steps } from "@/components/ui/steps";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { credentialName, vendorName } from "@/lib/credentials";
import { age, num, span, stamp } from "@/lib/format";
import { useNow } from "@/lib/now";
import { useMappingTest, useSampleSource, useSyncSource } from "@/lib/queries";
import { connectorOf, sourceError, sourceName } from "@/lib/sources";
import { toastError } from "@/lib/toast";
import type { ConfiguredSource, CredentialList, Onboarding, SourceSample } from "@/types";
import { ClickPath, ConnectForm } from "./ConnectForm";
import { FootprintTable } from "./Footprint";
import { otherSide, productLogo, productName, RESPONSE, RESPONSE_TONE, responseState, viewsOf, type Product } from "./products";
import { CredentialSettings, ResponseOnboarding, ResponseReview } from "./ResponseView";
import { deliveryTone, onboardingSteps, useSourceState, worstDelivery, type View } from "./state";

const LABELS: Record<View, string> = {
  delivery: "Review",
  settings: "Settings",
  onboarding: "Onboarding",
  footprint: "shoc's own",
  response: "Review",
  credential: "Settings",
  grant: "Onboarding",
};

export function ProductDialog({
  product,
  source,
  credentials,
  view,
  onView,
  onSource,
  step,
  onClose,
}: {
  product: Product;
  /** The source the source views show: one of the product's. */
  source: ConfiguredSource | undefined;
  credentials: CredentialList | undefined;
  view: View;
  onView: (view: View) => void;
  onSource: (source: string) => void;
  step: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const model = useSourceState();
  const sync = useSyncSource();
  const sample = useSampleSource();
  const test = useMappingTest();
  const name = source?.source ?? "";
  const polled = source ? model.mode(source) === "poll" : false;
  const onboarding = model.list.data?.onboarding.find((o) => o.source === name);
  const needs = model.list.data?.needs[connectorOf(name)];
  const formId = useId();
  const views = viewsOf(product);
  const shown = views.includes(view) ? view : views[0]!;
  const responding = RESPONSE.includes(shown);
  const side = views.filter((v) => RESPONSE.includes(v) === responding);
  const twin = otherSide(product, shown);
  const logs = worstDelivery(product.sources.map(model.state));
  const acts = responseState(product);

  // J and K keep the dialog open on the next product: the last one's sample and mapping test go.
  useEffect(() => {
    sample.reset();
    test.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  const footer =
    // A push source has no page to pull or sample: what it sent is under Events.
    shown === "delivery" && source && polled ? (
      <>
        <Button disabled={sample.isPending} onClick={() => sample.mutate(name)}>
          Sample one page
        </Button>
        <Button
          variant="primary"
          disabled={sync.isPending && sync.variables === name}
          onClick={() =>
            sync.mutate(name, {
              onError: (error) => toastError(error, `Pull ${sourceName(name)}`),
            })
          }
        >
          Pull now
        </Button>
      </>
    ) : (shown === "settings" && polled) || shown === "credential" ? (
      <Button type="submit" form={formId} variant="primary">
        Save
      </Button>
    ) : shown === "onboarding" ? (
      <Button disabled={test.isPending} onClick={() => test.mutate(name)}>
        Test mapping
      </Button>
    ) : null;
  const perSource = !responding && product.sources.length > 1;

  return (
    <Dialog
      // As tall as the view shows, with its top held, so the view control stays under the pointer.
      className="md:mt-[12dvh] md:mb-auto md:max-h-[calc(88dvh-1.5rem)]"
      title={
        <span className="inline-flex items-center gap-2">
          <ProductLogo product={productLogo(product)} size={16} />
          {productName(product)}
        </span>
      }
      id={product.key}
      head={
        <span className="inline-flex items-center gap-1.5">
          {product.sources.length ? (
            <Status tone={deliveryTone(logs)} badge>
              {logs}
            </Status>
          ) : null}
          {acts ? (
            <Status tone={RESPONSE_TONE[acts] ?? "idle"} badge>
              {acts}
            </Status>
          ) : null}
        </span>
      }
      step={step}
      onClose={onClose}
      footer={footer}
    >
      <div className="flex flex-wrap items-center gap-2">
        {twin ? (
          <Seg
            label="Side"
            value={responding ? "response" : "collection"}
            onChange={() => onView(twin)}
            options={[
              { value: "collection", label: "Logs" },
              { value: "response", label: "Response" },
            ]}
          />
        ) : null}
        {side.length > 1 ? (
          <Seg label="View" value={shown} onChange={onView} options={side.map((v) => ({ value: v, label: LABELS[v] }))} />
        ) : null}
      </div>
      {perSource ? (
        <span className="flex flex-wrap gap-1" role="group" aria-label="Source">
          {product.sources.map((s) => (
            <Chip key={s.source} active={s.source === name} onClick={() => onSource(s.source)}>
              {sourceName(s.source)}
            </Chip>
          ))}
        </span>
      ) : null}
      {shown === "response" ? (
        <ResponseReview product={product} credentials={credentials} onSetUp={() => onView("credential")} />
      ) : shown === "credential" ? (
        <CredentialSettings product={product} credentials={credentials} formId={formId} />
      ) : shown === "grant" ? (
        <ResponseOnboarding product={product} credentials={credentials} />
      ) : !source ? (
        <Unread product={product} credentials={credentials} />
      ) : shown === "delivery" ? (
        <Delivery row={source} polled={polled} alert={model.alert(source)} sample={sample} />
      ) : shown === "settings" ? (
        <ConnectForm key={name} source={name} current={source} formId={formId} />
      ) : shown === "onboarding" ? (
        <OnboardingView onboarding={onboarding} where={polled ? needs?.where : needs?.push_where} test={test} />
      ) : (
        <FootprintTable source={name} bounded={320} />
      )}
    </Dialog>
  );
}

/* -- Delivery ---------------------------------------------------------------- */

/** A product with a credential and no logs yet: the connectors that would bring them in. */
function Unread({ product, credentials }: { product: Product; credentials: CredentialList | undefined }) {
  const connectors = credentials?.providers[product.provider]?.connectors ?? [];
  return connectors.length ? (
    <div className="flex flex-col gap-1">
      <Label>connect its logs</Label>
      <span className="flex flex-wrap gap-1.5">
        {connectors.map((c) => (
          <Link key={c} to={`?add=${encodeURIComponent(c)}`} className="sh-chip sh-chip--dashed">
            {sourceName(c)}
          </Link>
        ))}
      </span>
    </div>
  ) : (
    <Empty title="No logs to read" />
  );
}

function Delivery({
  row,
  polled,
  alert,
  sample,
}: {
  row: ConfiguredSource;
  polled: boolean;
  /** The detail of Ops' `source.failing` alert on this source. */
  alert?: string;
  sample: ReturnType<typeof useSampleSource>;
}) {
  const now = useNow();
  const error = alert ? alert.replace(/^last error: /, "") : row.last_error;
  return (
    <>
      <Fields
        ruled
        rows={[
          ["Last run", row.last_run_at ? `${stamp(row.last_run_at)} · ${age(row.last_run_at, now)}` : "never"],
          ["Last ok", row.last_ok_at ? `${stamp(row.last_ok_at)} · ${age(row.last_ok_at, now)}` : "never"],
          ["Every", polled ? span(row.interval_seconds) : null],
          ["Events", num(row.events_seen)],
          ["Acts with", row.response?.length ? <ActsWith row={row} /> : null],
          [
            "Error",
            error ? <span className="sh-mono whitespace-pre-wrap break-words text-bad">{sourceError(error)}</span> : null,
          ],
        ]}
      />
      {sample.error ? <ErrorNote error={sample.error} inline /> : null}
      {sample.data ? <Sample data={sample.data} /> : null}
    </>
  );
}

/** The credentials that act on what it sees, or a link to connect one, per product it calls for. */
function ActsWith({ row }: { row: ConfiguredSource }) {
  // A credential opens on its Response review; connecting one, on the form with what to grant and where.
  const open = (provider: string, credential = "") =>
    `?vendor=${encodeURIComponent(provider)}&view=${credential ? `response&credential=${encodeURIComponent(credential)}` : "credential"}`;
  return (
    <span className="flex flex-col gap-1">
      {(row.response ?? []).map((r) => (
        <span key={r.provider} className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {r.credentials.map((name) => (
            <Link key={name} to={open(r.provider, name)} className="underline">
              {credentialName(name)}
            </Link>
          ))}
          {!r.credentials.length || r.missing.length ? (
            <Link to={open(r.provider)} className="text-warn underline">
              {r.credentials.length
                ? `${num(r.missing.length)} account${r.missing.length === 1 ? "" : "s"} not covered`
                : `Connect ${vendorName(r.provider)}`}
            </Link>
          ) : null}
        </span>
      ))}
    </span>
  );
}

type SampleRow = Record<string, unknown>;

/** One page as the vendor sends it: a few top-level fields per row; a row opens its whole record. */
export function Sample({ data }: { data: SourceSample }) {
  const [open, setOpen] = useState<number | null>(null);
  const keys = Object.keys(data.rows[0] ?? {})
    .filter((k) => data.rows.some((r) => ["string", "number", "boolean"].includes(typeof r[k])))
    .slice(0, 3);
  const rows = data.rows.map((r, i) => ({ ...r, __i: i }));
  const nav = useListNav(rows, (r) => String(r.__i), { onOpen: (r) => setOpen(r.__i) });
  const columns: Column<SampleRow & { __i: number }>[] = keys.map((k) => ({
    label: k,
    mono: true,
    cell: (r) => (r[k] === undefined || r[k] === null ? "" : String(r[k])),
  }));
  const picked = open === null ? undefined : data.rows[open];
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Label>sample</Label>
        <span className="sh-mono">{num(data.fetched)} fetched</span>
        {data.error ? <span className="sh-mono text-bad">{data.error}</span> : null}
      </div>
      {data.rows.length ? (
        <Table
          label="Sample rows"
          columns={columns.length ? columns : [{ label: "row", mono: true, cell: (r) => JSON.stringify(r) }]}
          rows={rows}
          rowKey={(r) => String(r.__i)}
          rowProps={nav.rowProps}
          bounded={240}
        />
      ) : (
        <Empty title="Nothing came back" />
      )}
      {data.unmapped_fields.length ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <Label>unmapped</Label>
          {data.unmapped_fields.map((f) => (
            <Chip key={f} value={f} dashed />
          ))}
        </div>
      ) : null}
      {data.needs ? <span className="sh-mono text-warn">{data.needs}</span> : null}
      {picked && open !== null ? (
        <Dialog
          title="Sample row"
          step={{
            index: open,
            total: data.rows.length,
            onPrev: open > 0 ? () => setOpen(open - 1) : undefined,
            onNext: open < data.rows.length - 1 ? () => setOpen(open + 1) : undefined,
          }}
          onClose={() => setOpen(null)}
        >
          <Json value={picked} />
        </Dialog>
      ) : null}
    </div>
  );
}

/* -- Onboarding -------------------------------------------------------------- */

function OnboardingView({
  onboarding,
  where,
  test,
}: {
  onboarding: Onboarding | undefined;
  where: string | undefined;
  test: ReturnType<typeof useMappingTest>;
}) {
  const proof = test.data?.proof_finding || onboarding?.proof_finding;
  const supports = test.data?.supports ?? onboarding?.supports;
  const cannot = test.data?.cannot_support ?? onboarding?.cannot_support;
  return (
    <>
      <Steps steps={onboardingSteps(onboarding?.step)} label="Onboarding" />
      {onboarding?.dark ? (
        <Status tone="warn" badge className="self-start">
          dark
        </Status>
      ) : null}
      <Fields
        ruled
        rows={[
          [
            "Scopes",
            onboarding?.scopes.length ? (
              <span className="flex flex-wrap gap-1">
                {onboarding.scopes.map((s) => (
                  <Chip key={s} className="h-auto min-h-6 whitespace-normal py-0.5">
                    {s}
                  </Chip>
                ))}
              </span>
            ) : null,
          ],
          ["Supports", supports ? `${num(supports.length)} rules` : null],
          ["Cannot", cannot?.length ? `${num(cannot.length)} kinds of rule` : null],
          [
            "Proof",
            proof ? (
              <Link to={`/findings/${proof}`} className="sh-mono underline">
                {proof}
              </Link>
            ) : null,
          ],
        ]}
      />
      {/* The Integrator's own path, or the vendor's for how the source delivers: Settings keeps to the fields. */}
      {onboarding?.click_path || where ? (
        <div className="flex flex-col gap-1">
          <Label>where</Label>
          <ClickPath path={onboarding?.click_path || where || ""} />
        </div>
      ) : null}
      {test.error ? <ErrorNote error={test.error} inline /> : null}
      {!onboarding && !test.data ? <Empty title="The Integrator has not looked at it yet" /> : null}
    </>
  );
}
