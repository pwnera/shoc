/**
 * Connections › Services: what shoc itself runs on and reaches people with.
 * The model the crew thinks with, the Slack app it posts to and takes
 * approvals from, and PagerDuty, which pages the on-call person. A row opens
 * its dialog (`?service=`), which J and K step: the model's provider, models,
 * endpoint and key; the Slack app's channel, approvers and secrets;
 * PagerDuty's routing key, as any response credential, its view in `?view=`.
 * Each save asks the L2 confirm. A blank field keeps what is stored, every
 * secret included. Budgets are Health › Spend's.
 *
 * Capabilities used: llm.show, llm.configure, slack.show, slack.configure,
 * credential.list, and the PagerDuty form's credential.configure.
 */
import { useId, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { ProductLogo } from "@/components/ui/logo";
import { ErrorNote, Input } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { AutonomyBadge, Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { count } from "@/lib/format";
import { modelProvider } from "@/lib/labels";
import { loadError } from "@/lib/loaded";
import { closeParams, useFollow, type Step } from "@/lib/popup";
import { useConfigureLlm, useConfigureSlack, useCredentials, useLlm, useSlack } from "@/lib/queries";
import type { CredentialList, LlmConfig, SlackView } from "@/types";
import { hostOf } from "../intel/feeds";
import { product, RESPONSE_TONE, responseState, type Product } from "./products";
import { CredentialSettings, ResponseOnboarding, ResponseReview } from "./ResponseView";

type Service = "model" | "slack" | "paging";
type Row = { id: Service; name: string; logo: string; word: string; detail: string };

const PROVIDERS = ["anthropic", "openai", "openai-responses", "none"] as const;

const l2 = <AutonomyBadge level="L2" />;

const modelRow = (llm: LlmConfig | undefined): Row => ({
  id: "model",
  name: "Model",
  logo: llm?.provider.startsWith("openai") ? "openai" : (llm?.provider ?? "anthropic"),
  word: !llm ? "" : llm.provider === "none" || llm.key !== "set" ? "not connected" : "connected",
  detail: llm && llm.provider !== "none" ? [modelProvider(llm.provider), llm.model].filter(Boolean).join(" · ") : "",
});

const slackRow = (slack: SlackView | undefined): Row => ({
  id: "slack",
  name: "Slack",
  logo: "slack",
  word: !slack ? "" : slack.has_bot_token && slack.verifies_requests && slack.channel ? "connected" : "not connected",
  detail: slack?.channel ? `${slack.channel} · ${count(Object.keys(slack.approvers).length, "approver")}` : "",
});

/** PagerDuty as a product of its own: the `notify` credential. */
function paging(data: CredentialList | undefined): Product {
  return { ...product("notify", data), credentials: (data?.configured ?? []).filter((c) => c.provider === "notify") };
}

export function Services() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const llm = useLlm();
  const slack = useSlack();
  const credentials = useCredentials();
  const pager = paging(credentials.data);
  const rows: Row[] = [
    modelRow(llm.data),
    slackRow(slack.data),
    { id: "paging", name: "PagerDuty", logo: "pagerduty", word: credentials.data ? (responseState(pager) ?? "") : "", detail: "" },
  ];
  /** Open a row's dialog, or step to it in place; the last one's credential and view go. */
  const go = (row: Row, push = false) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.set("service", row.id);
        out.delete("credential");
        out.delete("view");
        return out;
      },
      { replace: !push },
    );
  const nav = useListNav(rows, (r) => r.id, { onOpen: (r) => go(r, true) });
  const shown = params.get("service") ?? "";
  useFollow(nav, shown);
  const close = () => closeParams(["service", "credential", "view"], navigate);
  const at = rows.findIndex((r) => r.id === shown);
  const step: Step = {
    index: at,
    total: rows.length,
    onPrev: at > 0 ? () => go(rows[at - 1]!) : undefined,
    onNext: at >= 0 && at < rows.length - 1 ? () => go(rows[at + 1]!) : undefined,
  };
  // The read behind the open row: one that failed with nothing to show opens as its error, with Retry.
  const read = at >= 0 ? { model: llm, slack, paging: credentials }[rows[at]!.id] : undefined;
  const failed = read ? loadError(read) : undefined;

  const columns: Column<Row>[] = [
    { label: "", fit: true, truncate: false, cell: (r) => <ProductLogo product={r.logo} size={16} /> },
    {
      label: "",
      fit: true,
      cell: (r) =>
        r.word ? (
          <Status tone={RESPONSE_TONE[r.word] ?? "idle"} badge>
            {r.word}
          </Status>
        ) : null,
    },
    { label: "", strong: true, cell: (r) => r.name },
    { label: "", width: 280, hide: "md", mono: true, cell: (r) => r.detail },
  ];

  return (
    <>
      <Table
        label="Services"
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        rowProps={nav.rowProps}
        loading={llm.isPending || slack.isPending || credentials.isPending}
        error={loadError(llm) ?? loadError(slack) ?? loadError(credentials)}
        onRetry={() => void Promise.all([llm.refetch(), slack.refetch(), credentials.refetch()])}
      />
      {failed ? (
        <Dialog title={rows[at]!.name} size="sm" step={step} onClose={close}>
          <ErrorNote error={failed} onRetry={() => void read?.refetch()} />
        </Dialog>
      ) : shown === "model" && llm.data ? (
        <ModelDialog llm={llm.data} step={step} onClose={close} />
      ) : shown === "slack" && slack.data ? (
        <SlackDialog slack={slack.data} step={step} onClose={close} />
      ) : shown === "paging" && credentials.data ? (
        <PagingDialog product={pager} credentials={credentials.data} step={step} onClose={close} />
      ) : null}
    </>
  );
}

const PAGING_VIEWS = ["response", "credential", "grant"] as const;
type PagingView = (typeof PAGING_VIEWS)[number];

/** PagerDuty's credential, with a product's Response side and its views (`?view=`): Review, Settings, Onboarding. */
function PagingDialog({
  product,
  credentials,
  step,
  onClose,
}: {
  product: Product;
  credentials: CredentialList;
  step: Step;
  onClose: () => void;
}) {
  const form = useId();
  const [params, setParams] = useSearchParams();
  const asked = params.get("view") ?? "";
  // With no key stored there is nothing to review: Settings, which takes one.
  const view: PagingView = (PAGING_VIEWS as readonly string[]).includes(asked)
    ? (asked as PagingView)
    : product.credentials.length
      ? "response"
      : "credential";
  const setView = (v: PagingView) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.set("view", v);
        return out;
      },
      { replace: true },
    );
  return (
    <Dialog
      title={
        <span className="inline-flex items-center gap-2">
          <ProductLogo product="pagerduty" size={16} />
          PagerDuty
        </span>
      }
      step={step}
      onClose={onClose}
      footer={
        view === "credential" ? (
          <Button type="submit" form={form} variant="primary">
            Save
          </Button>
        ) : null
      }
    >
      <Seg
        label="View"
        className="self-start"
        value={view}
        onChange={setView}
        options={[
          { value: "response", label: "Review" },
          { value: "credential", label: "Settings" },
          { value: "grant", label: "Onboarding" },
        ]}
      />
      {view === "response" ? (
        <ResponseReview product={product} credentials={credentials} onSetUp={() => setView("credential")} />
      ) : view === "credential" ? (
        <CredentialSettings product={product} credentials={credentials} formId={form} />
      ) : (
        <ResponseOnboarding product={product} credentials={credentials} />
      )}
    </Dialog>
  );
}

/** The fields that changed, as llm.configure and slack.configure take them: the kernel keeps what is stored for an empty one. */
const changed = (now: Record<string, string>, was: Record<string, string>) =>
  Object.fromEntries(Object.entries(now).filter(([k, v]) => v.trim() && v.trim() !== (was[k] ?? "")).map(([k, v]) => [k, v.trim()]));

function ModelDialog({ llm, step, onClose }: { llm: LlmConfig; step: Step; onClose: () => void }) {
  const form = useId();
  const save = useConfigureLlm();
  const was = { provider: llm.provider, model: llm.model, model_cheap: llm.model_cheap, base_url: llm.base_url };
  const [fields, setFields] = useState<Record<string, string>>({ ...was, api_key: "" });
  const [asking, setAsking] = useState(false);
  const set = (name: string) => (event: { target: { value: string } }) => setFields({ ...fields, [name]: event.target.value });
  const change = changed(fields, was);
  const ready = Object.keys(change).length > 0;
  // Whoever holds the endpoint reads every case's evidence: the confirm names its host.
  const host = hostOf(fields.base_url ?? "");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) setAsking(true);
  };
  return (
    <Dialog
      title="Model"
      size="sm"
      step={step}
      onClose={onClose}
      footer={
        asking ? null : (
          <Button type="submit" form={form} variant="primary" disabled={!ready}>
            Save
          </Button>
        )
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Seg
          label="Provider"
          className="self-start"
          value={(PROVIDERS as readonly string[]).includes(fields.provider ?? "") ? (fields.provider as string) : "anthropic"}
          onChange={(provider) => setFields({ ...fields, provider })}
          options={PROVIDERS.map((p) => ({ value: p, label: modelProvider(p) }))}
        />
        <Field label="model">
          <Input mono autoComplete="off" spellCheck={false} value={fields.model} onChange={set("model")} />
        </Field>
        <Field label="light model" hint="the narrow roles">
          <Input mono autoComplete="off" spellCheck={false} value={fields.model_cheap} onChange={set("model_cheap")} />
        </Field>
        <Field label="endpoint">
          <Input mono type="url" autoComplete="off" spellCheck={false} value={fields.base_url} onChange={set("base_url")} />
        </Field>
        <Field label="key">
          <Input
            mono
            type="password"
            autoComplete="off"
            value={fields.api_key}
            onChange={set("api_key")}
            placeholder={llm.key === "set" ? "stored ••••" : undefined}
          />
        </Field>
      </form>
      {asking ? (
        <Confirm
          inline
          what={["Model", modelProvider(fields.provider ?? ""), fields.model].filter(Boolean).join(" · ")}
          facts={
            <>
              {l2}
              {host ? <span className="sh-badge">endpoint: {host}</span> : null}
              {change.api_key ? <span className="sh-badge">new key</span> : null}
            </>
          }
          go="Save"
          onConfirm={() => save.mutateAsync(change).then(onClose)}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}

/** "U0123 Sam Lee, U0456 Alex" ⇄ {U0123: "Sam Lee", U0456: "Alex"}; an id given no name is `unnamed`. */
const approversText = (a: Record<string, string>) =>
  Object.entries(a)
    .map(([id, name]) => `${id} ${name}`)
    .join(", ");
function approversOf(text: string) {
  const entries = text
    .split(",")
    .map((part) => part.trim().split(/\s+/))
    .filter(([id]) => id);
  return {
    named: Object.fromEntries(entries.filter((e) => e.length > 1).map(([id, ...name]) => [id!, name.join(" ")])),
    unnamed: entries.filter((e) => e.length === 1).map(([id]) => id!),
  };
}

function SlackDialog({ slack, step, onClose }: { slack: SlackView; step: Step; onClose: () => void }) {
  const form = useId();
  const save = useConfigureSlack();
  const stored = approversText(slack.approvers);
  const [channel, setChannel] = useState(slack.channel);
  const [approvers, setApprovers] = useState(stored);
  const [token, setToken] = useState("");
  const [signing, setSigning] = useState("");
  const [asking, setAsking] = useState(false);
  const { named, unnamed } = approversOf(approvers);
  // slack.configure keeps the stored approvers when it is given none, so the list cannot be emptied here.
  const wrong = unnamed.length ? `no name for ${unnamed.join(", ")}` : stored && !Object.keys(named).length ? "at least one" : undefined;
  const change = {
    ...(channel.trim() && channel.trim() !== slack.channel ? { channel: channel.trim() } : {}),
    ...(approvers.trim() !== stored ? { approvers: named } : {}),
    ...(token.trim() ? { bot_token: token.trim() } : {}),
    ...(signing.trim() ? { signing_secret: signing.trim() } : {}),
  };
  const ready = Object.keys(change).length > 0 && !wrong;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) setAsking(true);
  };
  return (
    <Dialog
      title={
        <span className="inline-flex items-center gap-2">
          <ProductLogo product="slack" size={16} />
          Slack
        </span>
      }
      size="sm"
      step={step}
      onClose={onClose}
      footer={
        asking ? null : (
          <Button type="submit" form={form} variant="primary" disabled={!ready}>
            Save
          </Button>
        )
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Field label="channel" hint="its id, e.g. C0123456789">
          <Input mono autoComplete="off" spellCheck={false} value={channel} onChange={(e) => setChannel(e.target.value)} />
        </Field>
        <Field label="approvers" hint="Slack user id and name, comma-separated" error={wrong}>
          <Input mono autoComplete="off" spellCheck={false} value={approvers} onChange={(e) => setApprovers(e.target.value)} />
        </Field>
        <Field label="bot token">
          <Input
            mono
            type="password"
            autoComplete="off"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={slack.has_bot_token ? "stored ••••" : "xoxb-…"}
          />
        </Field>
        <Field label="signing secret">
          <Input
            mono
            type="password"
            autoComplete="off"
            value={signing}
            onChange={(e) => setSigning(e.target.value)}
            placeholder={slack.verifies_requests ? "stored ••••" : undefined}
          />
        </Field>
      </form>
      {asking ? (
        <Confirm
          inline
          what={`Slack · ${channel.trim() || "no channel"}`}
          facts={
            <>
              {l2}
              <span className="sh-badge">{count(Object.keys(named).length, "approver")}</span>
              {change.bot_token ? <span className="sh-badge">new bot token</span> : null}
              {change.signing_secret ? <span className="sh-badge">new signing secret</span> : null}
            </>
          }
          go="Save"
          onConfirm={() => save.mutateAsync(change).then(onClose)}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}
