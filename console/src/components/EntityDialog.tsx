/**
 * One entity, the home of its facts and of `intel.lookup`: what it is and
 * whether it is ours, exposed, privileged or stale (Overview), what it touches
 * (Graph, re-rooted by a click), live state from a connected platform (Live,
 * audited), and what the intel sources say (Intel, for the kinds they answer).
 * Each view loads when first opened. ⌘J while it is open asks the crew with
 * the entity as context.
 *
 * Capabilities used: posture.exposure, asset.identify, identity.resolve,
 * graph.neighbours, platform.lookups, platform.lookup, intel.lookup,
 * timeline.extend.
 */
import { useState, type ReactNode } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { cn } from "@/lib/cn";
import { exploreHref } from "@/lib/explore";
import { exploreQuery, intelType, parseEntity, type Entity as Parsed, type EntityKind } from "@/lib/entity";
import { num } from "@/lib/format";
import { intelSourceLabel } from "@/lib/labels";
import type { Step } from "@/lib/popup";
import {
  useAssetIdentify,
  useExposureOf,
  useExtendTimeline,
  useIdentityResolve,
  useLookup,
  useLookupOf,
  useNeighbours,
  usePlatformLookup,
  usePlatformLookups,
} from "@/lib/queries";
import { toast, toastError } from "@/lib/toast";
import { FLAGS, type Flag } from "@/routes/posture/cells";
import type { PlatformLookupDef } from "@/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Dialog, Fields } from "./ui/dialog";
import { Entity } from "./ui/entity";
import { Copy } from "./ui/field";
import { Graph } from "./ui/graph";
import { ProductLogo } from "./ui/logo";
import { Empty, ErrorNote, Label } from "./ui/misc";
import { Meter } from "./ui/meter";
import { Seg } from "./ui/seg";
import { QueryState, Skel } from "./ui/state";
import { Mark, Status, type StatusTone } from "./ui/status";
import { Tip } from "./ui/tip";

type View = "overview" | "graph" | "live" | "intel";

/** The parameter names a platform lookup takes for each kind of entity. */
const PARAMS: Partial<Record<EntityKind, string[]>> = {
  user: ["user", "username", "login", "email", "upn"],
  email: ["email", "user", "mailbox", "upn"],
  key: ["key", "access_key", "access_key_id", "key_id"],
  ip: ["ip", "address", "ip_address"],
  host: ["host", "hostname", "device", "device_id"],
  account: ["account", "account_id"],
  domain: ["domain"],
  repo: ["repo", "repository"],
};

/** Intel verdicts on the status scale (`shoc/detect/osint.py`): known-bad is bad, never a severity hue. */
const INTEL: Record<string, StatusTone> = { malicious: "bad", suspicious: "warn", benign: "good" };

const IDENTITY: EntityKind[] = ["user", "key", "email"];
const ASSET: EntityKind[] = ["ip", "host", "user", "domain", "resource"];

function fit(def: PlatformLookupDef, kind: EntityKind): string | null {
  const names = PARAMS[kind] ?? [];
  return def.params.find((p) => names.includes(p.toLowerCase())) ?? null;
}

export function EntityDialog({
  entity,
  view: asked,
  onView,
  onClose,
  step,
}: {
  /** `kind:value` or a bare value. */
  entity: string;
  view?: string;
  onView?: (view: string) => void;
  onClose: () => void;
  /** "3 / 25" and J and K, for the list that opened it. */
  step?: Step;
}) {
  const parsed: Parsed = parseEntity(entity) ?? { kind: "resource", type: "value", value: entity, key: entity };
  const intel = intelType(parsed);
  const views: { value: View; label: string }[] = [
    { value: "overview", label: "Overview" },
    { value: "graph", label: "Graph" },
    { value: "live", label: "Live" },
    ...(intel ? [{ value: "intel" as View, label: "Intel" }] : []),
  ];
  const [local, setLocal] = useState<View>("overview");
  const view: View = views.some((v) => v.value === asked) ? (asked as View) : asked ? "overview" : local;
  const pick = (next: View) => (onView ? onView(next) : setLocal(next));
  const exposure = useExposureOf(parsed.key);
  const { pathname } = useLocation();
  const caseUid = /^\/cases\/([^/]+)$/.exec(pathname)?.[1];

  // Each flag in the look Posture's rows give it.
  const e = exposure.data;
  const shown: Flag[] = !e
    ? []
    : [
        ...((e.exposed && e.privileged ? ["both"] : [e.exposed && "exposed", e.privileged && "privileged"]) as (Flag | false)[]),
        e.stale && "stale",
      ].filter((f): f is Flag => Boolean(f));
  const flags = shown.length ? (
    <>
      {shown.map((f) => (
        <Badge key={f} tone={FLAGS[f].tone} className={cn(FLAGS[f].className, FLAGS[f].className && "bg-transparent")}>
          {FLAGS[f].word}
        </Badge>
      ))}
    </>
  ) : null;

  return (
    <Dialog
      title={
        <span className="inline-flex min-w-0 items-center gap-2">
          <Label>{parsed.type}</Label>
          <Copy value={parsed.value} label="Copy the value" />
        </span>
      }
      head={flags}
      step={step}
      onClose={onClose}
      footer={<Footer entity={parsed} caseUid={caseUid} />}
    >
      <Seg<View> label="View" value={view} options={views} onChange={pick} className="self-start" />
      {view === "overview" ? <Overview entity={parsed} /> : null}
      {view === "graph" ? <GraphView entity={parsed} /> : null}
      {view === "live" ? <Live entity={parsed} /> : null}
      {view === "intel" && intel ? <Intel value={parsed.value} type={intel} /> : null}
    </Dialog>
  );
}

function Chips({ values }: { values: string[] }) {
  if (!values.length) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {values.slice(0, 8).map((v) => (
        <span key={v} className="sh-chip">
          <span className="sh-chip__value">{v}</span>
        </span>
      ))}
      {values.length > 8 ? <span className="sh-mono">+{values.length - 8}</span> : null}
    </span>
  );
}

function Overview({ entity }: { entity: Parsed }) {
  const exposure = useExposureOf(entity.key);
  const asset = useAssetIdentify(entity.key, ASSET.includes(entity.kind));
  const identity = useIdentityResolve(entity.key, IDENTITY.includes(entity.kind));
  const queries = [exposure, ...(ASSET.includes(entity.kind) ? [asset] : []), ...(IDENTITY.includes(entity.kind) ? [identity] : [])];

  return (
    <QueryState queries={queries}>
      {() => {
        const e = exposure.data;
        const a = ASSET.includes(entity.kind) ? asset.data : undefined;
        const i = IDENTITY.includes(entity.kind) ? identity.data : undefined;
        const rows: [string, ReactNode][] = [
          ["Events", e ? <span className="sh-mono sh-mono--strong">{num(e.events)}</span> : null],
          [
            "Sources",
            e?.sources.length ? (
              <span className="flex flex-wrap items-center gap-1.5">
                {e.sources.map((s) => (
                  <Tip key={s} label={s}>
                    <span className="inline-flex">
                      <ProductLogo product={s} named />
                    </span>
                  </Tip>
                ))}
              </span>
            ) : null,
          ],
          ["Countries", e?.countries.length ? <Chips values={e.countries} /> : null],
          ["Operations", e?.operations.length ? <Chips values={e.operations} /> : null],
          [
            "Ours",
            a ? (
              <span className="flex flex-wrap items-center gap-1.5">
                <Badge tone={a.is_ours ? "good" : "idle"}>{a.is_ours ? "ours" : "not ours"}</Badge>
                {/* What a declaration or a source says it is; "observed" repeats the rows around it. */}
                {a.source !== "observed" && a.what_it_is !== "unknown" ? (
                  <span className="min-w-0 text-fg-2">{a.what_it_is}</span>
                ) : null}
              </span>
            ) : null,
          ],
          [
            "Accounts behind it",
            a && a.principals !== 0 ? (
              <span className="sh-mono">{a.principals < 0 ? "unknown" : num(a.principals)}</span>
            ) : null,
          ],
          [
            "Linked",
            i ? (
              i.linked.length ? (
                <span className="flex flex-wrap gap-1">
                  {i.linked.slice(0, 12).map((l) => (
                    <Entity key={l.entity} value={l.entity} button />
                  ))}
                </span>
              ) : i.unbridged ? (
                <Badge tone="warn">not linked</Badge>
              ) : null
            ) : null,
          ],
        ];
        const shown = rows.filter(([, v]) => v !== null && v !== undefined);
        if (!shown.length || (e && !e.known && !e.events)) return <Empty title="Nothing on record" />;
        return <Fields rows={rows} ruled />;
      }}
    </QueryState>
  );
}

function GraphView({ entity }: { entity: Parsed }) {
  const [hops, setHops] = useState<"1" | "2">("1");
  const [, setParams] = useSearchParams();
  const graph = useNeighbours(entity.key, Number(hops));
  const nodes = (graph.data?.nodes ?? []).map((n) => ({ id: n.node_id, kind: n.kind, label: n.label, weight: n.events }));
  // Every edge is "observed with"; a label on each would only hide the nodes.
  const edges = (graph.data?.edges ?? []).map((e) => ({ src: e.src, dst: e.dst, weight: e.weight }));
  const reroot = (id: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.set("entity", id);
      return out;
    });
  return (
    <div className="flex flex-col gap-2">
      <Seg
        label="Hops"
        value={hops}
        options={[
          { value: "1", label: "1 hop" },
          { value: "2", label: "2 hops" },
        ]}
        onChange={setHops}
        className="self-start"
      />
      <QueryState queries={graph} isEmpty={nodes.length <= 1} empty={<Empty title="No connections on record" />} skeleton={<Skel kind="block" />}>
        {() => (
          <Graph
            layout="radial"
            nodes={nodes}
            edges={edges}
            root={graph.data?.root ?? entity.key}
            focus={graph.data?.root ?? entity.key}
            height={320}
            onOpen={(node) => node.id !== graph.data?.root && reroot(node.id)}
            name={(node) => `${node.kind} ${node.label}, ${num(node.weight ?? 0)} events`}
            label={`What ${entity.value} touches`}
          />
        )}
      </QueryState>
    </div>
  );
}

function Live({ entity }: { entity: Parsed }) {
  const lookups = usePlatformLookups();
  const lookup = usePlatformLookup();
  const [asked, setAsked] = useState("");
  const fitting = (lookups.data?.lookups ?? []).flatMap((def) => {
    const param = fit(def, entity.kind);
    return param ? [{ def, param }] : [];
  });
  return (
    <QueryState
      queries={lookups}
      isEmpty={!fitting.length}
      empty={<Empty title={`No platform answers for a ${entity.type}`} />}
    >
      {() => (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-1.5">
            {fitting.map(({ def, param }) => (
              <Tip key={def.lookup} label={def.configured ? def.does : `${def.does} · not connected`}>
                <Button
                  size="sm"
                  disabled={!def.configured || lookup.isPending}
                  aria-pressed={asked === def.lookup}
                  onClick={() => {
                    setAsked(def.lookup);
                    lookup.mutate({ lookup: def.lookup, params: { [param]: entity.value } });
                  }}
                >
                  {def.lookup}
                </Button>
              </Tip>
            ))}
          </div>
          {lookup.isPending ? <Skel kind="block" /> : null}
          {lookup.isError ? <ErrorNote error={lookup.error} /> : null}
          {lookup.data ? (
            <Fields
              ruled
              rows={Object.entries(lookup.data.data).map(([k, v]): [string, ReactNode] => [
                k,
                <span className="sh-mono">{typeof v === "string" ? v : JSON.stringify(v)}</span>,
              ])}
            />
          ) : null}
        </div>
      )}
    </QueryState>
  );
}

function Intel({ value, type }: { value: string; type: string }) {
  const answer = useLookupOf(value, type);
  const refresh = useLookup();
  return (
    <QueryState queries={answer}>
      {() => {
        const d = answer.data!;
        return (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Status tone={INTEL[d.verdict] ?? "idle"} badge>
                {d.verdict}
              </Status>
              {/* The kernel adds source weights: 1.5 suspicious, 4 malicious (`shoc/detect/osint.py`). */}
              <Meter
                value={Math.max(-2, Math.min(6, d.score))}
                min={-2}
                max={6}
                marks={[
                  { at: 1.5, label: "suspicious" },
                  { at: 4, label: "malicious" },
                ]}
                tone={(v) => (v >= 4 ? "bad" : v >= 1.5 ? "warn" : "neutral")}
                label="Score"
                format={() => d.score.toFixed(1)}
                width={96}
              />
              <span className="sh-mono">conf {Math.round(d.confidence * 100)}%</span>
              {d.shared_infrastructure ? <Badge tone="idle">shared infrastructure</Badge> : null}
              {d.internal ? <Badge tone="idle">internal</Badge> : null}
              {d.owner ? <Badge>{d.owner}</Badge> : null}
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto"
                disabled={refresh.isPending}
                onClick={() =>
                  refresh.mutate(
                    { value, type, refresh: true },
                    { onSuccess: () => toast({ tone: "ok", text: `Looked up again · ${d.observations.length} sources` }), onError: (e) => toastError(e, "Lookup failed") },
                  )
                }
              >
                <RefreshCw aria-hidden />
                Refresh
              </Button>
            </div>
            {d.observations.length ? (
              <ul className="m-0 flex list-none flex-col gap-1 p-0">
                {d.observations.map((o) => (
                  <li key={o.source} className="flex items-center gap-2">
                    <Mark tone={INTEL[o.verdict] ?? "idle"} />
                    <span className="sh-mono sh-mono--strong">{intelSourceLabel(o.source)}</span>
                    <span className="sh-mono">{o.verdict || "no answer"}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty title="No source knows it" />
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Link className="sh-link" to={exploreHref({ q: value, since: "-90d" })}>
                {num(d.seen_in_our_logs)} in our logs
              </Link>
              {d.sources_failed.map((s) => (
                <Badge key={s} tone="faint">
                  {intelSourceLabel(s)} failed
                </Badge>
              ))}
            </div>
          </div>
        );
      }}
    </QueryState>
  );
}

function Footer({ entity, caseUid }: { entity: Parsed; caseUid?: string }) {
  const extend = useExtendTimeline();
  return (
    <>
      <Link className="sh-btn sh-btn--ghost sh-btn--md" to={exploreHref({ q: exploreQuery(entity), since: "-7d" })}>
        Events
      </Link>
      <Link className="sh-btn sh-btn--ghost sh-btn--md" to={`/findings?on=${encodeURIComponent(entity.key)}`}>
        Findings
      </Link>
      <Link className="sh-btn sh-btn--ghost sh-btn--md" to={`/memory?q=${encodeURIComponent(entity.value)}`}>
        Memory
      </Link>
      {caseUid ? (
        <Button
          disabled={extend.isPending}
          onClick={() =>
            extend.mutate(
              { case_uid: caseUid, value: entity.key },
              {
                onSuccess: (more) => toast({ tone: "ok", text: `${num(more.count)} events added to the timeline` }),
                onError: (error) => toastError(error, "Extend failed"),
              },
            )
          }
        >
          Extend timeline
        </Button>
      ) : null}
    </>
  );
}
