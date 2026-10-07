/**
 * Connections: is every product delivering good data and can shoc act on it,
 * and what else should I connect? Everything shoc reaches out to has its one
 * home here (D124). The strip answers the first, per product as the list
 * counts them (delivering, late or failing, silent, the lowest quality, the
 * products shoc cannot act on); the tabs split the products (logs and
 * response side by side), the intel sources, the services shoc runs on, data
 * quality per product, and what shoc treats as its own. Every dialog lives in
 * the URL: `?vendor=&source=&credential=&view=` a product (`?source=` or
 * `?credential=` alone finds its product), `?add=new` the catalog
 * (`?add=<connector>` its connect form), `?tab=quality&product=` a product's
 * quality, where Ops alerts land, `?feed=`, `?lookup=`, `?add=intel` and
 * `?service=&view=` on their tabs.
 *
 * Capabilities used: source.list, health.sources, ops.alerts (a source
 * failing), health.quality, health.cost and events.summarize (volume),
 * credential.list, rule.list (catalog counts), source.onboard (behind a
 * confirm), and through the tabs and dialogs the rest.
 */
import { useLayoutEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Empty, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Confirm, MenuList, Popover } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Strip, type StripFact } from "@/components/ui/strip";
import { useCommand, useTabKeys } from "@/lib/commands";
import { count, percent } from "@/lib/format";
import { useParam, useTab } from "@/lib/param";
import { closeParams, focusRow } from "@/lib/popup";
import { useCredentials, useIndicators, useOnboardSources, useOwn } from "@/lib/queries";
import { connectorOf } from "@/lib/sources";
import type { SourceQuality } from "@/types";
import { Catalog } from "./connections/Catalog";
import { Footprint } from "./connections/Footprint";
import { IntelSources } from "./connections/IntelSources";
import { ProductDialog } from "./connections/ProductDialog";
import { product as emptyProduct, productOf, products, responseState, sortProducts, viewsOf } from "./connections/products";
import { Products } from "./connections/Products";
import { Quality } from "./connections/Quality";
import { QualityDialog } from "./connections/QualityDialog";
import { Services } from "./connections/Services";
import { useQualityRows, useSourceState, VIEWS, worstDelivery, type View } from "./connections/state";

const TABS = ["products", "intel", "services", "quality", "footprint"] as const;

export function Connections() {
  const model = useSourceState();
  const list = model.list;
  const credentials = useCredentials();
  const intel = useIndicators("", "", 1);
  const { quality, volume, rows: scored } = useQualityRows();
  const own = useOwn();
  const onboard = useOnboardSources();
  const [tab, setTab] = useTab(TABS);
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [only, setOnly] = useParam("state");
  // `?add=intel` is the Intel tab's own Add intel source.
  const add = params.get("add") === "intel" ? "" : (params.get("add") ?? "");
  const productParam = params.get("product") ?? "";
  const asked = params.get("view") ?? "";

  /**
   * Set and drop parameters in one history step. A palette hand-off's `do` goes
   * too: this write lands on the same snapshot as useCommand's own removal of it.
   */
  const edit = (change: Record<string, string | null>, push = false) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.delete("do");
        for (const [k, v] of Object.entries(change)) {
          if (v) out.set(k, v);
          else out.delete(k);
        }
        return out;
      },
      { replace: !push },
    );

  const configured = model.configured;
  const all = products(configured, credentials.data);
  const logs = (p: (typeof all)[number]) => worstDelivery(p.sources.map(model.state));
  // The strip counts what the list shows: products, each by its worst source.
  const read = all.filter((p) => p.sources.length);
  const n = (word: string) => read.filter((p) => logs(p) === word).length;
  const cannot = all.filter((p) => (responseState(p) ?? "connected") !== "connected");
  const listed = sortProducts(
    only === "cannot act" ? cannot : only ? all.filter((p) => only.split(",").includes(logs(p))) : all,
    logs,
  );

  // The product a link names: by vendor, by one of its sources, or by one of its credentials.
  const sourceParam = params.get("source") ?? "";
  const credentialParam = params.get("credential") ?? "";
  const bySource = configured.find((s) => s.source === sourceParam);
  const byCredential = credentials.data?.configured.find((c) => c.name === credentialParam);
  const vendor =
    params.get("vendor") ||
    (bySource ? productOf(bySource) : "") ||
    (byCredential && byCredential.provider !== "notify" ? byCredential.provider : "");
  const at = listed.findIndex((p) => p.key === vendor);
  const picked = at >= 0 ? listed[at] : all.find((p) => p.key === vendor) ?? (vendor && credentials.data ? emptyProduct(vendor, credentials.data) : undefined);
  const steps = at >= 0 ? listed : picked ? [picked] : [];
  const pickedAt = picked ? steps.indexOf(picked) : -1;
  const source = picked?.sources.find((s) => s.source === sourceParam) ?? picked?.sources[0];
  const views = picked ? viewsOf(picked) : [];
  const view: View = (VIEWS as readonly string[]).includes(asked) && views.includes(asked as View) ? (asked as View) : (views[0] ?? "delivery");

  const openProduct = (key: string, v?: string, s?: string) =>
    edit({ vendor: key, source: s ?? null, credential: null, view: v && v !== "delivery" ? v : null }, true);
  const openAdd = (connector = "new") => edit({ add: connector }, !add);
  // Closing hands focus to the row of the record shown, which J and K may have moved.
  const closeProduct = () => {
    closeParams(["vendor", "source", "credential", "view"], navigate);
    focusRow(vendor);
  };
  const closeQuality = () => {
    closeParams(["product"], navigate);
    focusRow(productParam);
  };

  useCommand("sources.add", () => openAdd(), tab === "products");
  // The menu, the palette and `?do=` open one confirm; only its Work starts the Integrator.
  const [menu, setMenu] = useState(false);
  const [asking, setAsking] = useState(false);
  useCommand("sources.onboard-all", () => {
    setAsking(true);
    setMenu(true);
  });
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));

  // A connected connector opens its own Settings: a blank connect form would replace them.
  // `cloudflare:2` is a second account, so only a bare name stands for any account.
  const live =
    configured.find((row) => row.source === add) ??
    (add.includes(":") ? undefined : configured.find((row) => connectorOf(row.source) === add));
  const loaded = Boolean(list.data);
  useLayoutEffect(() => {
    if (live) edit({ add: null, vendor: productOf(live), source: live.source, view: "settings" });
    // Only when the link is followed: a connector connected from the catalog a moment ago stays in its form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [add, loaded]);

  const failing = n("failing");
  const late = n("late");
  // A quiet push product and a low-volume one are not silent (`shownVolume`), so the strip agrees with the rows.
  const silenced = volume.data ? scored.filter((q) => volume.of(q.product)?.mark === "silent") : null;
  const silent = silenced ? silenced.length : null;
  const worst = scored.reduce<SourceQuality | undefined>((w, q) => (w && w.score <= q.score ? w : q), undefined);
  const word =
    failing > 0
      ? { tone: "bad" as const, word: "Failing" }
      : late > 0
        ? { tone: "warn" as const, word: "Late" }
        : silent
          ? { tone: "warn" as const, word: "Silent" }
          : configured.length
            ? { tone: "good" as const, word: "Delivering" }
            : all.length
              ? { tone: "idle" as const, word: "No logs" }
              : { tone: "idle" as const, word: "Nothing connected" };
  const filterTo = (state: string) => ({
    onClick: () => {
      setOnly(only === state ? "" : state);
      if (tab !== "products") setTab("products");
    },
    pressed: only === state,
  });
  const facts: StripFact[] = [
    { label: "delivering", value: `${n("delivering")} of ${read.length}`, ...filterTo("delivering") },
    // One fact for both, so the strip's five keep room for what shoc cannot act on.
    {
      label: "late or failing",
      value: late + failing,
      tone: failing ? "bad" : late ? "warn" : undefined,
      ...filterTo("failing,late"),
    },
    {
      label: "silent",
      value: volume.isError && !volume.data ? null : volume.isPending ? <Skel kind="fact" /> : silent,
      tone: silent ? "warn" : undefined,
      // One silent product opens its quality; several lead the Quality tab.
      to: silenced?.length === 1 ? `?tab=quality&product=${encodeURIComponent(silenced[0]!.product)}` : "?tab=quality",
      tip: "Nothing in 24 hours from a product that usually sends five or more a day",
    },
    {
      label: "lowest quality",
      value: quality.isLoadingError ? null : worst ? percent(worst.score) : quality.isPending ? <Skel kind="fact" /> : null,
      tone: worst && worst.score < 0.5 ? "bad" : worst && worst.score < 0.8 ? "warn" : undefined,
      to: worst ? `?tab=quality&product=${encodeURIComponent(worst.product)}` : undefined,
      tip: worst?.product,
    },
    {
      label: "cannot act",
      value: credentials.isLoadingError ? null : credentials.data ? cannot.length : <Skel kind="fact" />,
      tone: cannot.length ? "warn" : undefined,
      tip: "Not connected, incomplete, refused or not covered",
      ...filterTo("cannot act"),
    },
  ];
  const known = new Set([...(list.data?.available ?? []), ...(list.data?.push_only ?? [])]);
  const qualityAt = scored.findIndex((row) => row.product === productParam);
  const step = (to: number) => () => edit({ vendor: steps[to]!.key, source: null, credential: null });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Connections"
        aside={
          <Popover
            menu
            align="end"
            open={menu}
            onOpenChange={(now) => {
              setMenu(now);
              if (!now) setAsking(false);
            }}
            trigger={(props) => (
              <Button {...props} variant="ghost" size="icon" aria-label="More">
                <MoreHorizontal aria-hidden />
              </Button>
            )}
          >
            {(close) =>
              asking ? (
                <Confirm
                  what={list.data ? `Work every source · ${count(configured.length, "source")}` : "Work every source"}
                  go="Work"
                  onCancel={() => setAsking(false)}
                  onConfirm={() => onboard.mutateAsync(undefined).then(close)}
                />
              ) : (
                <MenuList
                  label="Connections actions"
                  close={close}
                  items={[
                    {
                      label: "Let the Integrator work every source",
                      keepOpen: true,
                      disabled: onboard.isPending,
                      onSelect: () => setAsking(true),
                    },
                  ]}
                />
              )
            }
          </Popover>
        }
        strip={
          <Strip
            state={word}
            facts={facts}
            loading={model.pending}
            error={model.error}
            onRetry={() => void Promise.all([model.list.refetch(), model.health.refetch()])}
            asOf={model.asOf}
          />
        }
      />

      <Tabs
        id="connections"
        label="Connections"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "products", label: "Products", count: list.data && credentials.data ? all.length : null },
          {
            value: "intel",
            label: "Intel",
            count: intel.data ? (intel.data.feeds?.length ?? 0) + (intel.data.lookups ?? []).filter((l) => l.configured).length : null,
          },
          { value: "services", label: "Services" },
          { value: "quality", label: "Quality", count: quality.data ? scored.length : null },
          { value: "footprint", label: "shoc's own", count: own.data ? own.data.rows.length : null },
        ]}
      />
      <TabPanel id="connections" value={tab}>
        <Card>
          {tab === "products" ? (
            <Products
              rows={listed}
              current={vendor}
              filtered={Boolean(only)}
              loading={model.pending || credentials.isPending}
              error={model.error ?? (credentials.isLoadingError ? credentials.error : undefined)}
              onRetry={() => void Promise.all([model.list.refetch(), model.health.refetch(), credentials.refetch()])}
              onOpen={openProduct}
              onAdd={() => openAdd()}
              onClear={() => setOnly("")}
            />
          ) : tab === "intel" ? (
            <IntelSources />
          ) : tab === "services" ? (
            <Services />
          ) : tab === "quality" ? (
            <Quality current={productParam} onOpen={(p) => edit({ product: p }, true)} />
          ) : (
            <Footprint />
          )}
        </Card>
      </TabPanel>

      {picked ? (
        <ProductDialog
          product={picked}
          source={source}
          credentials={credentials.data}
          view={view}
          onView={(v) => edit({ view: v === views[0] ? null : v })}
          onSource={(s) => edit({ source: s })}
          step={{
            index: pickedAt,
            total: steps.length,
            onPrev: pickedAt > 0 ? step(pickedAt - 1) : undefined,
            onNext: pickedAt < steps.length - 1 ? step(pickedAt + 1) : undefined,
          }}
          onClose={closeProduct}
        />
      ) : sourceParam && list.data && known.has(connectorOf(sourceParam)) ? (
        // Not connected yet (a credentials link from the Integrator): its connect form.
        <Catalog connector={sourceParam} onPick={(c) => edit({ source: null, view: null, add: c })} onClose={() => closeParams(["source", "view"], navigate)} />
      ) : (sourceParam || (credentialParam && !params.get("service"))) && list.data && credentials.data ? (
        <Dialog title={sourceParam || credentialParam} size="sm" onClose={() => closeParams(["source", "credential", "view"], navigate)}>
          <Empty kind="page" title="No such connection" />
        </Dialog>
      ) : null}

      {add ? <Catalog connector={add} onPick={(c) => edit({ add: c }, true)} onClose={() => closeParams(["add"], navigate)} /> : null}

      {productParam && qualityAt >= 0 ? (
        <QualityDialog
          row={scored[qualityAt]!}
          step={{
            index: qualityAt,
            total: scored.length,
            onPrev: qualityAt > 0 ? () => edit({ product: scored[qualityAt - 1]!.product }) : undefined,
            onNext: qualityAt < scored.length - 1 ? () => edit({ product: scored[qualityAt + 1]!.product }) : undefined,
          }}
          onClose={closeQuality}
        />
      ) : productParam && quality.data ? (
        <Dialog title={productParam} size="sm" onClose={() => closeParams(["product"], navigate)}>
          <Empty kind="page" title="Not scored in 30 days" />
        </Dialog>
      ) : null}
    </div>
  );
}
