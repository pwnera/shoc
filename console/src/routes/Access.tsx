/**
 * Access: who signs in or holds a key, what each may call, and who called
 * what? The strip reads the audit chain (intact or broken), how many
 * capabilities need a person, and how many rows the chain verified (the Audit
 * pager leaves the total to it). Tabs split the people who sign in (RFC 0028),
 * the live tokens, the registry and the audit log; the tab, each tab's filters and
 * an open capability (`?cap=&view=`) live in the URL. Changing tabs drops the
 * last tab's filters, and each tab keeps its own: Capabilities filters on who
 * may call (`caller`), Audit on who called (`principal`).
 *
 * Capabilities used: capability.list, user.list, token.list, health.audit;
 * in the People tab user.invite, user.reset, user.update, sso.show and
 * sso.configure; in the Tokens tab token.create and token.revoke.
 */
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Empty, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Strip } from "@/components/ui/strip";
import { useTabKeys } from "@/lib/commands";
import { AUTONOMY } from "@/lib/labels";
import { useTab } from "@/lib/param";
import { closeParams, focusRow } from "@/lib/popup";
import { useAudit, useCapabilities, useTokens, useUsers } from "@/lib/queries";
import { Audit } from "./access/Audit";
import { CapabilityDialog, VIEWS, type View } from "./access/CapabilityDialog";
import { useRegistryRows } from "./access/parts";
import { People } from "./access/People";
import { Registry } from "./access/Registry";
import { Tokens } from "./access/Tokens";

const TABS = ["people", "tokens", "capabilities", "audit"] as const;
type Tab = (typeof TABS)[number];
/* Every tab's filter parameters, dropped when the tab changes: People's, the registry's, Audit's. */
const FILTERS = ["pq", "role", "state", "q", "caller", "autonomy", "audited", "aq", "principal", "errors", "area"];

export function Access() {
  const [tab] = useTab(TABS);
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const registry = useCapabilities();
  const users = useUsers();
  const tokens = useTokens();
  const audit = useAudit({ limit: 200 });

  const capabilities = registry.data?.capabilities ?? [];
  // A failed refresh keeps the strip's last answer, as of its time.
  const stale = [audit, registry].filter((q) => q.isRefetchError);
  const asOf = stale.length ? new Date(Math.min(...stale.map((q) => q.dataUpdatedAt))).toISOString() : null;
  const { filters, rows } = useRegistryRows(capabilities);
  const human = capabilities.filter((c) => c.autonomy === "L2").length;
  const cap = params.get("cap") ?? "";
  const asked = params.get("view") ?? "";
  const view: View = (VIEWS as readonly string[]).includes(asked) ? (asked as View) : "signature";
  const autonomy = params.get("autonomy") ?? "";
  const set = (change: Record<string, string | null>, push = false) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        for (const [k, v] of Object.entries(change)) {
          if (v) out.set(k, v);
          else out.delete(k);
        }
        return out;
      },
      { replace: !push },
    );
  const drop = Object.fromEntries(FILTERS.map((k) => [k, null]));
  const switchTab = (next: Tab) => set({ ...drop, tab: next === "people" ? null : next }, true);
  useTabKeys(TABS.length, (i) => switchTab(TABS[i]!));

  // The dialog steps through the list as the registry shows it, filtered and sorted.
  const at = rows.findIndex((c) => c.name === cap);
  const picked = rows[at] ?? capabilities.find((c) => c.name === cap);
  const steps = at >= 0 ? rows : picked ? [picked] : [];
  const pickedAt = picked ? steps.indexOf(picked) : -1;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Access"
        strip={
          <Strip
            state={
              audit.data
                ? audit.data.chain_ok
                  ? { tone: "good", word: "Intact" }
                  : { tone: "bad", word: "Broken" }
                : undefined
            }
            loading={audit.isPending}
            error={audit.isLoadingError ? audit.error : undefined}
            onRetry={() => void audit.refetch()}
            asOf={asOf}
            facts={[
              {
                // The badge's own word, as Response › Autonomy counts it ("3 you").
                label: AUTONOMY.L2,
                value: registry.isLoadingError ? null : registry.data ? human : undefined,
                pressed: tab === "capabilities" && autonomy === "L2",
                // The fact's own list: every L2 capability, no other filter.
                onClick: () =>
                  set(tab === "capabilities" && autonomy === "L2" ? { autonomy: null } : { ...drop, tab: "capabilities", autonomy: "L2" }),
              },
              { label: "verified", value: audit.data?.rows_verified, to: "?tab=audit" },
            ]}
          />
        }
      />
      <Tabs
        id="access"
        label="Access"
        value={tab}
        onChange={switchTab}
        tabs={[
          { value: "people", label: "People", count: users.data ? users.data.users.length : null },
          { value: "tokens", label: "Tokens", count: tokens.data ? tokens.data.tokens.length : null },
          { value: "capabilities", label: "Capabilities", count: registry.data ? capabilities.length : null },
          { value: "audit", label: "Audit" },
        ]}
      />
      <TabPanel id="access" value={tab}>
        {tab === "capabilities" ? (
          <Registry
            query={registry}
            filters={filters}
            rows={rows}
            current={cap}
            onOpen={(name) => set({ cap: name, view: null }, true)}
          />
        ) : (
          <Card>{tab === "people" ? <People /> : tab === "tokens" ? <Tokens /> : <Audit />}</Card>
        )}
      </TabPanel>
      {cap && picked ? (
        <CapabilityDialog
          // One mount per record, so a dialog the browser closed never lingers behind a live `?cap=`.
          key={cap}
          capability={picked}
          view={view}
          onView={(v) => set({ view: v === "signature" ? null : v })}
          calls={audit.data?.recent ?? []}
          callsPending={audit.isPending}
          step={{
            index: pickedAt,
            total: steps.length,
            onPrev: pickedAt > 0 ? () => set({ cap: steps[pickedAt - 1]!.name }) : undefined,
            onNext: pickedAt < steps.length - 1 ? () => set({ cap: steps[pickedAt + 1]!.name }) : undefined,
          }}
          onClose={() => {
            closeParams(["cap", "view"], navigate);
            focusRow(cap);
          }}
        />
      ) : cap && registry.data ? (
        <Dialog title={cap} size="sm" onClose={() => closeParams(["cap", "view"], navigate)}>
          <Empty kind="page" title="No such capability" />
        </Dialog>
      ) : null}
    </div>
  );
}
