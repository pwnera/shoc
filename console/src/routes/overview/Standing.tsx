/**
 * Where things stand: one fact per area, each the word its own screen holds
 * and a link to it, so a quiet Overview still shows sources delivering, rules
 * running and no case open. No state word: the heading above is the state.
 * The crew has none here: the top bar's pulse holds it and "Crew down" takes
 * the heading. Response in dry run is a fact of its own, in warn, until it acts.
 *
 * Capabilities used: source.list, health.sources, ops.alerts (Connections'
 * delivery words), health.status (rules), case.list and policy.show.
 */
import { Strip, type StripFact } from "@/components/ui/strip";
import { useCaseLog, useHealth, usePolicy } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import { useSourceState } from "../connections/state";

/** Delivery words that are trouble while another source delivers; with none delivering, every word is. */
const TROUBLE = new Set(["failing", "late", "no credential"]);

export function Standing() {
  const delivery = useSourceState();
  const health = useHealth();
  const cases = useCaseLog();
  const policy = usePolicy();

  const words = delivery.configured.map((row) => ({ source: row.source, word: delivery.state(row) }));
  const delivering = words.filter((w) => w.word === "delivering").length;
  const failing = words.some((w) => w.word === "failing");
  const troubled = words.filter((w) => w.word !== "delivering" && (!delivering || TROUBLE.has(w.word)));
  const rules = health.data?.rules;
  const open = (cases.data?.rows ?? []).filter((row) => row.state !== "closed");
  const critical = open.some((row) => row.severity === "critical");
  // The effective mode (SHOC_DRY_RUN, else the policy file), as Response's strip reads it.
  const dry = policy.data?.data.defaults.dry_run === true;

  const facts: StripFact[] = [
    {
      label: "sources",
      value: `${delivering} of ${delivery.configured.length}`,
      tone: failing || !words.length ? "bad" : troubled.length ? "warn" : undefined,
      to: "/connections",
      tip: troubled.map((w) => `${sourceName(w.source)} ${w.word}`).join(", ") || undefined,
    },
    rules?.failing
      ? { label: "rules failing", value: rules.failing, tone: "bad", to: "/detection?state=failing" }
      : { label: "rules", value: rules?.tracked, to: "/detection" },
    { label: "open cases", value: open.length, tone: critical ? "bad" : undefined, to: "/cases" },
    ...(dry ? [{ label: "response", value: "dry run", tone: "warn" as const, to: "/response?tab=autonomy" }] : []),
  ];

  return (
    <Strip
      stateless
      facts={facts}
      loading={delivery.pending || health.isPending || cases.isPending}
      error={delivery.error ?? (health.isLoadingError ? health.error : cases.isLoadingError ? cases.error : undefined)}
      onRetry={() => void Promise.all([delivery.list.refetch(), delivery.health.refetch(), health.refetch(), cases.refetch()])}
    />
  );
}
