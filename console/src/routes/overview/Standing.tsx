/**
 * Where things stand: one fact per area, each the word its own screen holds
 * and a link to it, so a quiet Overview still shows sources delivering, rules
 * running and no case open. No state word: the heading above is the state.
 * The crew has none here: the top bar's pulse holds it and "Crew down" takes
 * the heading.
 *
 * Capabilities used: source.list, health.sources, ops.alerts (Connections'
 * delivery words), health.status (rules) and case.list.
 */
import { Strip, type StripFact } from "@/components/ui/strip";
import { useCaseLog, useHealth } from "@/lib/queries";
import { sourceName } from "@/lib/sources";
import { useSourceState } from "../connections/state";

export function Standing() {
  const delivery = useSourceState();
  const health = useHealth();
  const cases = useCaseLog();

  const words = delivery.configured.map((row) => ({ source: row.source, word: delivery.state(row) }));
  const delivering = words.filter((w) => w.word === "delivering").length;
  const failing = words.some((w) => w.word === "failing");
  const troubled = words.filter((w) => w.word === "failing" || w.word === "late");
  const rules = health.data?.rules;
  const open = (cases.data?.rows ?? []).filter((row) => row.state !== "closed");
  const critical = open.some((row) => row.severity === "critical");

  const facts: StripFact[] = [
    {
      label: "sources",
      value: `${delivering} of ${delivery.configured.length}`,
      tone: failing ? "bad" : troubled.length ? "warn" : undefined,
      to: "/connections",
      tip: troubled.map((w) => `${sourceName(w.source)} ${w.word}`).join(", ") || undefined,
    },
    rules?.failing
      ? { label: "rules failing", value: rules.failing, tone: "bad", to: "/detection?state=failing" }
      : { label: "rules", value: rules?.tracked, to: "/detection" },
    { label: "open cases", value: open.length, tone: critical ? "bad" : undefined, to: "/cases" },
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
