/**
 * What the Access tabs share: the four kinds of caller, a capability's area, the
 * registry's filters and order (the list and its dialog step through the same
 * rows).
 */
import { Bot, Plug, Server, User, type LucideIcon } from "lucide-react";
import { useFilters, type Dim } from "@/lib/filters";
import { principalWord } from "@/lib/labels";
import type { CapabilityDoc } from "@/types";

export const PRINCIPALS: { id: string; label: string; icon: LucideIcon }[] = [
  { id: "human", label: principalWord("human"), icon: User },
  { id: "agent", label: principalWord("agent"), icon: Bot },
  { id: "external_agent", label: principalWord("external_agent"), icon: Plug },
  { id: "service", label: principalWord("service"), icon: Server },
];

/** "action" for action.approve. */
export const areaOf = (name: string) => name.split(".")[0] ?? name;

export const CAPABILITY_DIMS: Dim<CapabilityDoc>[] = [
  {
    // Not `principal`: Audit's filter on who called, a tab away.
    id: "caller",
    label: "caller",
    options: PRINCIPALS.map((p) => ({ value: p.id, label: p.label })),
    test: (c, v) => c.principals.includes(v),
  },
  {
    id: "autonomy",
    label: "autonomy",
    options: [
      { value: "L2", label: "you" },
      { value: "L0", label: "notify" },
    ],
    test: (c, v) => c.autonomy === v,
  },
  {
    id: "audited",
    label: "audited",
    options: [
      { value: "yes", label: "audited" },
      { value: "no", label: "not audited" },
    ],
    test: (c, v) => c.audit === (v === "yes"),
  },
];

/** The list as the registry shows it: filtered from the URL, by area then name. */
export function useRegistryRows(capabilities: CapabilityDoc[]) {
  const filters = useFilters(CAPABILITY_DIMS, {
    match: (c, text) => c.name.includes(text) || c.summary.toLowerCase().includes(text) || c.tags.some((t) => t.includes(text)),
  });
  const rows = capabilities
    .filter(filters.keep)
    .sort((a, b) => areaOf(a.name).localeCompare(areaOf(b.name)) || a.name.localeCompare(b.name));
  return { filters, rows };
}
