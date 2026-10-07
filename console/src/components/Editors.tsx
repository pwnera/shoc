/**
 * The three editors, each a MergeDialog: a rule (or the narrowing of the rule
 * a backlog item names), a hunt pack, a playbook. A new rule hands its cases
 * to a playbook picked from those that exist, the ones already answering the
 * rule's product first; Check waits until one is picked, the gate refuses one
 * that cannot act on it, and the ADS response defaults to it. A backlog item
 * seeds what it already says (techniques, product, a narrowing's events). A
 * passing check names rules, packs and playbooks by their titles.
 *
 * Capabilities used: detection.merge, hunt.merge, playbook.merge,
 * playbook.list, rule.list, hunt.results.
 */
import { useState } from "react";
import { productName } from "@/components/brands";
import { MergeDialog } from "@/components/MergeDialog";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/misc";
import {
  NARROWING_SECTIONS,
  PACK_SECTIONS,
  packFacts,
  PLAYBOOK_SECTIONS,
  playbookFacts,
  RULE_SECTIONS,
  ruleFacts,
  seeded,
  type Names,
} from "@/lib/merge";
import { usePlaybooks, useRules } from "@/lib/queries";
import { useTitles } from "@/routes/detection/state";

type Data = Record<string, unknown>;

/** The rule's logsource.product as the Rule tab parses now, or "". */
function productOf(doc: Data): string {
  const rule = (doc.rule ?? {}) as { logsource?: { product?: unknown } };
  return typeof rule.logsource?.product === "string" ? rule.logsource.product.toLowerCase() : "";
}

/** Titles for a passing check's rows, from the lists the console already holds. */
function useNames(): Names {
  const titles = useTitles();
  const playbooks = usePlaybooks();
  return {
    rule: (id) => titles(id).title ?? id,
    playbook: (id) => playbooks.data?.playbooks.find((b) => b.id === id)?.title ?? id,
  };
}

function PlaybookPick({
  value,
  onChange,
  product,
  error,
}: {
  value: string;
  onChange: (id: string) => void;
  product: string;
  error: string | null;
}) {
  const playbooks = usePlaybooks();
  const rules = useRules();
  const productBy = new Map((rules.data?.rules ?? []).map((r) => [r.id, r.logsource.product ?? ""]));
  const books = [...(playbooks.data?.playbooks ?? [])].sort((a, b) => a.title.localeCompare(b.title));
  const answers = (id: string) => books.find((b) => b.id === id)?.rules.some((r) => productBy.get(r) === product) ?? false;
  const near = product ? books.filter((b) => answers(b.id)) : [];
  const rest = books.filter((b) => !near.includes(b));
  const option = (b: (typeof books)[number]) => (
    <option key={b.id} value={b.id}>
      {b.title}
    </option>
  );
  return (
    <Field label="Playbook" error={error ?? undefined}>
      <Select value={value} onChange={(event) => onChange(event.target.value)} disabled={playbooks.isPending}>
        <option value="">{playbooks.isPending ? "Loading…" : "Pick the playbook that answers it"}</option>
        {near.length ? <optgroup label={`Answers ${productName(product)}`}>{near.map(option)}</optgroup> : null}
        {near.length ? <optgroup label="Others">{rest.map(option)}</optgroup> : rest.map(option)}
      </Select>
    </Field>
  );
}

export function RuleEditor({
  itemUid,
  narrows,
  seed,
  onClose,
}: {
  itemUid?: string;
  /** A shipped rule the backlog item names: narrow it instead of adding one. */
  narrows?: string;
  /** What the item already says: the Rule tab's `id`, `title`, `attack` and `product`, or a narrowing's `hide_events`. */
  seed?: Data;
  onClose: () => void;
}) {
  const [playbook, setPlaybook] = useState("");
  const names = useNames();
  const item = itemUid ? { item_uid: itemUid } : {};
  const events = seed?.hide_events;
  if (narrows)
    return (
      <MergeDialog
        title={`Narrow ${names.rule(narrows)}`}
        capability="detection.merge"
        sections={seeded(NARROWING_SECTIONS, "hide_events", Array.isArray(events) ? events : [])}
        reasonExample="The nightly backup job, confirmed in its case"
        extra={{ narrows, ...item }}
        facts={(d) => ruleFacts(d, names)}
        onClose={onClose}
      />
    );
  return (
    <MergeDialog
      title="New rule"
      capability="detection.merge"
      sections={seed ? seeded(RULE_SECTIONS, "rule", { ...seed, hide_events: undefined }) : RULE_SECTIONS}
      reasonExample="Nothing catches the Okta audit feed being cut"
      extra={{ ...(playbook ? { playbook_id: playbook } : {}), ...item }}
      head={(doc, error) => <PlaybookPick value={playbook} onChange={setPlaybook} product={productOf(doc)} error={error} />}
      missing={() => (playbook ? null : "Pick a playbook")}
      facts={(d) => ruleFacts(d, names)}
      onClose={onClose}
    />
  );
}

export function PackEditor({ itemUid, seed, onClose }: { itemUid?: string; seed?: Data; onClose: () => void }) {
  const names = useNames();
  return (
    <MergeDialog
      title="New pack"
      capability="hunt.merge"
      sections={seed ? seeded(PACK_SECTIONS, "pack", seed) : PACK_SECTIONS}
      reasonExample="No check for first-time policy changes by an admin"
      extra={itemUid ? { item_uid: itemUid } : {}}
      facts={(d) => packFacts(d, names)}
      onClose={onClose}
    />
  );
}

export function PlaybookEditor({ onClose }: { onClose: () => void }) {
  const names = useNames();
  return (
    <MergeDialog
      title="New playbook"
      capability="playbook.merge"
      sections={PLAYBOOK_SECTIONS}
      reasonExample="Audit tampering gets its own containment"
      facts={(d) => playbookFacts(d, names)}
      onClose={onClose}
    />
  );
}
