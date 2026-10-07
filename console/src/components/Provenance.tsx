/**
 * Where a rule or hunt was taken from, on one line ("Elastic ×3 · adapted ·
 * Elastic-2.0"); its popover lists each source with author, relation and
 * licence, linked, then the references. Sigma's licence (DRL 1.1) asks for the
 * author next to the link, so the popover always shows it.
 */
import type { RuleSource } from "@/types";
import { Popover } from "./ui/pop";

/** "Elastic ×3 · adapted · Elastic-2.0": the commonest origin, relation and licence. */
function line(sources: RuleSource[]): string {
  const counts = new Map<string, number>();
  for (const s of sources) counts.set(s.name, (counts.get(s.name) ?? 0) + 1);
  const names = [...counts].sort((a, b) => b[1] - a[1]).map(([name, n]) => (n > 1 ? `${name} ×${n}` : name));
  const relations = [...new Set(sources.map((s) => s.relation).filter(Boolean))];
  const licences = [...new Set(sources.map((s) => s.license).filter(Boolean))];
  return [names.join(", "), relations.join(", "), licences.join(", ")].filter(Boolean).join(" · ");
}

export function Provenance({ sources, references = [] }: { sources?: RuleSource[]; references?: string[] }) {
  if (!sources?.length && !references.length) return null;
  const all = sources ?? [];
  return (
    <Popover
      label="Provenance"
      pad
      trigger={(props) => (
        <button {...props} type="button" className="sh-link max-w-full truncate text-left font-mono text-xs">
          {all.length ? line(all) : `${references.length} references`}
        </button>
      )}
    >
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {all.map((s) => (
          <li key={s.url} className="flex min-w-0 flex-col gap-0.5">
            <a href={s.url} target="_blank" rel="noreferrer noopener" className="sh-link truncate">
              {s.name} · {s.title}
            </a>
            <span className="sh-mono">{[s.author, s.relation, s.license].filter(Boolean).join(" · ")}</span>
          </li>
        ))}
        {references.map((url) => (
          <li key={url} className="min-w-0">
            <a href={url} target="_blank" rel="noreferrer noopener" className="sh-link block truncate font-mono text-xs">
              {url}
            </a>
          </li>
        ))}
      </ul>
    </Popover>
  );
}
