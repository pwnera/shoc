/**
 * What the rule sees and what answers it: its ATT&CK techniques under their
 * tactics, the rule, and every playbook whose `rules` include it. The graph
 * draws the links; under it each playbook lists its steps with the autonomy
 * the policy gives them, so the same facts are rows too. A technique opens
 * ATT&CK; a playbook, and each of its steps, its page.
 *
 * Capabilities used: playbook.list, policy.show.
 */
import { Link, useNavigate } from "react-router-dom";
import { Card, CardHeader } from "@/components/ui/card";
import { Graph } from "@/components/ui/graph";
import { ErrorNote } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { AutonomyBadge } from "@/components/ui/status";
import { attackUrl, tacticLabel, tacticsOf, TACTICS, TACTIC_SHORT } from "@/lib/attack";
import { actionLabel } from "@/lib/labels";
import { usePlaybooks, usePolicy } from "@/lib/queries";
import type { Playbook, Rule } from "@/types";

type Node = { id: string; kind: string; label: string; href?: string; to?: string; name: string; weight: number };
type Edge = { src: string; dst: string; label?: string };

const LANES = ["technique", "rule", "step"] as const;
const LANE_LABEL: Record<string, string> = { technique: "ATT&CK", rule: "RULE", step: "PLAYBOOK" };
/** Node pitch: a 16px box, its label and air. */
const PITCH = 44;

const ORDER = new Map<string, number>(TACTICS.map(([id], i) => [id, i] as const));

/**
 * One node per technique, in kill-chain order of its first tactic, so the
 * techniques of a tactic sit together, labelled by its id with its tactics on
 * its edge (in the edge's tip where they would not fit); the rule in the
 * middle (the lane names it, so its node has no label); a node per playbook,
 * unlabelled too, since its title heads the list under the graph. Equal small
 * weights keep every box 16px.
 */
function graph(rule: Rule, books: Playbook[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [{ id: "rule", kind: "rule", label: "", name: `rule ${rule.title}`, weight: 1 }];
  const edges: Edge[] = [];
  const techniques = [...new Set(rule.attack)]
    .map((technique) => ({ technique, tactics: tacticsOf([technique]) }))
    .sort((a, b) => (ORDER.get(a.tactics[0] ?? "") ?? 99) - (ORDER.get(b.tactics[0] ?? "") ?? 99));
  for (const { technique, tactics } of techniques) {
    const id = `t:${technique}`;
    nodes.push({
      id,
      kind: "technique",
      label: technique,
      href: attackUrl(technique),
      name: `technique ${technique}${tactics.length ? `, ${tactics.map(tacticLabel).join(", ")}` : ""}`,
      weight: 0,
    });
    edges.push({ src: id, dst: "rule", label: tactics.map((t) => TACTIC_SHORT[t]).join("·") || undefined });
  }
  for (const book of books) {
    nodes.push({
      id: `p:${book.id}`,
      kind: "step",
      label: "",
      to: `/response/playbooks/${book.id}`,
      name: `playbook ${book.title}`,
      weight: 0,
    });
    edges.push({ src: "rule", dst: `p:${book.id}` });
  }
  return { nodes, edges };
}

export function Relations({ rule }: { rule: Rule }) {
  const navigate = useNavigate();
  const playbooks = usePlaybooks();
  const policy = usePolicy();
  const books = (playbooks.data?.playbooks ?? []).filter((p) => p.rules?.includes(rule.id));
  const { nodes, edges } = graph(rule, books);
  const tall = Math.max(...LANES.map((lane) => nodes.filter((n) => n.kind === lane).length));
  // The edges say tactics by their two letters; this line names them, as the tactics strip does.
  const used = tacticsOf(rule.attack).sort((a, b) => (ORDER.get(a) ?? 99) - (ORDER.get(b) ?? 99));
  const autonomy = (action: string) =>
    String(policy.data?.data.actions[action]?.autonomy ?? policy.data?.data.defaults.autonomy ?? "");

  return (
    <Card aria-label="Relations">
      <CardHeader title="Relations" />
      {playbooks.isError && !playbooks.data ? (
        <ErrorNote error={playbooks.error} onRetry={() => void playbooks.refetch()} />
      ) : (
        <Graph
          label="Techniques, the rule and its playbooks"
          layout="layered"
          nodes={nodes}
          edges={edges}
          lanes={LANES}
          laneLabel={(lane) => LANE_LABEL[lane] ?? lane}
          focus="rule"
          // Lane names, two pads, and a pitch per row: every node shows, none hides behind "+N".
          height={Math.max(96, 16 + 48 + (tall - 1) * PITCH)}
          perLane={tall}
          name={(n) => n.name}
          onOpen={(n) => {
            if (n.href) window.open(n.href, "_blank", "noopener");
            else if (n.to) navigate(n.to);
          }}
        />
      )}
      {used.length ? (
        <p className="sh-mono m-0 px-3 pb-2">{used.map((t) => `${TACTIC_SHORT[t]} ${tacticLabel(t)}`).join(" · ")}</p>
      ) : null}
      <div className="flex flex-col gap-3 border-t border-line-1 p-3">
        {playbooks.isPending ? (
          <Skel kind="row" width="70%" />
        ) : playbooks.isError && !playbooks.data ? null : books.length ? (
          books.map((book) => (
            <div key={book.id} className="flex min-w-0 flex-col gap-1">
              <Link to={`/response/playbooks/${book.id}`} className="sh-link truncate font-medium">
                {book.title}
              </Link>
              <ul className="m-0 flex list-none flex-col p-0">
                {book.steps.map((step, i) => (
                  <li key={`${step.action}-${i}`}>
                    <Link
                      to={`/response/playbooks/${book.id}`}
                      className="-mx-1 flex min-w-0 items-center gap-2 rounded-[var(--radius-1)] px-1 py-0.5 no-underline hover:bg-bg-2"
                    >
                      <span className="h-px w-2 shrink-0 bg-line-2" aria-hidden />
                      <span className={step.optional ? "truncate text-fg-3" : "truncate text-fg-2"}>{actionLabel(step.action)}</span>
                      <span className="ml-auto shrink-0">
                        {policy.isPending ? <Skel kind="badge" /> : <AutonomyBadge level={autonomy(step.action)} />}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))
        ) : (
          <span className="sh-mono">No playbook answers this rule</span>
        )}
      </div>
    </Card>
  );
}
