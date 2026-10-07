/**
 * One capability: its signature (the summary as one line, scope, who may
 * call it, what it takes and returns as a typed tree), how to call it from
 * the CLI, over HTTP or from an agent (the required fields as placeholders),
 * and its recent calls among the last 200 audited. The view is the page's
 * `?view=`, so J and K keep it while they step.
 *
 * Capabilities used: capability.list (the row), health.audit (recent calls).
 */
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy } from "@/components/ui/field";
import { Empty, Label } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { AutonomyBadge } from "@/components/ui/status";
import { Tip } from "@/components/ui/tip";
import { apiBase } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { Step } from "@/lib/popup";
import type { AuditRow, CapabilityDoc, JsonSchema } from "@/types";
import { AuditTable } from "./Audit";
import { PRINCIPALS } from "./parts";

export const VIEWS = ["signature", "call", "recent"] as const;
export type View = (typeof VIEWS)[number];

/** `int | None` arrives as anyOf [integer, null]: the non-null half, with the field's doc. */
function plain(schema: JsonSchema): JsonSchema {
  const inner = schema.anyOf?.find((option) => option.type !== "null");
  return inner ? { ...inner, description: schema.description } : schema;
}

function typeOf(schema: JsonSchema): string {
  const s = plain(schema);
  if (s.enum?.length) return s.enum.map((v) => JSON.stringify(v)).join(" | ");
  if (s.type === "array") return `${s.items ? typeOf(s.items) : "unknown"}[]`;
  if (s.type === "integer") return "int";
  return s.type ?? (s.properties ? "object" : "unknown");
}

/** "name: type  required", nested objects indented; each field's doc in its tip. */
function Tree({ schema, depth = 0 }: { schema: JsonSchema; depth?: number }) {
  const s = plain(schema);
  const props = Object.entries(s.properties ?? (s.items ? plain(s.items).properties : undefined) ?? {});
  if (!props.length) return depth ? null : <Empty title="Nothing" />;
  return (
    <ul className={cn("m-0 flex list-none flex-col p-0 font-mono", depth && "ml-4 border-l border-line-1 pl-3")}>
      {props.map(([name, field]) => {
        const required = s.required?.includes(name);
        const line = (
          <span className="inline-flex min-h-6 items-baseline gap-1.5">
            <span className="text-fg-1">{name}</span>
            <span className="text-fg-4">:</span>
            <span className="text-fg-3">{typeOf(field)}</span>
            {required ? <span className="text-fg-4">required</span> : null}
          </span>
        );
        return (
          <li key={name}>
            {plain(field).description ? (
              <Tip label={plain(field).description}>
                <span tabIndex={0} className="inline-flex">
                  {line}
                </span>
              </Tip>
            ) : (
              line
            )}
            <Tree schema={field} depth={depth + 1} />
          </li>
        );
      })}
    </ul>
  );
}

const flag = (name: string) => `--${name.replace(/_/g, "-")}`;
const shellWord = (text: string) => (/^[\w.:@/+<>-]+$/.test(text) ? text : `'${text.replace(/'/g, "'\\''")}'`);

/** The three ways in, with the required fields as `<placeholders>`. */
function examples(c: CapabilityDoc): { cli: string; http: string; mcp: string } {
  const required = c.input_schema.required ?? [];
  const input = Object.fromEntries(required.map((name) => [name, `<${name}>`]));
  const lone = required.length === 1 && plain(c.input_schema.properties?.[required[0]!] ?? {}).type === "string";
  const cli = [c.cli, ...required.flatMap((name) => (lone ? [`<${name}>`] : [flag(name), `<${name}>`]))].join(" ");
  const http = `curl -X ${c.rest.method} ${apiBase}${c.rest.path} \\
  -H "Authorization: Bearer $SHOC_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d ${shellWord(JSON.stringify(input))}`;
  const mcp = JSON.stringify({ name: c.mcp_tool, arguments: input }, null, 2);
  return { cli, http, mcp };
}

export function CapabilityDialog({
  capability: c,
  view,
  onView,
  calls,
  callsPending,
  step,
  onClose,
}: {
  capability: CapabilityDoc;
  view: View;
  onView: (view: View) => void;
  calls: AuditRow[];
  callsPending: boolean;
  step?: Step;
  onClose: () => void;
}) {
  const mine = calls.filter((row) => row.capability === c.name);
  const ex = examples(c);
  return (
    <Dialog
      title={<span className="font-mono">{c.name}</span>}
      head={c.autonomy === "L2" ? <AutonomyBadge level="L2" /> : null}
      step={step}
      onClose={onClose}
    >
      <Seg
        label="View"
        className="self-start"
        value={view}
        onChange={onView}
        options={[
          { value: "signature", label: "Signature" },
          { value: "call", label: "Call" },
          { value: "recent", label: "Recent", count: callsPending ? undefined : mine.length },
        ]}
      />
      {view === "signature" ? (
        <>
          <p className="m-0 text-fg-2">{c.summary}</p>
          <Fields
            ruled
            rows={[
              ["Scope", <span className="sh-mono sh-mono--strong">{c.scope}</span>],
              [
                "Callers",
                <span className="inline-flex gap-2">
                  {PRINCIPALS.map(({ id, label, icon: Icon }) => {
                    const may = c.principals.includes(id);
                    return (
                      <Tip key={id} label={`${label}${may ? "" : ": not allowed"}`}>
                        <span
                          role="img"
                          aria-label={`${label}${may ? "" : ", not allowed"}`}
                          className={cn("inline-flex", may ? "text-fg-1" : "text-fg-4 opacity-40")}
                        >
                          <Icon className="h-3.5 w-3.5" aria-hidden />
                        </span>
                      </Tip>
                    );
                  })}
                </span>,
              ],
              ["Audited", c.audit ? "yes" : "no"],
            ]}
          />
          <Label>takes</Label>
          <Tree schema={c.input_schema} />
          <Label>returns</Label>
          <Tree schema={c.output_schema.properties?.data ?? {}} />
        </>
      ) : view === "call" ? (
        <>
          <Label>cli</Label>
          <Copy value={ex.cli} block label="Copy the CLI call" />
          <Label>http</Label>
          <Copy value={ex.http} block label="Copy the HTTP call" />
          <Label>mcp</Label>
          <Copy
            value={`claude mcp add --transport http shoc ${apiBase}/mcp --header "Authorization: Bearer $SHOC_TOKEN"`}
            block
            label="Copy the MCP connect command"
          />
          <Copy value={ex.mcp} block label="Copy the MCP tool call" />
        </>
      ) : (
        <>
          {/* The empty state says the window itself. */}
          {mine.length ? <Label>of the last 200 calls</Label> : null}
          <AuditTable rows={mine} loading={callsPending} empty="No call in the last 200" bounded />
        </>
      )}
    </Dialog>
  );
}
