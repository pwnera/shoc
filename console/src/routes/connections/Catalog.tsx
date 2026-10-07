/**
 * Add source: the connectors not connected yet, as logo tiles grouped in the
 * order small companies get breached through them, each with the rules it
 * would carry and how far the Integrator got. "/" filters, arrows move, Enter
 * opens the connector's connect form inside the same dialog.
 *
 * Capabilities used: source.list, rule.list (rule counts), and the connect
 * form's source.configure and source.push_key.
 */
import { useRef, useState, type KeyboardEvent } from "react";
import { ChevronLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Input, Label } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { useRules } from "@/lib/queries";
import { catalog, connectorOf, rulesCarried, sourceName } from "@/lib/sources";
import { ConnectForm } from "./ConnectForm";
import { Logo } from "./parts";
import { useSourceState, words } from "./state";

/** The tile nearest to `from` in a direction, by on-screen position. */
function nearest(tiles: HTMLElement[], from: HTMLElement, key: string): HTMLElement | undefined {
  const at = tiles.indexOf(from);
  if (key === "ArrowRight") return tiles[at + 1];
  if (key === "ArrowLeft") return tiles[at - 1];
  const a = from.getBoundingClientRect();
  const down = key === "ArrowDown";
  return tiles
    .map((el) => ({ el, r: el.getBoundingClientRect() }))
    .filter(({ r }) => (down ? r.top > a.top + 4 : r.top < a.top - 4))
    .sort((x, y) => Math.abs(x.r.top - a.top) - Math.abs(y.r.top - a.top) || Math.abs(x.r.left - a.left) - Math.abs(y.r.left - a.left))[0]?.el;
}

export function Catalog({
  connector,
  onPick,
  onClose,
}: {
  /** "new" for the tiles, or a connector whose form is open. */
  connector: string;
  onPick: (connector: string) => void;
  onClose: () => void;
}) {
  const model = useSourceState();
  const rules = useRules();
  const [text, setText] = useState("");
  const filter = useRef<HTMLInputElement>(null);
  const grid = useRef<HTMLDivElement>(null);
  const data = model.list.data;
  const connected = new Set(model.configured.map((row) => connectorOf(row.source)));
  const open = [...new Set([...(data?.available ?? []), ...(data?.push_only ?? [])])].filter((c) => !connected.has(c));
  const asked = text.toLowerCase().trim();
  const shown = open.filter((c) => !asked || words(c).includes(asked) || sourceName(c).toLowerCase().includes(asked));
  const steps = new Map((data?.onboarding ?? []).map((o) => [o.source, o.step]));
  const picking = connector !== "new";

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (event.key === "/" && target.tagName !== "INPUT") {
      event.preventDefault();
      filter.current?.focus();
      return;
    }
    if (!/^Arrow/.test(event.key)) return;
    const tiles = [...(grid.current?.querySelectorAll<HTMLElement>("[data-tile]") ?? [])];
    if (!tiles.length) return;
    if (target === filter.current) {
      if (event.key !== "ArrowDown") return;
      event.preventDefault();
      tiles[0]?.focus();
      return;
    }
    if (!target.hasAttribute("data-tile")) return;
    event.preventDefault();
    nearest(tiles, target, event.key)?.focus();
  };

  return (
    <Dialog
      size="wide"
      title={
        picking ? (
          <span className="inline-flex items-center gap-2">
            <Logo name={connector} />
            {sourceName(connector)}
          </span>
        ) : (
          "Add source"
        )
      }
      onClose={onClose}
    >
      {picking ? (
        <>
          <Button variant="ghost" size="sm" className="self-start" onClick={() => onPick("new")}>
            <ChevronLeft aria-hidden />
            Catalog
          </Button>
          <ConnectForm key={connector} source={connector} />
        </>
      ) : (
        <div className="flex flex-col gap-3" onKeyDown={onKeyDown}>
          <Input
            ref={filter}
            small
            data-autofocus
            type="search"
            value={text}
            onChange={(event) => setText(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && shown.length === 1) onPick(shown[0]!);
            }}
            placeholder="Filter"
            aria-label="Filter connectors"
            aria-keyshortcuts="/"
          />
          {model.list.isPending ? (
            <Skel kind="block" />
          ) : model.list.isLoadingError ? (
            <ErrorNote error={model.list.error} onRetry={() => void model.list.refetch()} />
          ) : !open.length ? (
            <Empty kind="clear" title="Every connector is connected" />
          ) : !shown.length ? (
            <Empty title="No connector matches" />
          ) : (
            <div ref={grid} className="flex flex-col gap-4">
              {catalog(shown).map((group) => (
                <section key={group.group} className="flex flex-col gap-2" aria-label={group.group}>
                  <Label>{group.group}</Label>
                  <div className="grid grid-cols-[repeat(auto-fill,minmax(176px,1fr))] gap-2">
                    {group.connectors.map((c) => {
                      const step = steps.get(c);
                      const carried = rules.data ? rulesCarried(c, rules.data.rules) : null;
                      return (
                        <button
                          key={c}
                          type="button"
                          data-tile
                          onClick={() => onPick(c)}
                          className="flex min-w-0 flex-col items-start gap-1 rounded-panel border border-line-1 bg-bg-1 p-2.5 text-left hover:border-line-2 hover:bg-bg-2"
                        >
                          <span className="flex w-full min-w-0 items-center gap-2">
                            <Logo name={c} />
                            <span className="truncate text-fg-1">{sourceName(c)}</span>
                          </span>
                          <span className="flex w-full items-center gap-2">
                            <span className="sh-mono text-fg-4">
                              {carried === null ? "…" : `carries ${carried} rule${carried === 1 ? "" : "s"}`}
                            </span>
                            {step && step !== "discover" ? (
                              <Badge tone={step === "credentials" ? "warn" : "muted"} className="ml-auto">
                                {step}
                              </Badge>
                            ) : null}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </section>
              ))}
            </div>
          )}
        </div>
      )}
    </Dialog>
  );
}
