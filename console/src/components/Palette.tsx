/**
 * The command palette (⌘K), model-free: it calls `search` and reads cached
 * lists, never `ask`. Sections in order: this page's own commands (when opened
 * on a record), recent records, an entity typed exactly, records by name,
 * findings and events from `search`, every screen and tab, other screens'
 * commands (handed to their home with `?do=`), and Ask the crew, always last,
 * which only opens the chat with a draft. `>` narrows to commands, `#` to
 * records, `@` to an entity, `?` shows the keys that work here and nothing else.
 * Escape hands focus back to whatever had it, or to the search button.
 *
 * Capabilities used: search; cached case.list, rule.list, playbook.list,
 * source.list and hunt.results.
 */
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Box, Compass, Crosshair, CornerDownLeft, Plug, Radar, Search, Telescope, Zap, type LucideIcon } from "lucide-react";
import { aboutLabel, aboutOf, openChat } from "@/lib/chat";
import {
  COMMANDS,
  GO_TO,
  handOff,
  keyLabel,
  paletteLabel,
  recentRecords,
  runCommand,
  useBound,
  type Command,
  type Group,
} from "@/lib/commands";
import { exploreHref } from "@/lib/explore";
import { exploreQuery, intelType, parseEntity } from "@/lib/entity";
import { age, shortId } from "@/lib/format";
import { useNow } from "@/lib/now";
import { useCaseLog, usePlaybooks, useRules, useSearch, useSourceList } from "@/lib/reads";
import { sourceName } from "@/lib/sources";
import type { CaseRecord, Finding, FindingRecord, HuntReadiness } from "@/types";
import { SeverityBadge } from "./ui/badge";
import { Entity } from "./ui/entity";
import { Announcer } from "./ui/misc";
import { Seg } from "./ui/seg";
import { AutonomyBadge } from "./ui/status";

export type PaletteMode = "all" | "keys";

type Row = {
  key: string;
  icon?: ReactNode;
  /** A severity badge, between the icon and the title. */
  badge?: ReactNode;
  /** The title starts with the query: Enter goes here first. */
  exact?: boolean;
  title: ReactNode;
  meta?: ReactNode;
  keys?: string;
  level?: string;
  crew?: boolean;
  run: () => void;
};
type Section = { id: string; label?: string; aside?: ReactNode; rows: Row[] };

const WINDOWS = ["24h", "7d", "30d", "90d"] as const;
type Win = (typeof WINDOWS)[number];
const WINDOW_KEY = "shoc.palette.window";
const SHOW = 5;

const WORD_START = /[\s›/._:-]/;

/**
 * Higher is better; -1 is no match. Prefix beats word start beats substring
 * beats every word of the query found apart ("aws key" in "AWS access key")
 * beats a tight subsequence ("hlth" in "health"). The subsequence holds only
 * in a short label, starting a word and spanning at most two letters more
 * than the query, so "case" matches neither "bedrock_abuse" nor a long title.
 */
function score(text: string, query: string): number {
  if (!query) return 1;
  const t = text.toLowerCase();
  const q = query.toLowerCase().trim();
  const at = t.indexOf(q);
  if (at === 0) return 100;
  if (at > 0) return WORD_START.test(t[at - 1]!) ? 80 : 60;
  const words = q.split(/\s+/);
  if (words.length > 1) {
    const each = words.map((w) => score(t, w));
    return Math.min(...each) < 0 ? -1 : Math.min(...each) / 2;
  }
  if (t.length > 32) return -1;
  for (let start = t.indexOf(q[0]!); start >= 0; start = t.indexOf(q[0]!, start + 1)) {
    if (start > 0 && !WORD_START.test(t[start - 1]!)) continue;
    let i = 0;
    for (let end = start; end < t.length && end - start < q.length + 2 && i < q.length; end++) if (t[end] === q[i]) i++;
    if (i === q.length) return 20;
  }
  return -1;
}

/** Case uids all start with "CASE-": they count only when the query looks like one. */
const ID_LIKE = /^(case-?|f-)?[0-9a-f]{4,}$|^case-[0-9a-f]/i;

/** A whole case or finding uid; a shorter one is matched in the Records section, never guessed as a path. */
const FULL_ID = /^(CASE-[0-9a-f]{20}|F-[0-9a-f]{24})$/i;

/** How the Keys view names a dialog's commands. */
const DIALOGS: Record<string, string> = {
  "dialog:backlog": "Change",
  "dialog:pack": "Hunt pack",
  "dialog:indicator": "Indicator",
  "dialog:action": "Action",
  "dialog:decide": "Approval",
};

function ranked<T>(items: T[], text: (item: T) => string, query: string): T[] {
  return items
    .map((item, index) => ({ item, index, s: score(text(item), query) }))
    .filter((x) => x.s >= 0)
    .sort((a, b) => b.s - a.s || a.index - b.index)
    .map((x) => x.item);
}

function savedWindow(): Win {
  try {
    const w = localStorage.getItem(WINDOW_KEY) as Win | null;
    return w && WINDOWS.includes(w) ? w : "7d";
  } catch {
    return "7d";
  }
}

const KIND_ICON: Record<string, LucideIcon> = { case: Box, finding: Radar, rule: Crosshair, playbook: Zap, source: Plug, pack: Telescope };
const icon = (kind: string) => {
  const Icon = KIND_ICON[kind] ?? Compass;
  return <Icon aria-hidden />;
};

function Keys({ keys }: { keys?: string }) {
  if (!keys) return null;
  return (
    <span className="sh-palette__keys">
      {keyLabel(keys)
        .split(" ")
        .map((k, i) => (
          <kbd key={i} className="sh-kbd">
            {k}
          </kbd>
        ))}
    </span>
  );
}

export function Palette({ mode, onClose }: { mode: PaletteMode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const base = useId();
  const location = useLocation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const now = useNow();
  const [text, setText] = useState(mode === "keys" ? "?" : "");
  // The active row by key, so a slow section arriving above it never moves Enter; null is the best match.
  const [active, setActive] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [win, setWin] = useState<Win>(savedWindow);
  // The record the palette was opened on; Backspace on an empty input drops it.
  const [scope, setScope] = useState(() => {
    const about = aboutOf(location.pathname, location.search);
    return about && about.kind !== "query" ? about : null;
  });

  const prefix = /^[>#@?]/.test(text) ? text[0]! : "";
  const query = (prefix ? text.slice(1) : text).trim();
  const [debounced, setDebounced] = useState(query);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query), 250);
    return () => clearTimeout(timer);
  }, [query]);

  const bound = useBound();
  const cases = useCaseLog();
  const rules = useRules();
  const playbooks = usePlaybooks();
  const sources = useSourceList();
  const wantSearch = prefix === "" && debounced.length >= 3;
  const search = useSearch({ question: wantSearch ? debounced : "", since: `-${win}`, limit: 8 });

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal?.();
    input.current?.focus();
  }, []);

  const close = () => {
    const dialog = ref.current;
    if (dialog?.open && dialog.close) dialog.close();
    else onClose();
  };
  // A row that ran moves focus itself (a page, the chat); a dismissal returns it.
  const ran = useRef(false);
  const act = (fn: () => void) => () => {
    ran.current = true;
    close();
    fn();
  };
  const go = (to: string) => act(() => navigate(to));
  /** `?entity=…` over the screen the palette was opened on. */
  const over = (params: Record<string, string>) => {
    const out = new URLSearchParams(location.search);
    for (const [k, v] of Object.entries(params)) out.set(k, v);
    return `${location.pathname}?${out.toString()}`;
  };
  const askRow: Row = {
    key: "ask",
    crew: true,
    icon: <span className="sh-crewmark">›</span>,
    title: query && prefix !== "?" ? `Ask the crew about "${query}"` : "Ask the crew",
    keys: "mod+enter",
    run: act(() => openChat(prefix === "?" ? "" : query)),
  };

  // Rebuilt each render: the lists are small and already cached.
  const sections: Section[] = (() => {
    const out: Section[] = [];
    const cap = (id: string, rows: Row[], more?: () => void): Row[] => {
      if (rows.length <= SHOW || expanded.has(id)) return rows;
      return [
        ...rows.slice(0, SHOW),
        {
          key: `${id}:more`,
          icon: <span />,
          title: <span className="text-fg-3">+{rows.length - SHOW} more</span>,
          run: more ?? (() => setExpanded((was) => new Set(was).add(id))),
        },
      ];
    };

    if (prefix === "?") {
      // A screen's or a dialog's own keys show once it binds them; a key a screen binds
      // wins over the global or list key it shadows (`dispatch`), so that row is left out.
      const live = new Set(bound.map((c) => c.id));
      const taken = new Set(bound.flatMap((c) => (c.scope.startsWith("route:") && c.keys ? [c.keys] : [])));
      const groups: Group[] = ["Global", "Go to", "Lists", "Dialogs", "This screen"];
      for (const group of groups) {
        const commands = COMMANDS.filter((c) => {
          if (c.group !== group || !c.keys) return false;
          if (c.scope.startsWith("route:") || c.scope.startsWith("dialog:")) return live.has(c.id);
          return !(c.scope === "global" || c.scope === "list") || !taken.has(c.keys);
        });
        const label = (c: Command) => (DIALOGS[c.scope] ? `${DIALOGS[c.scope]} › ${c.label}` : c.label);
        const rows = ranked(commands, (c) => `${label(c)} ${c.keys}`, query).map(
          (c): Row => ({
            key: `keys:${c.id}`,
            title: label(c),
            meta: c.alt ? keyLabel(c.alt) : undefined,
            keys: c.keys,
            level: c.level,
            run: act(() => {
              if (!runCommand(c.id) && c.to) navigate(c.to);
            }),
          }),
        );
        if (rows.length) out.push({ id: `keys:${group}`, label: group, rows });
      }
      return out;
    }

    const all = prefix === "";
    // 1. This page: the commands the record's page or dialog registered.
    if (scope && (all || prefix === ">")) {
      const rows = ranked(bound, (c) => c.label, query).map(
        (c): Row => ({ key: `page:${c.id}`, icon: "→", title: c.label, keys: c.keys, level: c.level, run: act(() => runCommand(c.id)) }),
      );
      if (rows.length) out.push({ id: "page", label: `This ${scope.kind}`, rows });
    }

    // 2. Recent records, on an empty input: the cached title, the id beside it.
    if (all && !query) {
      const titleOf = (kind: string, id: string): string | undefined => {
        if (kind === "case")
          return (
            cases.data?.rows.find((c) => c.case_uid === id)?.title ??
            client.getQueryData<CaseRecord>(["case.get", id])?.case.title
          );
        if (kind === "rule") return rules.data?.rules.find((r) => r.id === id)?.title;
        if (kind === "playbook") return playbooks.data?.playbooks.find((p) => p.id === id)?.title;
        return (
          client.getQueryData<FindingRecord>(["finding.get", id])?.finding.title ??
          client
            .getQueriesData<{ rows?: Finding[] }>({ queryKey: ["finding.list"] })
            .flatMap(([, d]) => d?.rows ?? [])
            .find((f) => f.finding_uid === id)?.title
        );
      };
      // The page it was opened on is not a place to go.
      const rows = recentRecords()
        .filter((r) => r.to !== location.pathname)
        .map((r): Row => {
          const id = r.kind === "case" || r.kind === "finding" ? shortId(r.id) : r.id;
          const title = titleOf(r.kind, r.id);
          return {
            key: `recent:${r.to}`,
            icon: icon(r.kind),
            title: title ?? <span className="font-mono">{id}</span>,
            meta: title ? id : r.kind,
            run: go(r.to),
          };
        });
      if (rows.length) out.push({ id: "recent", label: "Recent", rows });
    }

    // 3. An entity typed exactly; a whole case or finding id opens its page.
    if ((all || prefix === "@") && query) {
      const record = FULL_ID.test(query);
      const entity = record ? null : parseEntity(query);
      if (record) {
        const kind = query.toUpperCase().startsWith("CASE-") ? "case" : "finding";
        const uid = `${query.slice(0, query.indexOf("-")).toUpperCase()}${query.slice(query.indexOf("-")).toLowerCase()}`;
        out.push({
          id: "entity",
          label: kind,
          rows: [{ key: "record", icon: icon(kind), title: <span className="font-mono">{uid}</span>, run: go(`/${kind === "case" ? "cases" : "findings"}/${uid}`) }],
        });
      } else if (entity) {
        const explore = exploreHref({ q: exploreQuery(entity), since: `-${win}` });
        const target = (label: string, to: string) => (
          <button
            type="button"
            className="sh-link"
            onClick={(event) => {
              event.stopPropagation();
              go(to)();
            }}
          >
            {label}
          </button>
        );
        out.push({
          id: "entity",
          label: "Entity",
          aside: <span>{entity.type}</span>,
          rows: [
            {
              key: "entity",
              title: <Entity value={entity.key} full />,
              meta: (
                <span className="inline-flex gap-2">
                  {target("Open", over({ entity: entity.key }))}
                  {target("Events", explore)}
                  {target("Findings", `/findings?on=${encodeURIComponent(entity.key)}`)}
                  {intelType(entity) ? target("Intel", over({ entity: entity.key, view: "intel" })) : null}
                </span>
              ),
              run: go(over({ entity: entity.key })),
            },
          ],
        });
      }
    }

    // 4. Records by name, from the lists already cached.
    if ((all || prefix === "#") && query) {
      type Hit = { kind: string; text: string; row: Row; screen: string };
      const packs = client
        .getQueriesData<{ readiness?: HuntReadiness[] }>({ queryKey: ["hunt.results"] })
        .flatMap(([, d]) => d?.readiness ?? []);
      const hits: Hit[] = [
        ...(cases.data?.rows ?? []).map((c) => ({
          kind: "case",
          screen: "/cases",
          text: `${c.title} ${c.entity_key}${ID_LIKE.test(query) ? ` ${c.case_uid}` : ""}`,
          row: {
            key: `open:${c.case_uid}`,
            badge: <SeverityBadge severity={c.severity} />,
            title: c.title,
            meta: `${shortId(c.case_uid)} · ${age(c.updated_at, now)}`,
            run: go(`/cases/${c.case_uid}`),
          },
        })),
        ...(rules.data?.rules ?? []).map((r) => ({
          kind: "rule",
          screen: "/detection",
          text: `${r.title} ${r.id}`,
          row: { key: `open:rule:${r.id}`, icon: icon("rule"), title: r.title, meta: "rule", run: go(`/detection/rules/${r.id}`) },
        })),
        ...(playbooks.data?.playbooks ?? []).map((p) => ({
          kind: "playbook",
          screen: "/response?tab=playbooks",
          text: `${p.title} ${p.id}`,
          row: { key: `open:pb:${p.id}`, icon: icon("playbook"), title: p.title, meta: "playbook", run: go(`/response/playbooks/${p.id}`) },
        })),
        ...(sources.data?.configured ?? []).map((s) => ({
          kind: "source",
          screen: "/connections",
          text: `${sourceName(s.source)} ${s.source}`,
          row: { key: `open:src:${s.source}`, icon: icon("source"), title: sourceName(s.source), meta: "source", run: go(`/connections?source=${encodeURIComponent(s.source)}`) },
        })),
        ...[...new Map(packs.map((p) => [p.pack_id, p])).values()].map((p) => ({
          kind: "pack",
          screen: "/hunts?tab=packs",
          text: `${p.title ?? ""} ${p.pack_id}`,
          row: { key: `open:pack:${p.pack_id}`, icon: icon("pack"), title: p.title ?? p.pack_id, meta: "hunt pack", run: go(`/hunts?pack=${encodeURIComponent(p.pack_id)}`) },
        })),
      ];
      const found = ranked(hits, (h) => h.text, query);
      if (found.length) {
        const next = found[SHOW];
        const screen = next?.screen ?? "/";
        const more = `${screen}${screen.includes("?") ? "&" : "?"}q=${encodeURIComponent(query)}`;
        const rows = found.map((h) => ({ ...h.row, exact: h.text.toLowerCase().startsWith(query.toLowerCase()) }));
        out.push({ id: "open", label: "Records", rows: cap("open", rows, go(more)) });
      }
    }

    // 5. Findings and events from `search`.
    if (wantSearch) {
      const rows: Row[] = [];
      if (search.isError)
        rows.push({ key: "search:failed", title: <span className="text-bad">Search failed · Retry</span>, run: () => void search.refetch() });
      const data = search.data?.data;
      // `search` always pads with the window's newest findings: keep the ones on
      // an entity it named, else the ones whose words match the query.
      const named = new Set(data?.entities ?? []);
      const matching = (data?.findings ?? []).filter((f) =>
        named.size
          ? named.has(f.entity_key) || named.has(f.finding_uid)
          : score(`${f.title} ${f.rule_id} ${f.entity_key}`, debounced) >= 0,
      );
      const findings: Row[] = [];
      for (const f of matching)
        findings.push({
          key: `finding:${f.finding_uid}`,
          badge: <SeverityBadge severity={f.severity} />,
          title: f.title,
          meta: `${f.entity_key ? `${f.entity_key} · ` : ""}${age(f.last_seen, now)}`,
          run: go(`/findings/${f.finding_uid}`),
        });
      rows.push(...cap("findings", findings, go(`/findings?q=${encodeURIComponent(debounced)}`)));
      // The entity typed exactly already has its own row above.
      const typed = parseEntity(debounced)?.key;
      const others = (data?.entities ?? []).filter((e) => (parseEntity(e)?.key ?? e) !== typed);
      if (others.length) {
        const first = others[0]!;
        rows.push({
          key: "search:entities",
          title: (
            <span className="inline-flex min-w-0 gap-1 overflow-hidden">
              {others.slice(0, 5).map((e) => (
                <Entity
                  key={e}
                  value={e}
                  onOpen={() => {
                    go(over({ entity: parseEntity(e)?.key ?? e }))();
                  }}
                />
              ))}
            </span>
          ),
          run: go(over({ entity: parseEntity(first)?.key ?? first })),
        });
      }
      if (data?.events.length)
        rows.push({
          key: "search:events",
          icon: <Compass aria-hidden />,
          title: `${data.events.length >= 8 ? "8+" : data.events.length} events → Explore`,
          run: go(exploreHref({ q: debounced, since: `-${win}` })),
        });
      if (rows.length || search.isFetching)
        out.push({
          id: "findings",
          label: "Findings",
          rows,
        });
    }

    // 6. Every screen and tab.
    if (all) {
      const rows = ranked(GO_TO, (g) => g.label, query).map(
        (g): Row => ({
          key: `go:${g.to}`,
          icon: <CornerDownLeft aria-hidden />,
          title: g.label,
          keys: g.keys,
          exact: Boolean(query) && g.label.toLowerCase().startsWith(query.toLowerCase()),
          run: go(g.to),
        }),
      );
      if (rows.length) out.push({ id: "go", label: "Go to", rows: cap("go", rows) });
    }

    // 7. Other screens' commands, each run by its home screen.
    if (all || prefix === ">") {
      // A command this record's page already lists under "This …" is not offered twice.
      const commands = COMMANDS.filter((c) => c.palette && !(scope && bound.some((b) => b.id === c.id)));
      const rows = ranked(commands, (c: Command) => paletteLabel(c), query).map(
        (c): Row => ({ key: `cmd:${c.id}`, icon: "→", title: paletteLabel(c), level: c.level, run: go(handOff(c)) }),
      );
      if (rows.length) out.push({ id: "commands", label: "Commands", rows: cap("commands", rows) });
    }
    return out;
  })();

  const everything = prefix === "?" ? sections : [...sections, { id: "ask", rows: [askRow] }];
  const flat = everything.flatMap((s) => s.rows);
  const held = flat.findIndex((r) => r.key === active);
  const best = flat.findIndex((r) => r.exact);
  const at = held >= 0 ? held : best >= 0 ? best : 0;
  const firsts = everything.map((s) => flat.indexOf(s.rows[0]!));
  const pick = (index: number) => setActive(flat[index]?.key ?? null);

  useEffect(() => setActive(null), [text]);
  useEffect(() => {
    document.getElementById(`${base}-${at}`)?.scrollIntoView?.({ block: "nearest" });
  }, [at, base]);

  const empty = !sections.length && prefix !== "?" && query && !search.isFetching;
  // Heard once the search settles: how many rows answer, or that none does.
  const results = sections.reduce((n, section) => n + section.rows.length, 0);
  const searching = sections.some((section) => section.id === "findings");
  const said =
    !query || search.isFetching
      ? ""
      : empty
        ? "No match"
        : `${results} ${results === 1 ? "result" : "results"}${searching ? `, findings in ${win}` : ""}`;
  const stepWin = (step: number) => {
    const next = WINDOWS[(WINDOWS.indexOf(win) + step + WINDOWS.length) % WINDOWS.length]!;
    setWin(next);
    try {
      localStorage.setItem(WINDOW_KEY, next);
    } catch {
      /* kept until the palette closes */
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    const ctrl = event.ctrlKey && !event.metaKey;
    const move = (step: number) => {
      event.preventDefault();
      pick((at + step + flat.length) % flat.length);
    };
    if (event.altKey && searching && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
      // The findings window, from the input: Alt+←/→.
      event.preventDefault();
      stepWin(event.key === "ArrowLeft" ? -1 : 1);
    } else if (event.key === "ArrowDown" || (ctrl && event.key.toLowerCase() === "n")) move(1);
    else if (event.key === "ArrowUp" || (ctrl && event.key.toLowerCase() === "p")) move(-1);
    else if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      askRow.run();
    } else if (event.key === "Enter") {
      event.preventDefault();
      flat[at]?.run();
    } else if (event.key === "Tab") {
      const current = firsts.filter((i) => i <= at).length - 1;
      // Shift+Tab from the first section leaves the input for the scope chip's remove button.
      if (event.shiftKey && scope && current <= 0) return;
      event.preventDefault();
      const next = (current + (event.shiftKey ? -1 : 1) + firsts.length) % firsts.length;
      pick(firsts[next] ?? 0);
    } else if (event.key === "Backspace" && !text && scope) {
      event.preventDefault();
      setScope(null);
    } else if (event.key === "Escape" && text && !(mode === "keys" && text === "?")) {
      // The first Escape clears; the next one closes (the dialog's own cancel). The keys sheet's own "?" closes at once.
      event.preventDefault();
      setText("");
    }
  };

  let index = -1;
  return (
    <dialog
      ref={ref}
      className="sh-palette"
      aria-label="Search or jump"
      onClose={(event) => {
        if (event.target !== event.currentTarget) return;
        // Opened with ⌘K while nothing had focus, the browser has nowhere to put it back.
        const held = document.activeElement;
        if (!ran.current && (!held || held === document.body || ref.current?.contains(held)))
          document.querySelector<HTMLElement>(".sh-shell__search")?.focus();
        onClose();
      }}
      onClick={(event) => event.target === ref.current && close()}
      onKeyDown={(event) => {
        // Opened over a record dialog, the palette closes alone, and through
        // the native close so focus returns to that dialog. ⌘K toggles it.
        const toggle = (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k";
        if ((event.key === "Escape" && !event.defaultPrevented) || toggle) {
          event.preventDefault();
          close();
        }
      }}
    >
      <div className="sh-palette__bar">
        <Search aria-hidden />
        {scope ? (
          <span className="sh-chip sh-palette__scope">
            <span className="sh-chip__label">{scope.kind}</span>
            <span className="sh-chip__value">{aboutLabel(scope)}</span>
            <button type="button" className="sh-chip__remove" onClick={() => setScope(null)} aria-label="Remove the scope">
              ×
            </button>
          </span>
        ) : null}
        <input
          ref={input}
          className="sh-palette__input"
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={onKeyDown}
          placeholder={prefix === "?" ? "Search the keys" : "Search or jump"}
          role="combobox"
          aria-expanded="true"
          aria-controls={`${base}-list`}
          aria-activedescendant={flat.length ? `${base}-${at}` : undefined}
          aria-autocomplete="list"
          aria-label="Search or jump"
          spellCheck={false}
          autoComplete="off"
        />
        {search.isFetching && wantSearch ? <i className="sh-palette__pending" aria-hidden /> : null}
        {/* The findings window sits beside the input, outside the listbox, while there are findings to search. */}
        {searching ? (
          <Seg<Win>
              label="Window"
              value={win}
              options={WINDOWS}
              onChange={(w) => {
                setWin(w);
                try {
                  localStorage.setItem(WINDOW_KEY, w);
                } catch {
                  /* kept until the palette closes */
                }
                input.current?.focus();
              }}
            />
        ) : null}
      </div>
      <div role="status" className="sr-only">
        {said}
      </div>
      <div id={`${base}-list`} role="listbox" aria-label="Results" className="sh-palette__list">
        {empty ? (
          <div className="sh-palette__empty" aria-hidden>
            No match
          </div>
        ) : null}
        {everything.map((section) => (
          <div key={section.id} role="group" aria-labelledby={section.label ? `${base}-${section.id}` : undefined}>
            {section.label ? (
              <div className="sh-palette__group" id={`${base}-${section.id}`} role="presentation">
                <span>{section.label}</span>
                {section.aside}
              </div>
            ) : null}
            {section.rows.map((row) => {
              index += 1;
              const mine = index;
              return (
                <div
                  key={row.key}
                  id={`${base}-${mine}`}
                  role="option"
                  aria-selected={mine === at}
                  className={row.crew ? "sh-palette__item sh-palette__item--crew" : "sh-palette__item"}
                  onMouseMove={() => mine !== at && pick(mine)}
                  onClick={row.run}
                >
                  {row.icon ? <span className="sh-palette__icon">{row.icon}</span> : null}
                  {row.badge}
                  <span className="sh-palette__title">{row.title}</span>
                  {row.meta ? <span className="sh-palette__meta">{row.meta}</span> : null}
                  {row.level ? <AutonomyBadge level={row.level} /> : null}
                  <Keys keys={row.keys} />
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div className="sh-palette__foot" aria-hidden>
        <span>↑↓ move</span>
        <span>↵ open</span>
        <span>{keyLabel("mod+enter")} ask the crew</span>
        <span>tab next section</span>
        <span>esc</span>
      </div>
      <Announcer />
    </dialog>
  );
}
