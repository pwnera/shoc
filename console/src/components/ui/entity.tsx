/**
 * An entity as a 20px chip: its kind's glyph and the value in mono, truncated
 * in the middle ("AKIA…MPLE") with the whole value in a tip. Kinds come from
 * `lib/entity.ts`: the `kind:` prefix of an entity key, or a strict pattern,
 * so a URL is never drawn as a domain nor a domain as an IP. As a button it
 * opens EntityDialog through `?entity=<kind:value>`.
 */
import {
  AtSign,
  Bug,
  Building2,
  CircleDot,
  Database,
  GitBranch,
  Globe,
  Globe2,
  Hash,
  KeyRound,
  Link as LinkIcon,
  Network,
  Server,
  User,
  type LucideIcon,
} from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";
import { parseEntity, type EntityKind } from "@/lib/entity";
import { middle } from "@/lib/format";
import { usePopParam } from "@/lib/popup";
import { Tip } from "./tip";

const ICON: Record<EntityKind, LucideIcon> = {
  ip: Globe,
  cidr: Network,
  email: AtSign,
  user: User,
  key: KeyRound,
  account: Building2,
  resource: Database,
  repo: GitBranch,
  url: LinkIcon,
  domain: Globe2,
  hash: Hash,
  host: Server,
  cve: Bug,
};

/** Keys and hashes keep their ends ("AKIA…MPLE"); anything else past 28 characters keeps its head and tail. */
function short(value: string, kind: EntityKind | undefined): string {
  return kind === "key" || kind === "hash" ? middle(value) : value.length > 28 ? middle(value, 13) : value;
}

/** Tip's handlers arrive as props and reach the button. */
function Opener({
  entity,
  label,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { entity: string; label: string; children: ReactNode }) {
  const openEntity = usePopParam("entity", ["view"]);
  return (
    <button
      {...rest}
      type="button"
      aria-label={label}
      onClick={(event) => {
        event.stopPropagation();
        openEntity(entity);
      }}
    >
      {children}
    </button>
  );
}

export function Entity({
  value,
  kind,
  button,
  onOpen,
  full,
  className,
}: {
  /** A bare value or an entity key (`user:alice`). */
  value: string;
  /** Overrides the kind read from the value. */
  kind?: EntityKind;
  /** Opens EntityDialog over the current page. */
  button?: boolean;
  /** Opens something else instead (a row's own handler). */
  onOpen?: () => void;
  /** No middle truncation (a dialog header). */
  full?: boolean;
  className?: string;
}) {
  const parsed = parseEntity(value);
  const k = kind ?? parsed?.kind;
  const bare = parsed?.value ?? value;
  const Icon = k ? ICON[k] : CircleDot;
  const shown = full ? bare : short(bare, k);
  const named = `${parsed?.type ?? k ?? "value"} ${bare}`;
  const body = (
    <>
      <Icon aria-hidden />
      <span className="sh-entity__value">{shown}</span>
    </>
  );
  const classes = cn("sh-entity", (button || onOpen) && "sh-entity--button", className);
  const el = onOpen ? (
    <button
      type="button"
      className={classes}
      aria-label={named}
      onClick={(event) => {
        event.stopPropagation();
        onOpen();
      }}
    >
      {body}
    </button>
  ) : button ? (
    <Opener entity={parsed?.key ?? `${k ?? "value"}:${bare}`} className={classes} label={named}>
      {body}
    </Opener>
  ) : (
    <span className={classes} role="img" aria-label={named}>
      {body}
    </span>
  );
  return (
    <Tip label={shown === bare ? undefined : bare} mono>
      {el}
    </Tip>
  );
}
