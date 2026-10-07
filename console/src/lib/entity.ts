/**
 * What kind of thing a value is, typed precisely: a URL is not a domain, a
 * domain is not an IP, an Okta session id is not an AWS key. Entity chips, the
 * palette's Entity row, EntityDialog and the graphs all read their kind here.
 * A `kind:` prefix (`user:alice`, the kernel's entity keys) wins over patterns.
 */
import { term, word } from "./explore";

export type EntityKind =
  | "ip"
  | "cidr"
  | "url"
  | "email"
  | "domain"
  | "hash"
  | "key"
  | "resource"
  | "cve"
  | "user"
  | "account"
  | "host"
  | "repo";

export type Entity = {
  kind: EntityKind;
  /** The exact type, for labels and `intel.lookup`: ipv4, ipv6, sha256, aws key, arn… */
  type: string;
  /** The bare value, prefix stripped. */
  value: string;
  /** `kind:value`, what `?entity=` carries. */
  key: string;
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
/** The URL parser is the strictest IPv6 check the platform has; a MAC address fails it. */
const IPV6 = {
  test(v: string): boolean {
    if (!v.includes(":") || !/^[0-9a-f:.]+$/i.test(v)) return false;
    try {
      new URL(`http://[${v}]/`);
      return true;
    } catch {
      return false;
    }
  },
};

/** Strict patterns, tried in order; the first match names the value. */
export const PATTERNS: { type: string; kind: EntityKind; test: (v: string) => boolean }[] = [
  { type: "cve", kind: "cve", test: (v) => /^CVE-\d{4}-\d{4,7}$/i.test(v) },
  { type: "url", kind: "url", test: (v) => /^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(v) },
  { type: "arn", kind: "resource", test: (v) => /^arn:aws[a-z-]*:\S+$/.test(v) },
  { type: "aws key", kind: "key", test: (v) => /^(AKIA|ASIA)[A-Z0-9]{16}$/.test(v) },
  { type: "email", kind: "email", test: (v) => /^[^\s@]+@([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v) },
  {
    type: "cidr",
    kind: "cidr",
    test: (v) => {
      const [ip = "", bits, extra] = v.split("/");
      if (bits === undefined || extra !== undefined || !/^\d{1,3}$/.test(bits)) return false;
      return (IPV4.test(ip) && Number(bits) <= 32) || (IPV6.test(ip) && Number(bits) <= 128);
    },
  },
  { type: "ipv4", kind: "ip", test: (v) => IPV4.test(v) },
  { type: "ipv6", kind: "ip", test: (v) => IPV6.test(v) },
  { type: "sha256", kind: "hash", test: (v) => /^[a-f0-9]{64}$/i.test(v) },
  { type: "sha1", kind: "hash", test: (v) => /^[a-f0-9]{40}$/i.test(v) },
  { type: "md5", kind: "hash", test: (v) => /^[a-f0-9]{32}$/i.test(v) },
  {
    type: "domain",
    kind: "domain",
    test: (v) => /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i.test(v),
  },
];

const PREFIXES: EntityKind[] = [
  "ip",
  "cidr",
  "url",
  "email",
  "domain",
  "hash",
  "key",
  "resource",
  "cve",
  "user",
  "account",
  "host",
  "repo",
];

function typed(value: string): { type: string; kind: EntityKind } | null {
  return PATTERNS.find((p) => p.test(value)) ?? null;
}

/** A value or entity key, typed; null when it is neither prefixed nor a known pattern. */
export function parseEntity(input: string): Entity | null {
  const text = input.trim();
  if (!text) return null;
  const colon = text.indexOf(":");
  const prefix = colon > 0 ? (text.slice(0, colon).toLowerCase() as EntityKind) : null;
  // `url:https://…` is prefixed; `https://…` is not, though it holds a colon.
  if (prefix && PREFIXES.includes(prefix) && !text.slice(colon).startsWith("://")) {
    const value = text.slice(colon + 1);
    if (!value) return null;
    const found = typed(value);
    const type = found && found.kind === prefix ? found.type : prefix;
    return { kind: prefix, type, value, key: `${prefix}:${value}` };
  }
  const found = typed(text);
  return found ? { ...found, value: text, key: `${found.kind}:${text}` } : null;
}

/** The kind alone. */
export function kindOf(input: string): EntityKind | null {
  return parseEntity(input)?.kind ?? null;
}

/** An entity key without its `kind:` prefix. */
export function bare(input: string): string {
  return parseEntity(input)?.value ?? input;
}

/** An AWS access key id: only these are drawn with the key glyph in a KEY lane. */
export const isAwsKey = (value: string) => /^(AKIA|ASIA)[A-Z0-9]{16}$/.test(bare(value));

/** The type `intel.lookup` answers for this entity, or "" when it answers none. */
export function intelType(entity: Entity): string {
  if (entity.kind === "ip" || entity.kind === "url" || entity.kind === "cve") return entity.kind;
  if (entity.kind === "domain" || entity.kind === "email") return entity.kind;
  if (entity.type === "sha256" || entity.type === "md5") return entity.type;
  return "";
}

/** The event field each kind lives in, as the detection engine keys entities. */
const FIELD: Partial<Record<EntityKind, string>> = {
  user: "actor.user.name",
  key: "actor.session.uid",
  ip: "src_endpoint.ip",
  resource: "resource.uid",
  account: "cloud.account.uid",
  host: "device.hostname",
};

/** The Explore query that finds this entity's events: its field when it has one, else a free word. */
export function exploreQuery(entity: Entity): string {
  const field = FIELD[entity.kind];
  return field ? term(field, entity.value) : word(entity.value);
}
