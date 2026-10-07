/**
 * The explorer's query language, as the kernel parses it (`shoc/capabilities/
 * events.py` `_TERM`): `field op value` terms and bare words, values quoted
 * with "…" or '…' and no escapes. Pivots everywhere build their terms here, so
 * a value always goes back into the query meaning exactly itself.
 */

/** The OCSF paths the store answers to (`contract/v1.json` `ocsf_fields`), for autocomplete and "+ field". */
export const FIELDS = [
  "activity_id",
  "activity_name",
  "actor.invoked_by",
  "actor.session.uid",
  "actor.user.name",
  "actor.user.type",
  "actor.user.uid",
  "api.operation",
  "api.response.code",
  "api.response.error",
  "api.service.name",
  "category_uid",
  "class_name",
  "class_uid",
  "cloud.account.uid",
  "cloud.provider",
  "cloud.region",
  "device.hostname",
  "device.uid",
  "dst_endpoint.domain",
  "dst_endpoint.ip",
  "dst_endpoint.port",
  "event_uid",
  "file.hashes.sha256",
  "file.path",
  "http_request.url.url_string",
  "http_request.user_agent",
  "message",
  "metadata.product.name",
  "metadata.version",
  "process.cmd_line",
  "process.file.hashes.sha256",
  "process.file.path",
  "process.name",
  "process.parent_process.name",
  "process.pid",
  "query.hostname",
  "resource.type",
  "resource.uid",
  "severity_id",
  "src_endpoint.asn",
  "src_endpoint.domain",
  "src_endpoint.ip",
  "src_endpoint.location.country",
  "src_endpoint.port",
  "status",
  "status_code",
  "time",
] as const;

/**
 * A stored column as the OCSF path the query bar takes (`shoc/store/ocsf.py`
 * FIELD_MAP, reversed), so a field named in a dialog can be typed into Explore
 * as it reads. A column with no path keeps its own name; `unmapped.…` and
 * `raw.…` paths are already paths.
 */
const PATHS: Record<string, string> = {
  actor_user_name: "actor.user.name",
  actor_user_uid: "actor.user.uid",
  actor_user_type: "actor.user.type",
  actor_session_uid: "actor.session.uid",
  actor_invoked_by: "actor.invoked_by",
  src_endpoint_ip: "src_endpoint.ip",
  src_endpoint_domain: "src_endpoint.domain",
  src_endpoint_location_country: "src_endpoint.location.country",
  src_endpoint_asn: "src_endpoint.asn",
  src_endpoint_port: "src_endpoint.port",
  dst_endpoint_ip: "dst_endpoint.ip",
  dst_endpoint_port: "dst_endpoint.port",
  dst_endpoint_domain: "dst_endpoint.domain",
  dns_query_hostname: "query.hostname",
  http_request_url: "http_request.url.url_string",
  http_user_agent: "http_request.user_agent",
  api_operation: "api.operation",
  api_service_name: "api.service.name",
  api_response_code: "api.response.code",
  api_response_error: "api.response.error",
  cloud_provider: "cloud.provider",
  cloud_account_uid: "cloud.account.uid",
  cloud_region: "cloud.region",
  resource_type: "resource.type",
  resource_uid: "resource.uid",
  device_hostname: "device.hostname",
  device_uid: "device.uid",
  process_name: "process.name",
  process_pid: "process.pid",
  process_cmd_line: "process.cmd_line",
  process_hash_sha256: "process.file.hashes.sha256",
  process_parent_name: "process.parent_process.name",
  process_file_path: "process.file.path",
  file_path: "file.path",
  file_hash_sha256: "file.hashes.sha256",
  metadata_product: "metadata.product.name",
  metadata_version: "metadata.version",
};

export const fieldPath = (column: string): string => PATHS[column] ?? column;

/**
 * The one plain word for the paths a reader meets outside Explore: the graph's
 * lanes, the event dialog's facts and a finding's match all say these.
 */
const FIELD_WORDS: Record<string, string> = {
  "src_endpoint.ip": "Source IP",
  "actor.user.name": "Actor",
  "actor.session.uid": "Session",
  "api.operation": "Operation",
  "resource.uid": "Resource",
  "cloud.account.uid": "Account",
  "cloud.region": "Region",
};

/** A path's plain word, else the path as Explore takes it. */
export const fieldWord = (path: string): string => FIELD_WORDS[path] ?? path;

/** The field rail's default pins. */
export const PINNED = ["metadata.product.name", "actor.user.name", "api.operation", "src_endpoint.ip", "status"];

/** The kernel's operators. */
export const OPERATORS = ["=", "!=", ">", ">=", "<", "<=", "~", "!~"] as const;
export type Operator = (typeof OPERATORS)[number];

/**
 * A term that means the same value when it goes back into the query box. A
 * value holding spaces or a single quote is wrapped in double quotes, one
 * holding a double quote in single quotes, and one holding both becomes a
 * contains match (`~`, `!~` for a negation) on its longest quote-free run.
 */
export function term(field: string, value: string, op: Operator = "="): string {
  const dq = value.includes('"');
  const sq = value.includes("'");
  if (dq && sq) {
    const run = value.split(/["']/).reduce((a, b) => (b.length > a.length ? b : a), "");
    const contains = op === "!=" || op === "!~" ? "!~" : "~";
    return `${field}${contains}${/\s/.test(run) || !run ? `"${run}"` : run}`;
  }
  if (dq) return `${field}${op}'${value}'`;
  if (sq || /\s/.test(value) || !value) return `${field}${op}"${value}"`;
  return `${field}${op}${value}`;
}

/** A bare word that searches for exactly this text, quoted as `term` quotes values. */
export function word(value: string): string {
  return term("", value).replace(/^[=~]/, "");
}

/** Add a term to a running query once: the same term twice is the same query. */
export function addTerm(query: string, next: string): string {
  const terms = splitTerms(query);
  return terms.includes(next) ? query.trim() : [...terms, next].join(" ");
}

/** The query's terms and words, quotes kept, in order. */
export function splitTerms(query: string): string[] {
  const re = /[A-Za-z_][A-Za-z0-9_.@$-]*\s*(?:!=|>=|<=|!~|[=~<>])\s*(?:"[^"]*"|'[^']*'|\S+)|"[^"]*"|'[^']*'|\S+/g;
  return [...query.matchAll(re)].map((m) => m[0].replace(/\s*(!=|>=|<=|!~|[=~<>])\s*/, "$1"));
}

/** The Explore link that reproduces a query over a window. */
export function exploreHref(input: { q?: string; since?: string; until?: string }): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(input)) if (v) params.set(k, v);
  const query = params.toString();
  return query ? `/explore?${query}` : "/explore";
}

/** An hour either side of an instant, as Explore's since and until. */
export function around(from: string, to = from, hours = 1): { since: string; until: string } {
  const pad = hours * 3_600_000;
  return {
    since: new Date(Date.parse(from) - pad).toISOString(),
    until: new Date(Date.parse(to) + pad).toISOString(),
  };
}
