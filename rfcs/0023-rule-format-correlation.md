---
rfc: 0023
title: Rules count distinct values, follow sequences, compare fields, match networks and remember what they saw
status: accepted
authors: ["@Rettila"]
created: 2026-10-02
requirements: ["DET-1", "DET-2", "DET-3", "DET-8", "ING-3"]
supersedes: null
---

# RFC 0023: Rules count distinct values, follow sequences, compare fields, match networks and remember what they saw

## Summary

The rule format gains seven things: `count_distinct` in an aggregation, a
two-event `sequence` by a shared key, the `fieldref` and `cidr` modifiers,
a `first_seen` baseline in a rule, a fallback list for `entity`, and a way to
read one item of a list of named items, which a mapping writes at ingest
(`keyed`). Hunt packs gain `seen_by_at_least` in their `rare` baseline. Each
compiles to canonical SQL that SQLGlot translates for Postgres, Databricks and
Snowflake, with no window function and no dialect-specific JSON path. Two
correctness fixes ride along: `contains`, `startswith` and `endswith` match
their value literally, and a YAML `true` on a `raw.` path compares as text.

## Motivation

The detection gap review of 2026-10-02 compared every shipped rule and hunt
with Elastic's prebuilt rules and SigmaHQ, area by area (AWS, Okta and Google
Workspace, Microsoft, GCP/GitHub/model APIs, endpoint and network). Each of the
five reports ended with the same engine gaps, and those gaps blocked more
upstream rules than any missing connector:

- **Distinct counts.** Rules counted events, so one noisy integration tripped a
  burst and an attacker who called each API once stayed under it. Blocked:
  Elastic "AWS Discovery API Calls via CLI from a Single Resource" (distinct
  actions), "AWS Secrets Manager Rapid Secrets Retrieval" (distinct secrets),
  "AWS IAM User Console Login from Multiple Geolocations", "AWS Access Token
  Used from Multiple Addresses", the Entra and Okta password-spray rules
  (distinct users per address), "Multiple Device Token Hashes for Single Okta
  Session", GitHub's
  [high number of cloned repositories from a PAT](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/github/execution_github_high_number_of_cloned_repos_from_pat),
  GCP's
  [ListSecrets across multiple projects](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/gcp/discovery_gcp_secret_manager_listsecrets_across_multiple_projects),
  "Multiple Remote Management Tool Vendors on Same Host" and DNS tunnelling by
  distinct subdomains.
- **Sequences.** Blocked: "AWS GetFederationToken Followed by Console Login via
  Federation Exchange", "AWS SES Email Identity Verified Then Deleted", "AWS EKS
  Access Entry Created Then Deleted by Same Identity", "AWS IAM User
  Self-Created Access Key Subsequently Used", the help-desk pattern (an admin
  resets a user's factors, then that user signs in from somewhere new), MFA
  bombing followed by an approval, GCP's
  [sensitive RBAC change followed by workload modification](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/gcp/privilege_escalation_gcp_gke_sensitive_rbac_change_followed_by_workload_modification),
  "Remote Management Access Launch After MSI Install" and eight Entra EQL
  sequences.
- **Field-to-field comparison.** Blocked: "AWS IAM User Created Access Keys For
  Another User" and Sigma "AWS IAM Backdoor Users Keys", Sigma "AWS User Login
  Profile Was Modified", "AWS Lambda Function Invoked Cross-Account", an admin
  password reset told apart from a self-service one in Okta, and the Google
  external group member rule.
- **CIDR.** Blocked: Sigma "External Remote RDP Logon from Public IP" and
  Elastic's seven "RDP/VNC/RPC/SMB from/to the Internet" rules. The endpoint
  area had written private ranges as hand-made regular expressions that were
  wrong for some IPv6 forms.
- **First-seen in a rule.** Hunts run once a day; Elastic's 53 `new_terms`
  rules alert within minutes. For a leaked AWS key the earliest signals, a key
  used from a new address and a first `GetCallerIdentity`, were hunts only.
- **List items.** Google's `events[0].parameters`, M365 `Parameters`,
  `ExtendedProperties` and `ModifiedProperties`, Entra
  `targetResources[].modifiedProperties` and GCP `bindingDeltas` are lists.
  Rules matched them with `contains` or `re` over the list's JSON text, which
  cannot say "the `NEW_VALUE` parameter is `true`" or "this delta adds
  `roles/owner`". Blocked: Marketplace allow-all, Drive "anyone with link",
  Global Admin by role name, per-user MFA state, DKIM disabled, and exact GCP
  IAM grants.
- **Entity fallback.** A vendor alert with no host was keyed `"-"` and merged
  with every other host-less alert of that rule in the same window.

Two defects surfaced in the same review. `contains` built `LIKE '%value%'`
without escaping, so on Postgres and Databricks every backslash in a Windows
path or registry key was read as an escape and the rule silently matched
nothing, and `%` or `_` in a value matched anything. A YAML `true` on a `raw.`
path compiled to `text = boolean`, which Postgres rejects.

## Guide-level explanation

A rule author writes these as follows. Fields are the OCSF paths and
`raw.`/`unmapped.` paths rules already use.

**Literal matching.** Write the value as the vendor logs it; nothing in it is a
wildcard.

```yaml
detection:
  selection:
    process.cmd_line|contains: '\Users\Public\'
    file.path|endswith: 'report_100%.txt'
```

**Booleans on source paths.** Quoted or not, both work.

```yaml
detection:
  selection:
    raw.requestParameters.isMultiRegionTrail: false
```

**Distinct count.** "Five or more distinct users fail from one address within
ten minutes."

```yaml
detection:
  selection:
    api.operation: ConsoleLogin
    status: Failure
  condition: selection
  group_by: [src_endpoint.ip]
  count_distinct: actor.user.name
  count: ">= 5"
  timeframe: 10m
```

The window is the same one a plain threshold uses (D64): a timeframe-long
window starting at one of the group's events must hold N distinct values. The
finding cites one event per value first.

**Sequence.** "A console password set for a user, then that user signs in,
within an hour."

```yaml
detection:
  set_password:
    api.operation: [CreateLoginProfile, UpdateLoginProfile]
  signin:
    api.operation: ConsoleLogin
    status: Success
  sequence:
    by: [actor.user.name]
    first: set_password
    then: signin
    within: 1h
```

`first` and `then` are condition expressions over the blocks (`then: signin
and not filter_sso` works). A sequence rule has no `condition` of its own and
cannot also aggregate. The `then` event fires; the finding cites the earlier
event before it.

**Field reference.** "An access key created for someone other than the caller."

```yaml
detection:
  create:
    api.operation: CreateAccessKey
    raw.requestParameters.userName|exists: true
  self:
    raw.requestParameters.userName|fieldref: actor.user.name
  condition: create and not self
```

Comparison is case-insensitive, like every other equality. Under `not`, an
event where either field is empty counts as different, so pair it with
`exists` as above.

**CIDR.** "An RDP logon from an address outside the private ranges."

```yaml
detection:
  logon:
    api.operation: logon
    src_endpoint.ip|exists: true
  internal:
    src_endpoint.ip|cidr: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, fc00::/7, fe80::/10, ::1/128]
  condition: logon and not internal
```

**First seen in a rule.** "A key used from an address it has not used in the
last 30 days."

```yaml
detection:
  selection:
    actor.session.uid|startswith: AKIA
  condition: selection
baseline:
  first_seen: [actor.session.uid, src_endpoint.ip]
  lookback: 30d
```

The tuple must include `actor.user.name`, `api.operation` or
`src_endpoint.ip`. The rule is silent until the product has events older than
the lookback, and on each account until that account's own sources do. A
first-seen rule cannot also aggregate or be a sequence.

**Entity fallback.**

```yaml
entity: [device.hostname, resource.uid, actor.user.name]
```

**List items.** The mapping declares the list once:

```yaml
# shoc/ingest/mappings/google_workspace.yaml
keyed:
  params:
    path: "events[*].parameters"
    key: name
    value: [value, intValue, boolValue, multiValue]
```

and a rule reads one item by its name:

```yaml
detection:
  selection:
    api.operation: CHANGE_APPLICATION_SETTING
    unmapped.params.SETTING_NAME|contains: marketplace
    unmapped.params.NEW_VALUE: true
```

Without `value`, the item minus its key is written, so a field is one level
down: `unmapped.modified.Role_DisplayName.newValue`. A list of keys nests:
with `key: [action, role]`, GCP's `bindingDeltas` become
`unmapped.deltas.ADD.roles_owner.member`.

**Hunts.** `rare` takes a floor as well as a ceiling. "One session seen from
two or more addresses":

```yaml
baseline:
  rare:
    by: [actor.session.uid]
    among: src_endpoint.ip
    seen_by_at_least: 2
```

## Reference-level explanation

Every rule scan now reads `ocsf_events e`, so a correlated subquery can name
the event being judged. The Detection Engineer's replay and exclusion probes
read the same alias.

- **LIKE.** The value is lower-cased, `!`, `%` and `_` are prefixed with `!`,
  and the clause is `LOWER(col) LIKE :p ESCAPE '!'`. `!` was chosen over a
  backslash because a backslash is LIKE's default escape on Postgres and
  Databricks, nothing on Snowflake, and needs different quoting in each
  dialect's string literal.
- **Booleans.** On a `raw.`/`unmapped.` path a YAML boolean becomes `'true'`
  or `'false'` and compares as text, which is what `JSON_EXTRACT_SCALAR`
  returns on all three backends. No column is boolean, so nothing else changes.
- **`count_distinct`.** The candidate query's `HAVING` uses
  `COUNT(DISTINCT expr)`; the evidence scan selects the field, and the engine
  slides the same window as for a count, keeping a counter of values instead of
  a row count. A NULL value is not counted.
- **`sequence`.** The rule's condition is `then`. The compiler adds
  `EXISTS (SELECT 1 FROM ocsf_events f WHERE f.tenant_id = :tenant_id AND
  <first, products> AND f.<by> = e.<by> AND f.time <= e.time AND f.time >=
  e.time - INTERVAL 'N' SECOND AND f.event_uid <> e.event_uid)` and selects the
  same subquery's `MAX(f.event_uid)` as `sequence_first` for the citation.
  Storing `then` as the condition keeps D77's narrowing working unchanged.
  The cycle's bucket list adds, by `UNION`, the buckets of `then` events that
  pair with a `first` ingested in the cycle, so whichever event arrives last
  completes the pair.
- **`fieldref`.** `LOWER(a) = LOWER(b)`, with an integer column cast to text.
- **`cidr`.** The network is turned into an anchored regular expression in
  Python with `ipaddress` and matched with `REGEXP_LIKE(LOWER(col), :p)`. IPv4
  octets are fixed, a decimal alternation, or `[0-9]{1,3}`. IPv6 matches the
  text the mappings store (lower case, no leading zeros, `::` for the longest
  zero run): fixed groups, then one group as a hex digit range, then `.*`. A
  prefix whose fixed groups include a zero group, or whose partial group can
  start with `0`, has no fixed text and is refused at load time with a request
  to list narrower networks. `64:ff9b::/96` and `::/8` are refused; the
  private, link-local, documentation and global unicast ranges all compile.
  The pattern covers the whole string, so it means the same on Snowflake.
- **`first_seen`.** `_not_seen` is shared with the hunt compiler. For a rule
  the history is the rule's own selection in `[e.time - lookback, e.time)`,
  ties broken by `event_uid`, so a failed attempt from an address does not make
  the successful one familiar (a hunt's history is its products and accounts,
  ingested before its window). A guard,
  `(SELECT MIN(o.time) FROM ocsf_events o WHERE <products>) <= e.time -
  lookback`, keeps the rule quiet until history covers the lookback; Postgres
  runs it once per query. The anti-join probes `(src_endpoint_ip, time)`,
  `(actor_user_name, time)` or `(api_operation, time)`, the indexes the
  Postgres adapter creates, which is why the tuple must include one of those
  fields. The history is per account (`cloud_account_uid`, empty matching
  empty), and the detection cycle binds, per account its sources speak for in
  `shoc.source_history`, the time that account's own data first covers the
  lookback; before then its events are not new (D76, D79).
- **`entity`.** A string or a list; the engine takes the first field, then the
  first `group_by` field, whose value is not NULL or empty. `Rule.to_json`
  joins the list with `, ` so the console's text field is unchanged.
- **`keyed`.** In `Mapping.map_record`, after the residue is built, each
  declared list is read with `dig` (so `[*]` takes the first list that
  resolves) and written to `unmapped.<alias>`. The first item with a given name
  wins, as `[name=x]` already reads it, and an item whose `value` fields are
  all empty is skipped. Characters a rule path cannot hold (anything outside
  `A-Za-z0-9_-`) become `_`.
- **`seen_by_at_least`.** Adds `COUNT(DISTINCT among) >= N` to the `rare`
  `HAVING`; a `rare` baseline needs this, `seen_by_fewer_than`, or both.

Two dialect fixes from DET-1's open list landed with this, because the
conformance cases for list membership needed them: `bind()` no longer reads
Databricks' `raw:a.b` as a `:a` placeholder (a placeholder cannot follow a
name or a colon), and on Snowflake `REGEXP_LIKE`, which matches the whole
string, is written as `REGEXP_INSTR(...) > 0`, which searches like Postgres and
Databricks do.

Membership in a JSON list or object (`raw.x|contains`, `re`, `exists`) relies
on JSON extraction returning the value's JSON text. Postgres writes it with a
space after `,` and `:`; Databricks and Snowflake write it compact. `contains`
on one element's text is portable; a regular expression spanning two elements
must allow `\s*` between them. `tests/unit/test_compiler.py` pins the
translated SQL on all three dialects and `tests/conformance/test_rules.py`
runs the cases on Postgres.

## Drawbacks

- `first_seen` costs one indexed probe per candidate event, over the lookback,
  on the rule's 5-minute cycle. On a warehouse there is no index, and the
  probe is a scan per candidate.
- Keyed lists only exist for events ingested after a mapping declares them.
  A rule that reads one is blind to older events until they age out.
- The CIDR refusal is a real limit: a network such as `64:ff9b::/96` has to be
  written another way.

## Alternatives

- **pySigma.** Still rejected (D11): its backends assume one engine each, and
  we would maintain a backend per dialect anyway.
- **Window functions** (`LAG`, `COUNT(DISTINCT) OVER`). Snowflake and
  Databricks lack `COUNT(DISTINCT)` over a window, and translation of
  framed windows is uneven; the engine already slides windows in Python (D64).
- **JSON-path filters for list items.** Postgres has `jsonb_path_query_first`
  with `?(@.name == "x")`; Databricks and Snowflake paths have no filter, and a
  `LATERAL FLATTEN` or `filter()` is not something SQLGlot translates from one
  canonical form. Ingest is the one place that is the same on every backend.
- **A `inet` column for CIDR.** Only Postgres has the type. Range tests on an
  integer form would need a new column per address field and do not cover
  IPv6 in 64-bit integers.
- **`not_followed_by`.** Considered and left out: "A with no B within an hour"
  cannot be decided until the hour has passed, and the ingestion-driven cycle
  has no notion of a deadline. It needs a delayed re-evaluation of its own.

## Dependency and scope impact

- New dependencies: none (`ipaddress` is in the standard library).
- New required services: none.
- Public contract changes: rule YAML gains `count_distinct`, `sequence`,
  `baseline.first_seen`/`lookback`, list `entity`, and the `cidr` and
  `fieldref` modifiers; hunt YAML gains `rare.seen_by_at_least`; mapping YAML
  gains `keyed`. `contains`/`startswith`/`endswith` change meaning for values
  holding `%`, `_` or a backslash. Where a shipped rule has an `_` in such a value
  (`user.account.reset_password`), it now matches only an underscore, which is
  what the author meant, and every shipped fixture still passes. `Rule.entity` is a
  list in Python.

## Security considerations

Values are still bound as parameters. A CIDR value becomes a pattern built from
`ipaddress` output, never from the rule's text, and is bound. The `by`, `first_seen`
and `fieldref` fields go through `ocsf.column_for`, whose character class stays
the only guard on a JSON path. A keyed-list name is attacker-controlled log
content; it becomes a JSON object key under `unmapped`, filtered to
`A-Za-z0-9_-`, and is never part of SQL text. A first-seen rule's guard means a
tenant whose history is wiped (retention, a restore) goes quiet for one
lookback rather than firing on everything.

## Unresolved questions

- Settled after acceptance: a sequence is also listed from its earlier
  event's side, and first-seen history and learning are per account.
- A second source whose events carry no account id still learns with its
  product, since nothing in its events tells it apart.

## Adoption and migration

No migration. Shipped rules keep their meaning, except that an `_` in a
`contains` value now matches only an underscore. The area rules that
worked around these gaps (regular expressions for private ranges, `contains`
over a parameter list, quoted booleans) can move to the new forms one at a
time; each rule's fixtures still decide whether it passes.
