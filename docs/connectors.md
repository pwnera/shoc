# Sources

shoc reads audit logs from the systems a small company actually runs on, the
way each vendor documents for a SIEM. Every source maps to OCSF through a
versioned YAML file, so a rule written once works across all of them.

## Pull connectors

| Source | Settings | Secret | What it reads |
| --- | --- | --- | --- |
| `aws_cloudtrail` | optional `region` (one or a list; default every enabled region), `backfill_hours`; or `bucket`, optional `prefix` and `bucket_region` | `access_key_id`, `secret_access_key`, optional `session_token` | `LookupEvents`, or the trail's log files in S3 |
| `aws_guardduty` | optional `region` (one or a list; default every enabled region), optional `detector_ids` (one region only) | same as CloudTrail | findings, updated since the cursor |
| `azure_activity` | `subscription_id` (one or a list), `backfill_hours` | `tenant_id`, `client_id`, `client_secret` | Activity Log management events |
| `gcp_audit` | `subscription` (`projects/<p>/subscriptions/<s>`), or `project_id` for the fallback | `client_email`, `private_key` | a Pub/Sub subscription on an audit-log sink, or Cloud Logging `entries.list` |
| `okta` | `org_url` | `api_token` | `/api/v1/logs` |
| `entra` | optional `stream`: any of `signIns`, `nonInteractiveSignIns`, `servicePrincipalSignIns`, `managedIdentitySignIns`, `directoryAudits`, `riskDetections`, `riskyUsers` (default all) | `tenant_id`, `client_id`, `client_secret` | Graph `auditLogs`, every kind of sign-in from the beta endpoint, which is the only one that serves the user agent, protocol and ASN; Identity Protection `riskDetections` and `riskyUsers` |
| `google_workspace` | `admin_email`, optional `application`: any of `admin`, `login`, `token`, `drive` (default all four) | `client_email`, `private_key` | Admin SDK Reports |
| `m365` | optional `content_type`: any of `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General` (default all four) | `tenant_id`, `client_id`, `client_secret` | Management Activity API |
| `defender` | `backfill_hours` | `tenant_id`, `client_id`, `client_secret` | Graph `security/alerts_v2` |
| `defender_hunting` | `storage_account`, optional `tables` (default DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents, DeviceEvents, EmailEvents, EmailUrlInfo, UrlClickEvents, IdentityLogonEvents, CloudAppEvents), `backfill_hours` | `tenant_id`, `client_id`, `client_secret` | Advanced Hunting tables the Defender XDR Streaming API exports to a storage account |
| `crowdstrike` | `cloud` (`eu-1`, `us-1`, `us-2`, `us-gov-1`) | `client_id`, `client_secret` | Falcon Alerts API |
| `crowdstrike_fdr` | `queue_url`, optional `event_names` (`["*"]` for every event) | `access_key_id`, `secret_access_key` from the FDR feed | Falcon Data Replicator: raw sensor events from the SQS queue and S3 bucket CrowdStrike provisions |
| `sentinelone` | `console_url` | `api_token` | `/web/api/v2.1/threats`, and Unified Alert Management (STAR, identity and cloud alerts) |
| `sentinelone_cloudfunnel` | `bucket`, optional `prefix` (default `s1/cloud_funnel`), `bucket_region`, `event_categories`, `backfill_hours` | `access_key_id`, `secret_access_key`, optional `session_token` | Cloud Funnel 2.0 telemetry in your S3 bucket |
| `github` | `org` | `token` | organisation audit log (GitHub Enterprise Cloud only; other plans push a [webhook](#github-on-the-free-and-team-plans)) |
| `gitlab` | optional `group`, `base_url` | `token` | audit events (group, or the instance), each named by its audit event type (`member_updated`, `deploy_key_added`) |
| `wazuh` | `indexer_url`, optional `index`, `verify_tls` | `username`, `password` | `wazuh-alerts-*` in the Wazuh indexer |
| `cloudflare` | `account_id` | `api_token` | account audit log (Audit Logs v2) |
| `cloudflare_logs` | `bucket`, `datasets` (dataset → the job's path, e.g. `{"http_requests": "logs/http", "gateway_dns": "zt/dns"}`), `account_id` for R2 or `bucket_region` for S3, `backfill_hours` | `access_key_id`, `secret_access_key` (an R2 API token's S3 credentials, or AWS keys) | Logpush jobs' files in R2 or S3: HTTP requests, firewall events, DNS, Gateway DNS/HTTP/network, Access requests, Zero Trust sessions, audit logs |
| `tailscale` | optional `tailnet` (default `-`, the credential's own) | `client_id`, `client_secret` of an OAuth client, or an `api_key` access token | configuration audit log |
| `stripe` | none | `api_key`, a restricted key | activity log (a public preview), and `charge.failed` and early fraud warning events |
| `openai` | none | `admin_key` | organization audit log, and hourly usage per API key |
| `anthropic` | optional `activity_feed` | `admin_key` | the Compliance API activity feed when `activity_feed` is on, API keys created since the last read, and hourly usage per API key |
| `file` | `path`, `mapping`, optional `as_recorded`, `skip_unreadable` | none | replays a recorded file; used by evals and the quick start |

A setting that picks a stream takes one value or a list: a Workspace
application, an Entra log, an M365 content type, an AWS region, an Azure
subscription. Each stream keeps its own cursor, and one that fails is reported
while the others go on loading. Entra sign-in logs need an Entra ID P1 or P2
licence; without one, set `stream` to `directoryAudits`. Risk detections and risky
users need P1 or P2, and carry their risk level only on P2.

`LookupEvents` returns 50 events a call, two calls a second per region, and
management events only, so a busy AWS account outgrows it. Set `bucket` to the
trail's S3 bucket and shoc reads the trail's own log files instead: every
account and region under `AWSLogs/`, organisation trails included, each with its
own position. `prefix` is the trail's key prefix, if it has one; `region`
narrows it to some regions. The bucket's region is found on the first call.
Rules on S3 object reads and writes (`aws_s3_mass_object_read`,
`aws_s3_sse_c_encryption`) need data events, which only the bucket mode sees,
and only on a trail that records S3 data events; LookupEvents never returns
them. Such a rule says so in its `logsource.definition`, and while the source
reads LookupEvents its onboarding lists the rule as one the source cannot carry
until `bucket` is set. The SMS half of the `aws_sns_sms_first_use` hunt needs
SNS data events the same way; onboarding does not list hunts. A stopped
trail stops writing to its bucket, while LookupEvents keeps recording, so in the
bucket mode the `StopLogging` event is the last one shoc sees from that trail.

Without `region`, or with `region: all`, `LookupEvents` and GuardDuty are read
in every region the account has enabled, as `ec2:DescribeRegions` lists them.
Miners are launched in regions nobody watches, so a single region misses them.
IAM, Organizations and global-endpoint STS events are recorded in `us-east-1`
only. With
`bucket`, every region under the trail's prefix is read already; point it at a
multi-region or organisation trail.

Cloudflare sends traffic and Zero Trust logs to a SIEM through Logpush. Point
one Logpush job per dataset at an R2 bucket (or S3) with `{DATE}` in its path,
as Cloudflare recommends, and give shoc the bucket and, per dataset, the path
the job writes to: `logs/http` stands for `logs/http/{DATE}`, and a path that
contains `{DATE}` itself (`logs/http/date={DATE}`) is taken as written. With
`account_id` set, shoc reads `<account_id>.r2.cloudflarestorage.com`; without
it, S3 in `bucket_region`. Jobs must keep the default NDJSON output. The
account audit log is read from the API by `cloudflare`; an `audit_logs` job
pointed here maps to the same class.

Defender XDR sends its Advanced Hunting tables to a SIEM through the Streaming
API. Point it at an Azure storage account (Settings → Microsoft Defender XDR →
Streaming API → Forward events to Azure Storage), choose the tables, and give
shoc the account name. Each table lands in its own container,
`insights-logs-advancedhunting-<table>`, one blob per hour; shoc keeps its
place in each blob and reads what was appended since. Alerts are read by
`defender` from Graph, so AlertInfo and AlertEvidence are only read when named
in `tables`.

```bash
shoc source configure --source entra \
  --settings '{"stream": "directoryAudits"}' \
  --secret-file ./entra.json        # or --secret-file - to read stdin
shoc source sync --source entra
shoc source list
```

`--secret '{…}'` works too, but a credential on a command line is a credential
in shell history and in the process list. `shoc.yaml` with `secret_env` is the
other way round: it names the environment variable rather than the value, and
[`deploy.md`](deploy.md) covers it.

Configuring a source tries the credential once before answering, so a token
that is wrong, expired or missing a permission says so there and then:

```
Source okta configured, polling every 300s. It is saved, but the credential
did not work: okta rejected the credential (401); it needs an API token of a
read-only administrator, which reads the System Log, users and network zones.
```

The source is still written down, so you can configure one before the
permission has been granted; `--no-verify` skips the check. The check reads one
record and leaves the stored cursor alone, so the first scheduled sync still
starts from the backfill window. `shoc source sync`
exits non-zero when a pull fails, so a cron job or a CI step notices.

A second account of the same vendor is its own source, named after the
connector and a label: `cloudflare:acme`. It has its own settings, credential,
cursor, schedule and health, and its events go through the connector's mapping.
The label takes lowercase letters, digits, `_` and `-`. A second GitHub
organisation that pushes posts to `/ingest/github:acme` with its own push key.

```bash
shoc source configure --source cloudflare:acme \
  --settings '{"account_id": "…"}' --secret-file ./cloudflare-acme.json
```

Each event names the account it belongs to in `cloud_account_uid`, which is how
a response picks the tenant to act in ([response](response.md)). Most records
carry it themselves. Okta and GitLab records do not, so their events get the
org host from `org_url` and the GitLab group. For any other source whose
records name no account, set an `account` setting and its events carry that.

`shoc source remove --source okta` disconnects a source. Its settings,
credential, cursor and schedule go; the events it already delivered stay until
retention drops them.

Cursors survive restarts: each connector stores where it got to in
`shoc.connector_state`. While a connector follows a provider's page token, its
time filter stays where the walk began, because the token belongs to that
filter. Once the pages run out, the next window starts 15 minutes before the
newest event read, so an event the provider delivers late, with an earlier
timestamp, is still picked up. Each run keeps a digest of the `event_uid` and
time of every row it read and stored, and the next run sends the store only the
rows it lacks, so a quiet source that reads the same page every poll costs a
warehouse nothing (D150). `events_seen` counts only the rows that were new. GuardDuty keeps a window per detector. Microsoft 365
lists content by when it became available rather than by when the activity
happened, so its cursor follows availability, in windows of at most 24 hours
and never more than 7 days back; content Microsoft publishes hours late is
still in the next window.

### Onboarding

The Integrator works each configured source once a day, or on demand with
`shoc source onboard --source okta`. It moves a source through `discover`,
`credentials`, `map`, `prove` and `done`: it names what is still dark, writes
the least-privilege scopes and click path when it is waiting on a credential,
samples a page (`shoc source sample`, which stores nothing), and lists which
rules the source's fields can and cannot carry (`shoc mapping test`). A source
is `done` only when one of its events has become a finding, and that finding is
recorded in `shoc.source_onboarding` as the proof. See
[`ontology.md`](ontology.md) for the states.

`shoc source list` returns that progress for every source, and for every
connector the permission to grant and the settings and secret keys
`source configure` expects; the console's Connections screen builds its connect
form from it. When a source starts waiting on a credential, the Integrator tells
the Manager once, and the scopes and click path reach the weekly report. An
install with nothing connected is told so once a week.

When a vendor moves a field, a column a rule reads goes empty and the field
lands in `unmapped`. The Integrator then asks the configured model, once per
change of shape, which new field carries that column, and keeps the answer in
`shoc.mapping_overrides` for this tenant only if its recent events fill no
column less and one more. The `mapping.write` capability does the same by
hand, and an empty `fields` restores the shipped mapping.

### Permissions to grant

Give every connector a read-only credential, scoped as narrowly as the provider
allows:

| Source | Permission |
| --- | --- |
| AWS CloudTrail | `cloudtrail:LookupEvents`, and `ec2:DescribeRegions` unless `region` is set; with `bucket`, `s3:ListBucket` on the bucket and `s3:GetObject` on `AWSLogs/*` (and `kms:Decrypt` if the trail uses a KMS key) |
| AWS GuardDuty | `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings`, and `ec2:DescribeRegions` unless `region` is set |
| Okta | API token of a read-only administrator; it reads the System Log, users and network zones |
| Entra ID | Graph application permissions `AuditLog.Read.All`, `Directory.Read.All`, and for Identity Protection `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All` |
| Google Workspace | Service account with domain-wide delegation for `https://www.googleapis.com/auth/admin.reports.audit.readonly`, and the Admin SDK API enabled in its Cloud project; `admin_email` is a user whose only admin role has the Reports privilege |
| Microsoft 365 | `ActivityFeed.Read` on the Management API |
| GitHub | Fine-grained token with organisation `Administration: read`; the audit-log API answers 404 unless the organisation is on GitHub Enterprise Cloud, so other plans send a webhook instead |
| GitLab | Personal or group access token with `read_api`; instance-wide events need an administrator |
| Azure Activity Log | `Reader` on the subscription, granted to the same app registration as Entra ID |
| GCP Cloud Audit | Service account with `roles/pubsub.subscriber` on the sink's subscription; `roles/logging.viewer` on the project for the `project_id` fallback |
| Defender | Graph application permission `SecurityAlert.Read.All` |
| Defender Advanced Hunting | `Storage Blob Data Reader` on the Streaming API's storage account |
| CrowdStrike Falcon | API client with the `Alerts: read` scope |
| CrowdStrike FDR | The key pair of an FDR feed; CrowdStrike scopes it to that feed's queue and bucket |
| SentinelOne | Service-user API token with viewer rights |
| SentinelOne Cloud Funnel | `s3:ListBucket` and `s3:GetObject` on the Cloud Funnel bucket |
| Wazuh | Indexer user whose role reads `wazuh-alerts-*` (port 9200) |
| Cloudflare | Account API token with `Account Settings: Read` |
| Cloudflare Logpush | R2 API token with Object Read on the Logpush bucket; for S3, `s3:ListBucket` and `s3:GetObject` on it |
| Tailscale | OAuth client (Trust credentials) with the Audit Logs read scope; an API access token works too, and expires within 90 days |
| Stripe | Restricted key with `Activity logs: read` and `Events: read` |
| OpenAI | Admin key with audit logs read, which only an organization owner can create. An owner first turns audit logging on in the organization's data controls; nothing before that day is recorded |
| Anthropic | Admin API key, which only an organization admin can create; an individual account has no Admin API |

Stripe counts every API read against an allowance that starts at 10,000 a
month, and its connector makes two per poll, so give it
`--interval-seconds 900`. The OpenAI and Anthropic connectors read usage an hour
at a time once the hour has closed, which puts a key's usage in shoc 30 to 90
minutes after it happened. The first read takes the last seven days of usage.
Their usage rules band a key's hourly output tokens by order of magnitude from
one million, and fire the first hour a key works in a band it has not worked in
for seven days.

An EDR's alerts and its raw telemetry are separate sources. `crowdstrike`,
`sentinelone`, `defender` and `wazuh` read alerts, which carry the evidence a finding
cites. `crowdstrike_fdr`, `sentinelone_cloudfunnel` and `defender_hunting` read
the device events behind them, one to two orders of magnitude larger, from the
place each vendor exports them to; each keeps a default list of event kinds and
drops the rest before it reaches the store. Telemetry rows are never Detection
Findings (class 2004), except AlertInfo and AlertEvidence when they are named in
`defender_hunting`'s `tables`, so a rule written for alerts does not fire on them. A
rule reads alerts with `logsource: {product: edr, service: alerts}`, telemetry
with `service: telemetry`, and DNS names from Gateway and all three sensors with
`product: dns`. Every row's `device.uid` is the device's id: Falcon's `aid`,
Defender's `machineId` or `DeviceId`, and the SentinelOne agent UUID, which
`sentinelone.isolate_host` looks up to the console's agent id. It is the `device` entity
a playbook isolates (RFC 0026). `resource.uid` is not: on a registry or
scheduled-task row it is the key or the task.

A vendor alert keeps the vendor's severity, with two adjustments. An alert the
agent already stopped (SentinelOne `mitigated`, Falcon "Prevention, ...") drops
one band, to medium, and a critical one stays critical. A Defender alert that
Defender or an analyst classified as a false positive, expected activity or a
security test before shoc read it is informational. Defender's `serviceSource`
and Falcon's `product` go to `api.service.name`, so the endpoint rules leave out
Office 365, Identity, Cloud Apps, Entra ID Protection and Falcon Identity alerts.

Falcon Data Replicator keeps process starts, DNS requests, network
connections, logons, account changes, executable and script writes, scheduled
tasks, service starts and autorun registry values by default; `event_names`
changes that list and `["*"]` keeps everything FDR sends. FDR events carry no
host name (it lives in the `aidmaster` inventory, which shoc skips), so rules
and hunts on telemetry key on the device id.

Defender's Streaming API writes `AdditionalFields` as JSON text; the
`defender_hunting` connector decodes it, so a rule can read
`raw.properties.AdditionalFields.<key>` and a `DnsQueryResponse` row fills
`query.hostname` from `DnsQueryString`.

Cloud Funnel 2.0 writes gzipped NDJSON into a bucket you own, under
`s1/cloud_funnel/YYYY/MM/DD/account_id=<account>/`. shoc reads every account
under that prefix and maps each record by `event.category`. `event_categories`
keeps process, command_script, logins, scheduled_task, driver, dns, ip, url,
indicators, threat_intelligence_indicators and windows_event_logs by default
and leaves out file, registry, module and cross_process; `all` keeps
everything. The filter applies after download, so narrow the stream in
SentinelOne's Cloud Funnel settings too.

## How each source is read

Every source is read the way its vendor documents for a SIEM, and nothing needs
installing on the vendor's side. For almost all of them that is shoc calling
the vendor's API over HTTPS with a read-only credential. Where the vendor
recommends a delivery of its own, shoc reads that:

| Source | Read from | Why |
| --- | --- | --- |
| GCP Cloud Audit | a Pub/Sub pull subscription on a log sink (`subscription`) | Google says `entries.list` is not meant for high-volume reads, and caps it at 60 calls a minute; it remains the fallback when no subscription is set |
| AWS CloudTrail | the trail's S3 bucket (`bucket`) | LookupEvents returns management events only, 50 at a time; it remains the fallback |
| Wazuh | the Wazuh indexer, `wazuh-alerts-*` | the route Wazuh documents for a third-party SIEM |
| CrowdStrike FDR | the SQS queue and S3 bucket of a Falcon Data Replicator feed | the route CrowdStrike documents for a SIEM to receive raw sensor events; detections still come from the Alerts API (`crowdstrike`) |
| Cloudflare Logpush | the R2 or S3 bucket each Logpush job writes to | Cloudflare has no pull API for its traffic logs; Logpush is its route to a SIEM |
| Defender Advanced Hunting | the storage account the Streaming API writes to | Microsoft's route for exporting Advanced Hunting tables to a SIEM; alerts still come from Graph (`defender`) |
| SentinelOne Cloud Funnel | the S3 bucket Cloud Funnel 2.0 writes to | SentinelOne's route for handing Deep Visibility telemetry to a SIEM; threats and alerts still come from the API (`sentinelone`) |
| Anthropic | the Compliance API activity feed (`activity_feed`) where the organisation has it | Anthropic's audit log; key usage is read either way |
| GitHub | the audit-log API, or the organisation webhook on other plans | GitHub's own signed push, below |

A vendor's push is taken only as the vendor sends it, and today that is
GitHub's webhook. The EDRs, GitLab and Wazuh push in forms of their own
(CrowdStrike's workflow webhooks, SentinelOne's notifications, Wazuh's
integrator) that carry no signature shoc could check against its own, so shoc
polls them.

### GitHub on the Free and Team plans

The audit-log API is for GitHub Enterprise Cloud only. Every other plan can send
an organisation webhook, and `/ingest/github` takes it as GitHub sends it:

```bash
shoc source configure --source github --settings '{}'
shoc source push-key --source github     # shown once
```

In the organisation's Settings → Webhooks, add a webhook with:

| Field | Value |
| --- | --- |
| Payload URL | `https://<your shoc>/ingest/github?tenant=<tenant id>` |
| Content type | `application/json` (the form-encoded default works too) |
| Secret | the push key |
| Events | `organization`, `repository`, `public` (Visibility changes), `member`, `team` (Teams), `team_add` (Team adds), `membership`, `branch_protection_rule`, `branch_protection_configuration`, `repository_ruleset` (Repository rulesets), `release` (Releases), `deploy_key`, `org_block`, `meta`, `secret_scanning_alert`, `security_and_analysis`, `personal_access_token_request`, `dependabot_alert`, `push`, `create`, `delete`, `workflow_job`, `workflow_run` |

GitHub sends no bearer token, so the request is authenticated by its
`X-Hub-Signature-256` alone, and `/ingest/github` refuses every webhook until a
push key exists. Each event is recorded under the audit-log action for the same
change (`repository.publicized` is `repo.access`), so the GitHub rules work on
either. A release has no audit-log action and stays `release.<action>`;
`team_add` stays `team_add`, because the `team` event already records the same
change as `team.add_repository`. A webhook carries no source address, so rules
and questions that read `src_endpoint.ip` get nothing from it.

The webhook covers less than the audit log. GitHub sends no webhook for a
classic personal access token, an SSH key, an OAuth app grant, a change to
organisation settings or member roles, or a Git clone or push by token; those
reach shoc only through the audit-log API on Enterprise Cloud. Neither the
webhook nor the audit log records a GitHub sign-in. Without SSO it sits in the
user's own security log, which the organisation cannot read; with SAML SSO on
Enterprise Cloud the identity provider records it, and shoc reads it through
that provider's connector.

## Trying a source without credentials

`datasets/manifest.yaml` lists public raw logs per source, and
`scripts/fetch_dataset.py` fetches one into `var/datasets/` to replay through the
`file` connector. See [`datasets.md`](datasets.md), which is also where we are
honest about the sources nothing public covers.

## Writing a new connector

```bash
shoc new connector fastly
```

That writes the module, the OCSF mapping and a mapping fixture. Any module in
`shoc/ingest/connectors/` that defines `CONNECTOR` is picked up, a module that
also defines `from_webhook` takes its vendor's push as well, and a mapping with
no module is a push-only source. A rule's `logsource.product` reads the events
of every mapping that lists it under `logsource` (`product` or
`product/service`); a mapping that lists none answers to its own name, and a
product no mapping answers to matches nothing. Fill in `fetch()`, then:

```bash
pytest tests/unit/test_mappings_all.py -k fastly
```

The run loop gives you cursors, batching, deduplication and health accounting;
a connector only answers "what happened after this cursor?". Keep `since` where
it was while a page token is in the cursor, and set it to the newest event time
once the pages run out; the run loop applies the overlap.

A new platform also ships its own response actions under `shoc/actions/`, with
`platforms` naming the product its rules carry; CI fails when a platform we
ingest has no action of its own ([`response.md`](response.md), D56).

### Mapping language

A mapping is data, not code. `fields` map source paths to OCSF columns,
`constants` set what is always true for the source, and `derive` adjusts values
based on the record. The columns and the classes in use are listed in
[OCSF model](ocsf.md).

```yaml
fields:
  actor_user_name: { paths: [userIdentity.userName, userIdentity.arn], transform: arn_name }
  time: { path: eventTime, transform: iso8601 }
derive:
  - when: { errorCode: { exists: true } }
    set: { status: Failure, severity_id: 2 }
  - when: { "rule.level": { gte: 10 } }
    set: { severity_id: 4 }
```

A path can reach into a list: `evidence[0].ipAddress` takes that slot, and
`evidence[*].ipAddress` takes the first item of the list that resolves to
something, which is how a provider's evidence or target array is read without
knowing which slot holds the user. `events[0].parameters[name=doc_id].value`
takes the item whose `name` is `doc_id`, for a list keyed by name the way
Workspace writes its parameters. Where a provider puts an object in a field
OCSF types as text (GitLab's `details.with`, for one), the value is kept as
compact JSON rather than dropped.

A rule cannot select a list item by key, because the warehouses' JSON paths
have no filter. A mapping that wants rules to read such a list declares
it under `keyed`, and the list is also written as an object under
`unmapped.<alias>`, keyed by the items' names (RFC 0023):

```yaml
keyed:
  params: { path: "events[*].parameters", key: name, value: [value, intValue, boolValue, multiValue] }
  modified: { path: "targetResources[*].modifiedProperties", key: displayName }
  deltas: { path: protoPayload.serviceData.policyDelta.bindingDeltas, key: [action, role] }
```

A rule then reads `unmapped.params.NEW_VALUE`,
`unmapped.modified.Role_DisplayName.newValue` or
`unmapped.deltas.ADD.roles_owner.member`. `value` takes the first of those
fields an item has; without it the item minus its key is written. A list of
keys nests. The first item with a given name wins, and a character a rule path
cannot hold becomes `_`.

Supported conditions are `exists`, `equals`, `in`, `contains` and the numeric
comparisons `gt`, `gte`, `lt`, `lte`. Later rules win, so numeric bands are
written lowest first.

A `set` value may be a field spec instead of a literal, `{ paths: [FileName] }`,
so one class takes a column from a different field than the rest of the source:
Defender's process table names the started process in `FileName`, every other
table in `InitiatingProcessFileName`.

### Fields no column holds

A mapping flattens what every source has in common. The rest of the record is
kept twice: `raw` is the record exactly as it arrived, and `unmapped` is what no
field path read, pruned leaf by leaf: mapping `client.ipAddress` retires that
leaf and leaves `client.zone` and `client.device` in place.

Both are addressable from a rule or a query by their source path, so a mapping
does not have to anticipate every field a detection will want:

```yaml
detection:
  selection:
    eventType: user.session.start
    raw.debugContext.debugData.dtHash: 7e3f1a…
    unmapped.client.zone: OffNetwork
  condition: selection
```

The path is translated to the backend's JSON extraction, so the same rule runs
unchanged on every backend. The value comes back as text;
`gt`, `gte`, `lt` and `lte` compare it as a number and skip rows where the same
key holds something that is not one. Only `[A-Za-z0-9_@$-]` path segments
resolve, which is what keeps a path from reaching outside its string literal.

These paths are not indexed. A rule that narrows on ordinary columns first and
uses a source path to confirm stays cheap; one whose only predicate is a source
path scans the window.
