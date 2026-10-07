# OCSF model

Every source is mapped to [OCSF](https://schema.ocsf.io) **1.3.0** (ING-3). The
version is set per mapping by `ocsf_version` in `shoc/ingest/mappings/<source>.yaml`
and written to `metadata_version` on each event. A vendor's own record version
(CloudTrail's `eventVersion`) stays in `unmapped`.

## Storage shape

Events live in one table, `ocsf_events`, with the same columns on every backend
(STO-1, `shoc/store/ocsf.py`). shoc does not store nested OCSF objects. It keeps
a fixed set of OCSF attributes as flat columns, and the rest of the record in
two JSON columns:

- `raw` holds the source record as it arrived. A rule or query reads any field
  in it as `raw.<source path>`, for example `raw.debugContext.debugData.dtHash`.
- `unmapped` holds the leaves no mapping read, so a field a vendor adds later is
  visible there before anyone maps it.

The column list is part of the [public contract](contract.md): adding a column is
a minor release, removing one is a major.

| OCSF attribute | Column |
| --- | --- |
| `time` | `time` |
| `class_uid`, `class_name`, `category_uid` | same names |
| `activity_id`, `activity_name`, `type_uid` | same names |
| `severity_id`, `status`, `status_code`, `message` | same names |
| `actor.user.name`, `.uid`, `.type` | `actor_user_name`, `actor_user_uid`, `actor_user_type` |
| `actor.session.uid` | `actor_session_uid` |
| `actor.invoked_by` | `actor_invoked_by` |
| `src_endpoint.ip`, `.domain`, `.port`, `.asn` | `src_endpoint_ip`, `src_endpoint_domain`, `src_endpoint_port`, `src_endpoint_asn` |
| `src_endpoint.location.country` | `src_endpoint_location_country` |
| `dst_endpoint.ip`, `.domain`, `.port` | `dst_endpoint_ip`, `dst_endpoint_domain`, `dst_endpoint_port` |
| `query.hostname` | `dns_query_hostname` |
| `http_request.url.url_string` | `http_request_url` |
| `http_request.user_agent` | `http_user_agent` |
| `api.operation`, `api.service.name` | `api_operation`, `api_service_name` |
| `api.response.code`, `api.response.error` | `api_response_code`, `api_response_error` |
| `cloud.provider`, `cloud.account.uid`, `cloud.region` | `cloud_provider`, `cloud_account_uid`, `cloud_region` |
| `resource.type`, `resource.uid` | `resource_type`, `resource_uid` |
| `device.hostname`, `device.uid` | `device_hostname`, `device_uid` |
| `process.name`, `process.pid`, `process.cmd_line` | `process_name`, `process_pid`, `process_cmd_line` |
| `process.file.path`, `process.file.hashes.sha256` | `process_file_path`, `process_hash_sha256` |
| `process.parent_process.name` | `process_parent_name` |
| `file.path`, `file.hashes.sha256` | `file_path`, `file_hash_sha256` |
| `metadata.product.name`, `metadata.version` | `metadata_product`, `metadata_version` |
| `metadata.profiles` | `metadata_profiles` |
| `observables` | `observables` (JSON) |

`tenant_id`, `event_uid` and `ingested_at` complete the row. A rule names a field
by its OCSF path (`actor.user.name`), its column name, or a `raw.` / `unmapped.`
path; all three resolve to the same column.

`resource` and `device` are singular here, where OCSF has `resources[]` on some
classes. A mapping picks the resource the event is about. Other targets stay in
`raw`.

## Classes in use

Each mapping sets a default class in `constants` and moves an event to another
class with a `derive` rule when its type calls for it. These are the classes the
shipped mappings write, by OCSF category.

### System Activity (1)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| File System Activity | 1001 | `crowdstrike_fdr`, `defender_hunting`, `sentinelone_cloudfunnel` |
| Kernel Extension Activity | 1002 | `sentinelone_cloudfunnel` |
| Memory Activity | 1004 | `defender_hunting` |
| Module Activity | 1005 | `crowdstrike`, `crowdstrike_fdr`, `defender_hunting`, `sentinelone_cloudfunnel` |
| Scheduled Job Activity | 1006 | `crowdstrike_fdr`, `defender_hunting`, `github` (workflow runs and jobs), `sentinelone_cloudfunnel` |
| Process Activity | 1007 | `crowdstrike`, `crowdstrike_fdr`, `defender_hunting`, `sentinelone_cloudfunnel` |
| Event Log Activity | 1008 | `sentinelone_cloudfunnel` |
| Registry Key Activity | 201001 | `defender_hunting`, `sentinelone_cloudfunnel` |
| Registry Value Activity | 201002 | `crowdstrike_fdr`, `defender_hunting`, `sentinelone_cloudfunnel` |

The two registry classes come from the OCSF Windows extension, which is why
their `class_uid` has six digits.

### Findings (2)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| Vulnerability Finding | 2002 | `github` (Dependabot alerts) |
| Detection Finding | 2004 | `aws_cloudtrail`, `aws_guardduty`, `azure_activity`, `crowdstrike`, `defender`, `defender_hunting`, `entra`, `gcp_audit`, `github`, `google_workspace`, `m365`, `okta`, `sentinelone`, `wazuh` |

Class 2004 is a vendor's own alert. shoc's detections are stored as findings in
Postgres, not as events. Telemetry sources (`crowdstrike_fdr`,
`sentinelone_cloudfunnel`, `cloudflare_logs`) never write 2004 (D75).

### Identity & Access Management (3)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| Account Change | 3001 | `crowdstrike_fdr`, `defender_hunting`, `entra`, `gcp_audit`, `google_workspace`, `m365`, `okta`, `sentinelone`, `sentinelone_cloudfunnel` |
| Authentication | 3002 | `aws_cloudtrail`, `cloudflare_logs`, `crowdstrike`, `crowdstrike_fdr`, `defender_hunting`, `entra`, `gcp_audit`, `google_workspace`, `m365`, `okta`, `sentinelone`, `sentinelone_cloudfunnel`, `tailscale` |
| Entity Management | 3004 | `entra`, `m365`, `okta` |
| User Access Management | 3005 | `entra`, `google_workspace`, `m365`, `okta` |
| Group Management | 3006 | `crowdstrike_fdr`, `defender_hunting`, `entra`, `google_workspace`, `m365`, `okta`, `sentinelone_cloudfunnel` |

### Network Activity (4)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| Network Activity | 4001 | `cloudflare_logs`, `crowdstrike`, `crowdstrike_fdr`, `defender_hunting`, `sentinelone`, `sentinelone_cloudfunnel` |
| HTTP Activity | 4002 | `cloudflare_logs`, `defender_hunting`, `m365`, `sentinelone_cloudfunnel` |
| DNS Activity | 4003 | `cloudflare_logs`, `crowdstrike_fdr`, `defender_hunting`, `sentinelone_cloudfunnel` |
| Email Activity | 4009 | `defender_hunting`, `m365` |
| Email File Activity | 4011 | `defender_hunting` |
| Email URL Activity | 4012 | `defender_hunting` |

### Discovery (5)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| Device Inventory Info | 5001 | `crowdstrike`, `defender_hunting` |
| User Inventory Info | 5003 | `crowdstrike`, `defender_hunting` |
| File Query | 5007 | `defender_hunting` |

### Application Activity (6)

| Class | `class_uid` | Sources |
| --- | --- | --- |
| Web Resources Activity | 6001 | `google_workspace` (Drive), `m365` (SharePoint, OneDrive) |
| API Activity | 6003 | `anthropic`, `aws_cloudtrail`, `azure_activity`, `cloudflare`, `cloudflare_logs`, `crowdstrike`, `defender_hunting`, `entra`, `gcp_audit`, `github`, `gitlab`, `google_workspace`, `m365`, `openai`, `sentinelone`, `stripe`, `tailscale` |
| Datastore Activity | 6005 | `defender_hunting` |

API Activity is the default for audit logs: an event lands there until a
`derive` rule places it in a narrower class.

## Activities and `type_uid`

`activity_id` and `activity_name` follow the class's OCSF enum, and `type_uid` is
`class_uid * 100 + activity_id`. When a mapping knows only the class, it writes
activity 99 (`Other`). The loader sets `type_uid`, and `category_uid` as
`class_uid % 100000 // 1000` so an extension class keeps its core category, after
the last `derive`, so a rule that moves the class or
the activity cannot leave them stale.

An API call is `Create` (1), `Read` (2), `Update` (3) or `Delete` (4) when
its verb says which, and `Other` (99) when it does not, in CloudTrail, Azure
Activity and GCP Audit alike. Azure's `/write` creates or updates, and is
`Update`.

## Observables

A mapping lists which columns become observables and with which OCSF type. The
types in use are `IP Address`, `Domain Name`, `URL String`, `Hostname`, `User`,
`Email Address`, `Account UID`, `Session UID`, `Access Key`, `Process Name`,
`File Name`, `File Hash`, `Device`, `Resource` and `Other`. The indicator matcher compares
indicators against columns of the matching type only (D75).

## Not modelled

- **Profiles.** `metadata_profiles` exists as a column, and no shipped mapping
  fills it.
- **Enrichments.** Geolocation and ASN come from the vendor record when it has
  them. shoc adds no `enrichments[]`.
- **Nested objects.** Any OCSF attribute outside the table above is not a
  column. Read it from `raw` by its source path, or propose a column; a new
  column is a minor release.

Known deviations from OCSF 1.3.0 are listed under ING-3 in
[the requirements](prd.md).

## Adding a class

Pick the OCSF 1.3.0 class whose definition fits the event, set `class_uid`,
`class_name`, `activity_id` and `activity_name` together, and add a fixture for
that event type. The mapping language is
described in [Sources](connectors.md#mapping-language).
