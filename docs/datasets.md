# Public datasets

Detections and mappings are only as honest as the records they were written
against, and vendor documentation is not records. `datasets/manifest.yaml` lists
public raw logs per source, and `scripts/fetch_dataset.py` downloads them into
`var/datasets/`, which is never committed.

```bash
python scripts/fetch_dataset.py --list
python scripts/fetch_dataset.py --source aws_cloudtrail
python scripts/fetch_dataset.py --name google-workspace-invictus
```

Then replay a dataset through the `file` connector, which reads JSON, NDJSON and
`.gz`, walks a directory one file per page, and unwraps the envelope a provider
puts around an export (`Records`, `value`, `entries`, `items`, `data`,
`alerts`, `activities`):

```bash
shoc source configure --source file --settings \
  '{"path": "var/datasets/cloudtrail-flaws", "mapping": "aws_cloudtrail", "as_recorded": true}'
shoc source sync --source file
```

Some datasets need one step before they are raw again, and the manifest carries
it: `prepare` is a command the fetcher prints (unpacking a `.7z`, filtering
Cloud Logging down to audit entries, or running
`scripts/unwrap_splunk_csv.py`, which pulls the original record out of the column
a Splunk export buried it in). A dataset published through Git LFS is fetched
from the media host, so no `git lfs` is needed. Where a published set carries a
stray file that is not records at all (two of Splunk's Okta files are
key=value notable-event exports), the entry replays with `skip_unreadable`, and
the connector logs each file it skips. Without that setting a file it cannot
parse is an error, because usually it means the wrong path.

`as_recorded` keeps the original timestamps. Leave it out and a recorded scenario
(records carrying `_repeat`) is replayed as if it were happening now, which is
what `evals/` wants and what a historical dataset does not. A real export keeps
its own timestamps either way; `scripts/replay_datasets.py` loads one shifted so
its newest event lands two hours before now (`--margin-hours`), which puts it
back inside the detection windows. The script refuses a tenant that reads live
sources, where those events would open real cases: load into a tenant of its
own (`SHOC_TENANT=lab`, after `shoc --tenant lab migrate`), or pass `--force`.

## Checking a mapping against it

```bash
python scripts/probe_dataset.py --name cloudtrail-flaws --limit 20000
```

That maps the records with no database in sight (4,000 unless `--limit` says
otherwise) and prints how many distinct `event_uid` they made, how much of each
column got filled, and the source keys nothing consumed. Fewer than 90% distinct
is a warning: rows deduplicate on `(event_uid, time)`, so the mapping is
throwing events away.

```
cloudtrail-flaws as aws_cloudtrail: 20000 record(s) mapped, … distinct event_uid
  filled: time=100% api_operation=100% actor_user_name=89% src_endpoint_ip=100% resource_uid=11% status=100%
  unmapped keys: eventType, requestParameters, requestID, responseElements, readOnly
```

Low numbers are a question, not a verdict: CloudTrail fills `resource_uid` 11% of
the time because most management events have no single resource, and the Azure
Activity Log fills `src_endpoint_ip` 40% of the time because policy and system
events have no caller. A column at 0%, on the other hand, means a wrong path:
that is how the Entra mapping was found to miss the Event Hub envelope and the
Defender mapping to be guessing at evidence positions.

What the shipped mappings do on real records today:

| Dataset | Records probed | time | operation | user | ip |
| --- | --- | --- | --- | --- | --- |
| cloudtrail-flaws | 20,000 | 100% | 100% | 89% | 100% |
| azure-activity-zenodo | 4,000 | 100% | 100% | 98% | 40% |
| gcp-audit-zenodo (filtered) | 4,000 | 100% | 99% | 95% | 85% |
| google-workspace-invictus | 4,000 | 100% | 100% | 100% | 99% |
| okta-system-shape | 53 | 100% | 100% | 100% | 89% |
| entra-signin-shape | 20 | 100% | 100% | 100% | 100% |

## What is actually out there

| Source | Best public data | Verdict |
| --- | --- | --- |
| AWS CloudTrail | flaws.cloud, 1.94M real events | Solved. The scale fixture for the whole project |
| Azure Activity Log | Zenodo 19228517, real subscription, attack/clean pairs | Solved |
| GCP Cloud Audit | same Zenodo record, real `LogEntry` with `protoPayload` | Solved |
| Google Workspace | Invictus `gws_dataset`, ~10k real activities | Usable; 97% token events |
| Microsoft 365 | Invictus `o365_dataset` (9,608 real BEC records) plus Splunk attack_data | Solved for BEC |
| Okta | ~500 records across every public source | Thin. Positives only |
| Entra ID | Elastic fixtures; BOTSv3 if you want volume through Splunk | Thin |
| AWS GuardDuty | six findings | Nothing public. Generate from a sample account |
| Defender, CrowdStrike, SentinelOne | vendor-accurate fixtures, hundreds of records | Nothing public. No vendor releases tenant data |
| GitHub, GitLab | audit-log fixtures | Nothing public at size |
| Wazuh | AIT alert data set, 96MB | Solved |
| Cloudflare, Tailscale, Stripe, OpenAI, Anthropic | mapping fixtures only | None in the manifest yet |
| CrowdStrike FDR, SentinelOne Cloud Funnel, Defender Advanced Hunting | mapping fixtures only | None in the manifest yet |

The GCP set needs one filter before it is useful: only about a fifth of its
`default-logs` is Cloud Audit, the rest being Cloud Build and Cloud Run output
from the same projects. The manifest entry carries the `jq` line that splits the
audit entries out, and `scripts/fetch_dataset.py` prints it after the download.

Two honest caveats. First, for the EDRs and for source control there is no public
corpus at all. The fixtures are schema references, and anything claiming to be
an EDR dataset is either endpoint telemetry (Sysmon, not EDR alerts) or a
vendor-normalised export. Second, licences differ per dataset: the Elastic
fixtures are Elastic-2.0 and the AIT log data set (as opposed to its alert data
set) is non-commercial, so neither may be vendored into this repo. `var/` is
gitignored for that reason, and the fixtures under `tests/fixtures/mappings/` are
ours, written from provider documentation.

When a dataset shows that a mapping is wrong, the fix belongs in the mapping and
a record belongs in `tests/fixtures/mappings/<source>.json`, written by us, with
documentation IP ranges, never copied out of a licensed dataset.
