# Engineering guidelines

These guidelines come from the pre-go-live audit of 2026-10-12, which covered 17 areas of shoc and verified 349 findings. Each guideline states a rule, the defect that led to it, what the code still breaks (Open) and the test or review step that checks it. A change that breaks a guideline needs an entry in docs/decisions.md or an RFC in rfcs/. Ids are stable, and a retired guideline keeps its number.

An id in parentheses, such as (integ-5), names a finding in the audit report. The report is not in the repository; the maintainers hold it. The comment on the fixed line often carries the same id, so `grep -rn integ-5 shoc tests` finds the fix.

Most checks live in `tests/unit/test_guidelines_<area>.py`, `tests/conformance/test_guidelines_<area>.py` and `console/tests/guidelines.test.ts(x)`. Many are ratchets. A `KNOWN` list in the test names each place that breaks the guideline today, the test fails on a new break, and it fails on an entry whose break was fixed, so the list only shrinks. Where this page says "Open", the code does not meet the guideline yet. The gap is in a `KNOWN` list, or the check is review until its test exists. A check marked review has no test, and the reviewer of the change applies it.

## Ingest and connectors

### ING-G1 Re-read a look-back where the vendor publishes no lag

A connector that polls by event time, for a vendor that publishes no delivery lag, starts each walk at the newest event read minus `base.OVERLAP` (15 minutes, D164) with an inclusive start bound, and `connector_state.stored_keys` holds the digest of every row inside that look-back across all streams of the source (D150). The inclusive bound is `ge`, `>=`, `[gte]` or `__gte`, and the stored digests keep a re-read from reaching the store. The look-back is applied once, in `since_default`, when the walk begins, and the page token holds that start until the walk ends (Tailscale applies it per window). A vendor with a published lag ends each read at `settled(cursor, LAG)` instead: Google Workspace per application, Azure Activity, Cloud Logging, Entra sign-in and directory-audit reads at Microsoft's published latency, CloudTrail `LookupEvents` at 15 minutes, and Anthropic's activity read. Those reads may keep a strict bound. Okta follows its `next` link, Microsoft 365 reads by content availability, and the file listings and queue readers keep their own look-back or acknowledgement, so D164 leaves them out of the overlap. Each stream counts the events that arrived inside the overlap unseen, and `health.sources` shows the count.

D154 accepted that an event delivered after a newer one was never ingested, and a strict `gt` on one-second timestamps also skipped events in the newest second, so late events were lost with no error (detect-3). D154's 5-minute CloudTrail lag was AWS's average delivery time, and many events arrive later. When the D150 digests cover only the last run, a quiet stream reloads its overlap into the warehouse. Open: six overlap polls still filter strictly after their cursor (entra, defender, crowdstrike, sentinelone, wazuh and aws_guardduty).

Checked by: `tests/unit/test_guidelines_ing.py::test_since_default_applies_the_overlap`, `tests/unit/test_guidelines_ing.py::test_no_connector_filters_strictly_after_its_cursor`, `tests/unit/test_guidelines_ing.py::test_stored_keys_cover_the_overlap_across_streams`.

### ING-G2 Page the vendor its own way and stop at the limit

`FetchResult.more` comes from the vendor's continuation (a next link or token, `has_more`, a non-empty Pub/Sub pull, an SQS long-poll receive) and never from `len(page) == size`. Wazuh is the one exception, because OpenSearch `search_after` has no continuation token. A held cursor carries `since`, `until`, `newest` and the token together, and a walk that ends on an empty page returns `{'since': cursor['newest'] or since}`. Every `fetch` stops once it holds `limit` records and leaves the rest in its cursor (M365 contentUris, listing keys, undeleted SQS messages). Vendor objects are streamed line by line with `http.stream` and `zlib.decompressobj(wbits=31)`, and are never read whole with `gzip.decompress` or `resp.content`. A source behind its backlog catches up through `RunStats.more` and the re-queued `source.sync` (D200), never through a higher `max_pages`.

Pub/Sub and short-polled SQS return short pages while messages wait, so a size test ended the run and the backlog aged out of vendor retention (integ-5). FDR batches and M365 day listings were read whole, which killed the worker before it saved its cursor, and the same object killed it again each cycle (integ-6). Open: `stripe._activity` and `crowdstrike.fetch` still infer `more` from the page size (Falcon's `meta.pagination.total` goes unread), and `cloudtrail_s3.fetch` (the trail's log files), `CloudflareLogsConnector.fetch` and `sentinelone_cloudfunnel.read` still decompress objects whole.

Checked by: `tests/unit/test_connectors.py::test_crowdstrike_moves_on_when_the_window_held_exactly_one_full_page`, `tests/unit/test_connector_crowdstrike_fdr.py::test_a_page_stops_taking_messages_once_it_holds_the_limit`, `tests/unit/test_connectors.py::test_m365_reads_blobs_only_up_to_the_limit_and_keeps_the_rest`, `tests/unit/test_vendor_methods.py::test_gcp_a_pull_an_empty_subscription_holds_open_is_an_empty_page`, `tests/unit/test_connector_cloudflare_logs.py::test_a_full_batch_leaves_the_rest_for_the_next_call`, `tests/unit/test_connector_sentinelone_cloudfunnel.py::test_cloudfunnel_stops_at_the_limit_and_carries_on`, `tests/unit/test_connector_defender_hunting.py::test_a_page_stops_at_the_limit_and_says_there_is_more`, `tests/unit/test_guidelines_ing.py::test_a_listing_connector_stops_at_its_limit`, `tests/unit/test_guidelines_ing.py::test_more_never_comes_from_the_page_size`, `tests/unit/test_guidelines_ing.py::test_no_vendor_object_is_read_whole`.

### ING-G3 A cursor shape change reads the previous shape

Every cursor shape written to `shoc.connector_state.cursor` is a persisted format. A change to a connector's cursor keys ships an upgrade that reads the previous release's shape, as `updates.upgrade` reads a cursor from before `created`, and resumes without skipping events after the saved `since` or starting an unannounced `backfill_hours` re-read. The same change adds a test that resumes from the old shape.

Splitting SentinelOne into streams moved its cursor under `streams` and restarted a 24-hour backfill (integ-10). Moving the Pub/Sub ack out of the cursor dropped the ackIds it already held. Cursors outlive releases and backend moves, and no mapping test sees them.

Checked by: `tests/unit/test_connectors.py::test_sentinelone_goes_on_from_the_cursor_it_kept_before_the_streams_were_read_apart`, `tests/unit/test_connectors.py::test_defender_starts_a_new_walk_from_a_cursor_kept_before_updates_were_read`. A check over every connector waits for saved shapes in `tests/fixtures/cursors/<source>.json`; until then, review.

### ING-G4 Raise on every vendor refusal

A connector raises on any vendor refusal, a 200 carrying GraphQL or Graph `errors` included, and never sleeps, retries in place or returns an empty page. A GraphQL reader checks `errors` before it reads `data`. `base.run` keeps the cursor at the last stored page, and `explain()` turns the vendor's error code (throttling, clock skew, missing licence, missing subscription) into the sentence stored in `last_error`. Within a source, one failing stream goes through `Streams` as a `partial` error that still refreshes `last_ok_at` (D201). A window that vendor retention clamped is reported in `FetchResult.error`.

SentinelOne read threats and alerts in one call, so a 403 on alerts discarded the threats, and a GraphQL error passed as success (integ-4). AWS throttling read as a missing permission, and the M365 seven-day clamp dropped days with no trace. Open: `sentinelone._alerts` raises only when `data.alerts` is null, so errors returned beside data still pass as success.

Checked by: `tests/unit/test_connectors.py::test_a_refusal_names_the_vendors_code_and_its_cause`, `tests/unit/test_connectors.py::test_sentinelone_reports_a_graphql_error_instead_of_an_empty_page`, `tests/conformance/test_connectors.py::test_a_source_with_one_refused_stream_is_ingesting_not_stale`, `tests/unit/test_guidelines_ing.py::test_connectors_neither_sleep_nor_swallow`.

### ING-G5 No record can hold a cursor still

`Mapping.map_record` returns a storable row for any input (D205). `_storable` cleans NUL and lone surrogates, a time outside [`EARLIEST`, ingest + `AHEAD`] becomes `ingested_at` with the vendor's value kept in `unmapped._time_original` (D206), and an object in a text column is written as JSON. Every `EventStore.load_batch` loads the rest of a batch when it refuses one row, and logs that row's event_uid.

One NUL in a User-Agent, one lone surrogate in an NTFS path or one 9999-12-31 sentinel failed the whole COPY, and the page failed again on every cycle (data-1). Anyone who can write a log line could blind a source this way. Open: `map_record` does not bound integers, so an out-of-range value on an INTEGER column (`process_pid`, ports, `api_response_code`) reaches the store, whose per-row fallback leaves that row out.

Checked by: `tests/unit/test_mapping_safety.py::test_nul_and_lone_surrogates_never_reach_the_store`, `tests/unit/test_mapping_safety.py::test_an_event_time_that_cannot_be_one_becomes_the_ingest_time`, `tests/conformance/test_postgres_partitions.py::test_a_row_postgres_refuses_is_left_out_and_the_rest_load`, `tests/unit/test_guidelines_ing.py::test_no_value_on_a_mapped_path_breaks_a_row`, `tests/conformance/test_guidelines_ing.py::test_a_row_the_store_refuses_does_not_refuse_its_batch`.

### ING-G6 Every ingest path runs the same tail

Every path from vendor records to stored rows (`base.run`, `events.ingest`, the GitHub webhook in `api/rest.py`, replay and the scratch stores) runs the same steps in the same order. The steps are `Mapping.map_records` (never `map_record`), the `stored_keys` filter where a cursor exists, `batchwriter.load`, a load stamp and `events.loaded` only when rows were added, `FetchResult.commit` for vendor acks (D202), then the cursor write.

Each entry point reimplemented this tail and drifted. `events.ingest` stamped a load for a redelivery that added nothing and woke every rule (data-17), and Pub/Sub acks landed after their deadline.

Checked by: `tests/unit/test_connectors.py::test_a_store_failing_partway_keeps_the_cursor_at_the_last_page_stored`, `tests/unit/test_vendor_methods.py::test_gcp_acknowledges_each_page_in_the_run_that_stored_it`, `tests/conformance/test_lifecycle.py::test_a_batch_stored_already_is_no_new_load`, `tests/unit/test_guidelines_ing.py::test_only_the_tail_loads_rows`.

### ING-G7 One row per vendor event

A record that lists several events (Workspace `events[]`, Cloud Logging `protoPayload.metadata.event[]`, any later batch envelope) declares `explode: <list>` in `shoc/ingest/mappings/<source>.yaml` (D207) and is never split in the connector. The rows of one record get event_uids from the vendor id plus the position, and `raw` is the record as received with only the exploded list narrowed. Microsoft 365 also uses `explode` for one row per Teams link (D263).

The Workspace mapping read `events[0]`, so a 2SV save that turned enforcement off as its second event never fired the critical rule (integ-2). Open: gcp_audit still reads `metadata.event[0]`, because `Mapping.map_records` reads `explode` as a top-level key, and it waits for the engine to take a dotted path. The M365 explode fixture has no message with two links.

Checked by: `tests/unit/test_mapping_safety.py::test_each_event_of_a_workspace_activity_is_its_own_row`, `tests/unit/test_guidelines_ing.py::test_an_event_list_is_exploded_not_read_at_its_first_item`.

### ING-G8 The row's time is the cursor's field

The `time` column maps to the field the connector's cursor advances on, per stream. For an alert the vendor changes in place that is the update time (Defender `lastUpdateDateTime`, Falcon `updated_timestamp`, SentinelOne `updatedAt`), with the creation time left in `raw` (D203). The field per connector and stream is kept in `CURSOR_FIELD` in `tests/unit/test_guidelines_ing.py`, and every module that calls `since_default` has an entry. `replay.TIME_FIELD[source]` names one of `Mapping.paths('time')`. Every time string a connector compares is parsed in `base.py` (`base.utc` or `base._instant`), which reads a naive time as UTC (D252).

EDR alerts were filtered and timed on creation, so a severity rise or a failed remediation never reached shoc (integ-11). The private parsers turned a vendor time with no offset into local time or a TypeError. Open: `aws_cloudtrail._epoch`, `aws_guardduty._epoch_ms` and `awssig.assumed` still call `fromisoformat` themselves, and SentinelOne's unified-alert fixtures carry no `updatedAt`.

Checked by: `tests/unit/test_connectors.py::test_defender_reads_a_changed_alert_again_as_an_update`, `tests/unit/test_mapping_safety.py::test_replay_places_every_source_on_a_path_its_mapping_reads`, `tests/unit/test_guidelines_ing.py::test_the_cursor_field_is_the_rows_time`, `tests/unit/test_guidelines_ing.py::test_every_poll_by_event_time_names_its_cursor_field`, `tests/unit/test_guidelines_ing.py::test_times_are_parsed_by_base_utc`.

### ING-G9 Entity columns hold principals and objects

A mapping fills an entity column (the keys of `detect.engine.ENTITY_COLUMNS`) only with the principal or object its kind names. A correlation, request, trace or operation id never goes into `actor_session_uid` or any other entity column, and a session id is a `session:` entity only where the product says it is one (D265). The object an event creates or grants (CreateAccessKey's new key id, a new member, a new token) lands in `resource_uid`. Every rule's `entity:` names a column that a mapping answering the rule's `logsource` fills, and resolves on its positive fixture.

Entra's correlationId became a `key:` entity that joined unrelated cases and looked like a credential to revoke (hunt-23). CreateAccessKey's new key was never an entity, so the leaked-key playbook left the attacker's second key active.

Checked by: `tests/conformance/test_rules.py::test_rule_fires_on_its_positive_fixture`, `tests/unit/test_mappings_all.py::test_mapping_extracts_at_least_one_entity`, `tests/unit/test_guidelines_ing.py::test_no_request_id_is_an_entity`, `tests/unit/test_guidelines_ing.py::test_every_rule_entity_names_a_mapped_column`.

### ING-G10 Verify a push before reading it

`ingest` in `shoc/api/rest.py` and `shoc/api/ingest.py` verifies a vendor push's signature over the raw body with `hmac.compare_digest` before parsing it or writing anything. A value taken from an unsigned header is bounded (the delivery id's v1-UUID time to GitHub's three-day redelivery window) and never sets event time. A delivery loads once by its id in `shoc.push_deliveries`, and the id is forgotten when the load fails. `source.configure` keeps `push_key` when it replaces the poll credential, and shoc accepts no push form the vendor does not document (D70). On a warehouse backend a delivery waits in Postgres for the next cycle (D292).

A captured signed body could be replayed under a new delivery id with a back-dated time from the unsigned header (appsec-12). Reconfiguring GitHub with an audit token deleted the push key, so every later webhook was refused.

Checked by: `tests/unit/test_github_webhook.py::test_only_a_delivery_signed_with_the_push_key_is_accepted`, `tests/unit/test_github_webhook.py::test_without_a_push_key_nothing_is_accepted`, `tests/unit/test_github_webhook.py::test_a_delivery_id_dated_outside_the_redelivery_window_is_refused`, `tests/conformance/test_push_replay.py::test_a_replayed_delivery_loads_nothing_whatever_its_id`, `tests/conformance/test_connectors.py::test_a_new_credential_keeps_the_push_key`, `tests/conformance/test_rest.py::test_nothing_but_githubs_webhook_is_pushed`.

### ING-G11 A new vendor tenant works on the first cycle

A connector works on a brand-new vendor tenant with only the permission it documents, and performs the vendor's one-time setup itself, as m365 starts its content subscriptions on AF20022. Every connector except `file` has `PERMISSION_HINTS` and `WHERE` (or `PUSH_WHERE`) entries in `shoc/ingest/connectors/base.py`. For a `Streams` connector those entries name each default stream's permission, licence, tenant setting and setup step (Entra P2 risk scopes, the M365 subscription start, GitHub source IP disclosure, Purview audit), and a stream's failure message names the stream, its permission and the setting that drops it. Sources that share one vendor app (entra, m365, defender, defender_hunting, azure_activity) read the same `secret_env` names, so one rotation covers all of them.

Default streams failed on every install that followed the documented setup, and the errors pointed operators at permissions they had already granted (integ-1). A new M365 tenant loaded nothing, and the error said only that Microsoft refused the request.

Checked by: `tests/unit/test_connectors.py::test_m365_starts_a_subscription_the_listing_says_is_missing`, `tests/unit/test_connectors.py::test_an_entra_refusal_names_the_identity_protection_permissions`, `tests/unit/test_connectors.py::test_github_setup_turns_on_source_ip_disclosure`, `tests/unit/test_guidelines_ing.py::test_every_connector_says_what_it_needs`, `tests/unit/test_guidelines_ing.py::test_every_hint_names_a_real_connector`, `tests/unit/test_guidelines_ing.py::test_every_default_stream_says_what_it_needs`.

## Detection, hunting and intel content

### CON-G1 Severity is the impact, and it moves with its playbook

A rule's `severity` is the impact if the finding is true, and is never derived from its `confidence` (D267). It changes only in the same commit as the `trigger.severity_at_least` of the playbook in `content/playbooks/` that lists the rule and the `severity_at_least` floors in `content/policy.yaml` that the playbook's steps need, because the rule's severity also sets the case deadline, the investigation budget and the case's paging floor (D165). Sibling rules on different products share one severity.

Severities were set one rule at a time, sibling rules disagreed, and medium rules sat in playbooks that trigger at high, so a malicious verdict on them contained nothing unless the Investigator raised the case's severity (detect-4). Open: 82 of the 279 rule and playbook pairs in content/ sit below their playbook's trigger.

Checked by: `tests/unit/test_guidelines_con.py::test_every_rule_can_reach_its_playbooks_trigger`, `tests/unit/test_guidelines_con.py::test_sibling_rules_share_a_severity`. The policy.yaml floors are review.

### CON-G2 Every named field is written by a mapping

Every field a rule or hunt pack names (detection selections, `entity`, `fields`, `group_by`, `sequence.by`, `baseline.first_seen`, `count_distinct`, `rare.by` and `rare.among`, `pivot`) is an OCSF column that a mapping answering its `logsource` writes, or a `raw.` or `unmapped.` path that resolves in a row of the item's own fixtures. For an OR block, one alternative resolving is enough. Every column kernel code reads off a scan row (`engine.ENTITY_COLUMNS`, `engine.HASH_COLUMNS`, `engine.entities_of`, `hunter.ACTORS`) is in `compiler.EVIDENCE_COLUMNS`, in what `compile_pack` always selects, or in the test's `SELECTED_ONLY` set (`device_hostname`, left out of the evidence on purpose).

A dead field compiles, matches nothing and fails silently. `entities_of` read columns the scan never selected, so GuardDuty's outbound peer never became an `ip:` entity (detect-12). Open: three display fields and five per-vendor pack blocks that the fixtures do not exercise.

Checked by: `tests/conformance/test_rules.py::test_rule_fires_on_its_positive_fixture`, `tests/unit/test_guidelines_con.py::test_every_named_field_is_written_by_a_mapping`, `tests/unit/test_guidelines_con.py::test_kernel_reads_only_selected_columns`.

### CON-G3 Coverage counts only what the tenant delivers

A coverage claim (a rule or pack covering an ATT&CK technique, a backlog gap closed) counts only content on products the tenant delivers (`layout.products_for` against the delivering set), by exact technique id present in `content/attack_platforms.json` (D228). Every value a `filter_*` block hands off is selected by another shipped rule on an overlapping product.

Defender alerts from Office 365, Identity, Cloud Apps and Entra ID Protection were filtered out of all four edr/alerts rules and selected by none, so they were stored and ignored (detect-2). `edr_identity_or_email_alert` and `edr_medium_identity_or_email_alert` now select them (D268). Open: `microsoftDefenderForCloud` and `unknownFutureValue` are still filtered out of the four edr/alerts rules and selected only by `azure_vendor_alert`, which reads Azure Activity. 45 attack tags on shipped content (T1562 or its sub-techniques, T1070.001 or T1656) are missing from the shipped ATT&CK 19.2 map and can never count, so they need retagging.

Checked by: `tests/conformance/test_detection_engineer.py::test_a_rule_on_a_product_we_do_not_receive_covers_nothing`, `tests/conformance/test_detection_engineer.py::test_a_sub_technique_is_not_covered_by_a_rule_that_maps_to_its_parent`, `tests/unit/test_guidelines_con.py::test_every_attack_tag_is_in_the_shipped_attack_map`, `tests/unit/test_guidelines_con.py::test_values_a_rule_hands_off_are_selected_elsewhere`.

### CON-G4 A baseline says how it learns

Every `first_seen` rule sets `baseline.while_learning` explicitly, `fire` or `quiet` (D142), so a reviewer sees which rules stay silent while they learn. A rule adds `learns_from: selection` (D157, and D287 for packs) when its product's history would make it ready before its own matches cover the lookback, as with Stripe payouts, where the first poll reads months of activity log and one day of payouts. Every hunt pack's `first_seen` keys on at least one `compiler.INDEXED` column, and every `rare` pack with `seen_by_fewer_than` sets `new_only` (D233). Before you change `compiler.USED`, check each product's status vocabulary in its mapping.

`stripe_payout_to_new_destination` was ready at once over one day of payouts and would have fired at critical on the first payout to the company's own bank. Open: 8 of the 13 first-seen rules leave `while_learning` to the default. Under D142 the quiet default stands, so `aws_access_key_new_address` stays silent for the 30 days of its lookback on each new install, and that choice is still with the maintainers (detect-7). 13 packs anti-join weeks of history on unindexed keys and time out on Postgres.

Checked by: `tests/unit/test_compiler.py::test_first_seen_needs_an_indexed_column_and_no_other_correlation`, `tests/conformance/test_hunts.py::test_a_baseline_silences_a_pack`, `tests/unit/test_guidelines_con.py::test_a_first_seen_rule_says_how_it_learns`, `tests/unit/test_guidelines_con.py::test_a_first_seen_pack_starts_from_an_indexed_column`. The `compiler.USED` vocabulary check is review.

### CON-G5 A sequence starts on an attacker-shaped event

A `sequence` rule's `first` block matches an event that is attacker-shaped by itself (an explicit MFA decline, a risky sign-in, a recon call). Its `by` keys are ids both logs write byte for byte (`actor.user.uid`, `actor.session.uid`, `device.uid`, `resource.uid`, `cloud.account.uid`, `src_endpoint.ip`, the test's `JOIN_KEYS`), because `by`, `first_seen`, `group_by` and `re` compare text as stored, case included, while selections compare lower-cased (D236). A rule that joins on a name lists the reason both events write it identically in the test's `JOINED_ON_NAMES`. The fixtures prove that event order matters (TST-G1).

UPN casing differs between Entra sign-in and audit logs, so a join on names missed. In the wave-1 run both Entra sequence rules missed their positive fixture and fired on their negative one once fixture record order changed (detect-13).

Checked by: `tests/conformance/test_rules.py::test_a_sequence_pairs_up_when_its_first_event_is_delivered_last`, `tests/conformance/test_guidelines_con.py::test_a_sequence_rule_is_quiet_on_its_positive_fixture_reversed`, `tests/unit/test_guidelines_con.py::test_a_sequence_joins_on_ids`.

### CON-G6 Fixtures are what the connector delivers

Rule and pack fixtures are the vendor's records as the connector delivers them, mapped through `map_records`, with any field the connector adds (GitHub's `default_ref`) and any update record it emits (EDR alert updates, activity_id 2). The negative fixture is a near miss on the same product that differs only in the condition the rule discriminates on, which may be the operation itself. A baseline rule's negative carries the history (`_day_offset`) that silences it.

Missing alert-update records hid that EDR rules opened a second case on each update. Open: 6 of 13 first-seen rules have negatives with no history record, so the baseline that should silence them is never exercised (detect-15).

Checked by: `tests/conformance/test_rules.py::test_rule_is_quiet_on_its_negative_fixture`, `tests/unit/test_rules_content.py::test_rule_has_positive_and_negative_fixtures`, `tests/unit/test_guidelines_con.py::test_negatives_are_near_misses`.

### CON-G7 A cap sorts, filters first and reports what it cut

Every cursor walk over the event store (detection watermarks, `ioc_match`, `hunter.window`) takes its window from the engine's ingestion-time window (`engine.SETTLE` and `engine._late_loads` over `shoc.store_loads`). `intel.retro_hunt` keys on `shoc.iocs.retro_hunted_at` and an event-time lookback instead (D260). Every SELECT in shoc/ with a LIMIT other than 1, and every Python cap on rows, sorts by an explicit key with a unique tie-breaker that keeps the rows a SOC must not lose (rarest tuples first in hunts, open needs_human cases ahead of closed ones), and applies every filter in SQL before the LIMIT. No cap (`TOO_MANY_TUPLES`, `ADHOC_LIMIT`, `SLICES_PER_RUN`, `OTX_PAGES`, `MISP_PAGES`, `PROSE_LIMIT`, `LEARNING_SHOWN`) moves a cursor past rows it did not read without writing the loss where Ops reads it (`rule_state.last_error`, a `gap` outcome, `FeedResult.error` or `truncated`). Every module-level cap in the detection, hunt and intel code has a test or a stated reason it is harmless.

The hunter kept the 200 noisiest tuples and advanced past the attacker's single one (hunt-1, D229, D230). A needs_human case dropped out of the console after 200 newer cases were updated, because the verdict filter ran after the LIMIT (ux-6). OTX read one page and MISP 1,000 attributes, and both reported success (D223). Open: unordered LIMITs in `surveyor.exposure_of`, `credentials.owners`, `credentials.products_behind` and `review.case_citations`, and caps that drop input with no test (`engine.MAX_BUCKETS`, `intel.PER_SOURCE`, `report.MAX_TEXT`).

Checked by: `tests/unit/test_hunter.py::test_a_load_that_committed_late_pulls_the_window_back`, `tests/unit/test_hunter.py::test_catch_up_stops_at_its_slices_and_says_what_it_lost`, `tests/conformance/test_hunts.py::test_too_many_tuples_are_triaged_in_order_and_the_rest_named`, `tests/conformance/test_rules.py::test_the_merge_gate_backtest_reads_past_the_ad_hoc_limit`, `tests/conformance/test_intel.py::test_a_cycle_matches_an_indicator_on_an_event_that_arrived_late`, `tests/unit/test_guidelines_con.py::test_every_cap_is_reported_or_harmless`, `tests/unit/test_guidelines_con.py::test_every_limit_has_an_order`, `tests/conformance/test_guidelines_con.py::test_every_reader_sees_a_late_load`, `tests/conformance/test_guidelines_con.py::test_a_filter_runs_before_the_limit`.

### CON-G8 One classifier per indicator kind

Indicators reach `shoc.iocs` only through `intel.store_indicators`, and no UPDATE changes a stored value or type. They are typed by one classifier per kind (`report.extract` with `report.TLDS` for text, `osint.classify` for a bare value, D219) and canonicalised by `intel.normalise` when stored (D224). An event value meets them in the same form: every address column in `intel.MATCH_COLUMNS` uses `transform: ip` in its mapping, and every domain column strips a trailing dot. A host or address a source names only inside a URL or email is a derivation, and is never stored or matched as its own `domain` or `ip` indicator.

Each path reimplemented typing and each copy was wrong a different way. Extraction knew 45 TLDs and no IPv6, file names became domains, and URL hosts were matched as report domains (cti-3). Long-form IPv6, trailing dots and CIDRs never matched events. Open: only the cloudflare and m365 `src_endpoint_ip` fields use `transform: ip`, and 26 `src_endpoint_ip` and `dst_endpoint_ip` fields across the mappings store the vendor's text verbatim, so a vendor that writes long-form IPv6, a `::ffff:` address or `name.` never matches a normalised indicator. `observables._HASHES`, `observables._IPV4` and `capabilities/ask.IP` still type indicators outside report and osint.

Checked by: `tests/unit/test_intel_feeds.py::test_a_value_is_stored_the_way_events_write_it`, `tests/unit/test_intel_feeds.py::test_urlhaus_stores_each_url_as_a_url_never_its_host`, `tests/unit/test_report.py::test_any_real_tld_and_an_ipv6_address_are_indicators`, `tests/conformance/test_intel_reading.py::test_a_urls_host_is_held_back_whatever_the_model_called_it`, `tests/unit/test_guidelines_con.py::test_iocs_are_written_in_one_place`, `tests/unit/test_guidelines_con.py::test_indicator_patterns_live_in_report_and_osint`, `tests/unit/test_guidelines_con.py::test_normalise_matches_what_events_write`. The mapping transforms are review.

### CON-G9 A hold is scoped to its evidence and seen by a person

Anything that stops a matching value or tuple from raising a finding is scoped to the evidence that justifies it and leaves a record a person sees. That covers the prevalence hold in `intel.findings_from_hits`, own-value and warninglist holds, suppressions and narrowings, and a Hunter `human_fact` or `older_event` basis (D232). Under D166 the prevalence hold applies only to leads (confidence below `intel.LEAD_BELOW`, 0.6) and to values matched only in `src_endpoint_ip` or Authentication (class_uid 3002) rows. A match at 0.6 or above in an `intel.OUTBOUND` column opens one finding listing every account. A held value is an exception-report item (D288), because only a person's `intel.add` releases it. A non-human path whose list is not loaded holds the value back (D217).

The hold tagged a URLhaus link clicked by 30 mailboxes as prevalent, and it was never matched again (cti-9). A person's fact about one user explained another user's inbox rule, and `known_benign` answered empty in the serve process, so nothing was held.

Checked by: `tests/conformance/test_intel.py::test_a_value_everybody_touches_is_held_not_raised`, `tests/conformance/test_intel.py::test_a_listed_link_everybody_got_opens_one_finding_naming_them_all`, `tests/conformance/test_intel.py::test_a_lead_everybody_got_is_held`, `tests/conformance/test_hunts.py::test_a_fact_about_someone_else_is_no_basis`, `tests/conformance/test_hunts.py::test_an_older_event_explains_only_a_routine_return`, `tests/conformance/test_intel_reading.py::test_an_agents_read_holds_values_back_until_the_warninglists_are_in`.

### CON-G10 Feed indicators expire and stay below the action floor

Every indicator from a parser in `intel.FEEDS` has a finite `expires_at` and a confidence below the policy's 0.8 action floor, except those from a curated C2 list (Feodo). The `intel.REPORT_FEEDS` parsers return report items, whose values arrive through `intel.digest`. What the publisher retired (`is_active`, `expiration`, `to_ids`, TLP:RED) is dropped (D223, D262). A pull pages to the end or returns `Pulled.short`, and never follows a redirect while carrying a key (D223). A pull that errors or changes shape, and an abuse.ch pull that comes back empty, shows as a failing feed in `ops.alerts` (D248). An empty `list` pull fails the same way, which amends D248. An OTX or MISP pull with nothing new is an ordinary day.

MISP pulled non-IDS context attributes at 0.8 with no expiry, which met `cloudflare.block_ip`'s floor forever (cti-5). An empty abuse.ch body counted as success while its indicators expired, and TLP:RED events reached model prompts. Open: `intel.listing` passes a person's confidence (0.95) and `days: 0` (no expiry) through unclamped, and the feed parsers record no error for an empty pull. The table keeps no per-run fetched count, so "empty for a day" needs a schema change.

Checked by: `tests/unit/test_intel_feeds.py::test_otx_leaves_out_retired_indicators`, `tests/unit/test_intel_feeds.py::test_misp_asks_for_published_detection_values_page_by_page`, `tests/unit/test_intel_feeds.py::test_a_feed_redirect_is_an_error_and_the_key_stays_home`, `tests/unit/test_guidelines_con.py::test_every_feed_expires_and_stays_under_the_action_floor`, `tests/unit/test_guidelines_con.py::test_an_empty_pull_is_a_failure`, `tests/conformance/test_guidelines_con.py::test_a_feed_failing_or_empty_for_a_day_is_an_ops_alert`.

### CON-G11 Merged content gets the shipped checks

Content merged at runtime (`shoc.merged_rules`, `shoc.merged_hunts`, `shoc.merged_playbooks`) loads row by row (D227). A row that no longer parses or reuses a shipped id is left out and reported in `rule_state.last_error` or a Manager notice, and the tenant's cycle goes on. Its prose reaches a model only inside `safety.quote` (D235). `detection.merge`, `hunt.merge` and `playbook.merge` run every check the shipped content's tests apply, at full volume (D226).

One invalid Detection Engineer row stopped all detection for its tenant (detect-8). A merged pack's hypothesis entered every daily triage prompt as instructions, and the gate backtested 200 rows and let a 3650-day lookback through. Open: `detection.merge` compares neither severity with the playbook trigger (CON-G1) nor ATT&CK tags with `content/attack_platforms.json` (CON-G3), `hunt.merge` accepts a `first_seen` pack on any column, and `playbook.merge` does not compare its trigger with its rules' severities. Once `detection.merge` enforces CON-G1, the medium rule `tests/conformance/test_detection_engineer.py::_spec` merges into `contain_leaked_cloud_key` moves to high.

Checked by: `tests/conformance/test_rules.py::test_a_merged_rule_that_no_longer_loads_or_takes_a_shipped_id_is_left_out`, `tests/unit/test_hunter.py::test_a_merged_packs_prose_is_quoted_as_data`, `tests/unit/test_hunter.py::test_a_pack_reads_at_most_a_week_against_ninety_days`, `tests/conformance/test_rules.py::test_the_merge_gate_backtest_reads_past_the_ad_hoc_limit`, `tests/conformance/test_guidelines_con.py::test_a_gate_refuses_what_shipped_tests_refuse`.

### CON-G12 An enumerated value is matched whole

A rule that matches an enumerated vendor value (Entra's `signInEventTypes`, a status, a role name) uses equality or a list of values, never `contains`, `startswith` or `endswith`, because one value of a vocabulary is often part of another.

`contains: interactiveUser` in `entra_sign_in_after_mfa_denial` also matched `nonInteractiveUser` sign-ins.

Checked by: review.

## Response, autonomy and paging

### RSP-G1 An action's id covers its whole target

Every `shoc.actions.action_uid` in `actions.propose` comes from `actions.target_key()` over all of the action's identity parameters (its declared `identity_params`, otherwise every required param) (D173). It never comes from `required_params[0]` alone or from free text such as `notify.page`'s summary. The same parameter set drives `playbooks._target_text` fan-out, the `playbooks.targets()` hash and the action's `plan()` wording.

A partial id merged distinct containments into one row, so a second inbox rule or IAM policy on the same user got the first one's done row back (ir-1). A page keyed on its text was never sent again once the words repeated. Open: `playbooks._target_text` still reads `required_params[0]`, so 11 multi-parameter actions (`detach_user_policy.policy_arn`, `m365.delete_inbox_rule.rule_id`, the Okta and Entra `remove_admin_role.role` among them) neither fan out nor re-hash on their second identity parameter.

Checked by: `tests/unit/test_playbook_plan.py::test_an_action_id_covers_every_required_parameter`, `tests/unit/test_playbook_plan.py::test_a_parameter_that_only_locates_the_object_is_not_part_of_its_id`, `tests/conformance/test_action_lifecycle.py::test_two_policies_on_one_user_are_two_actions_and_both_run`, `tests/conformance/test_action_lifecycle.py::test_a_second_outage_a_day_later_pages_again`, `tests/unit/test_guidelines_rsp.py::test_every_identity_parameter_changes_the_action_id_and_shows_in_its_plan`, `tests/unit/test_guidelines_rsp.py::test_an_action_id_comes_only_from_target_key`, `tests/unit/test_guidelines_rsp.py::test_a_step_fans_out_on_every_parameter_of_its_action_id`.

### RSP-G2 A page counts as sent only when a channel took it

`notify.*` is never a dry run, whatever `SHOC_DRY_RUN` or a policy rule says, and `Policy.dry_run_for` returns False for it (D168). `manager.deliver` settles a `shoc.notices` row as `paged` or `merged` only when PagerDuty accepted it, the Slack main post reached a configured channel, or `mail.send` reached an admin or operator (D167). A missing route, a policy refusal or a dry result settles as `failed` at once. A send failure that can recover keeps `delivered_at` NULL with `attempts` and `retry_at`, retries on `RETRY_MINUTES` (D169), then appears in `ops.alerts` and `reporter.exceptions`. Every page opens with `manager._head` written by code, and model wording runs only within `WORDING_SECONDS` before falling back to `manager.template` (D171).

A stock install recorded every dry-run page as sent while nobody was woken, and the 24-hour merge folded later notices into that false `paged` (sre-1). A pager answering 503 settled the notice as delivered, and a slow model could hold a page for about 30 minutes.

Checked by: `tests/conformance/test_pages.py::test_a_page_leaves_while_dry_run_is_on`, `tests/conformance/test_pages.py::test_no_pager_and_no_channel_is_failed_not_paged`, `tests/conformance/test_pages.py::test_a_page_pagerduty_refused_is_tried_again_then_goes_out`, `tests/conformance/test_pages.py::test_a_page_that_keeps_failing_is_settled_failed_after_its_retries`, `tests/conformance/test_pages.py::test_the_model_words_a_page_but_never_how_it_opens`, `tests/conformance/test_pages.py::test_a_slow_model_does_not_hold_the_page`, `tests/conformance/test_pages.py::test_a_failed_malicious_page_can_be_told_again`, `tests/conformance/test_manager.py::test_a_page_that_reached_nobody_is_an_alert`, `tests/unit/test_guidelines_rsp.py::test_a_page_is_never_a_dry_run`.

### RSP-G3 A dry run leaves the live record alone

A dry run (`action.run` or `playbook.run` with `dry_run`, a preview step, or `SHOC_DRY_RUN`) never moves a live `shoc.actions` row, takes a live run's `run_uid` or job key, counts toward `_auto_actions` or `max_auto_actions_per_case`, is chased by `unattended._undecided_actions`, reaches `_hand_to_manager`, or counts as containment (D175).

A dry `action.run` marked the live action done, and a dry `playbook.run` took the case's only `run_uid`, so the leaked key was never disabled while the action list said it was (ir-2). Preview rows still used up the per-case L1 budget and were chased and paged.

Checked by: `tests/conformance/test_action_lifecycle.py::test_a_dry_run_of_a_live_action_leaves_it_for_the_run_that_acts`, `tests/conformance/test_action_lifecycle.py::test_a_dry_playbook_run_never_stands_in_for_the_live_one`, `tests/conformance/test_action_lifecycle.py::test_a_preview_leaves_nothing_to_approve_chase_run_or_count`.

### RSP-G4 Undo restores the recorded state

A `shoc/actions` class with `reversible = True` that changes an existing object records it as it was before shoc touched it through `snapshot(creds, params)` (D178). `actions._act_with` stores that in `actions.result.before` before the mutating call and reuses it on every retry. Undo restores exactly that state and removes only what shoc added (D254). An action that only creates an object its undo deletes by id, a sign-out (`revoke_sessions`) and `notify.page` need no snapshot. When the earlier state cannot be read, the action records itself as not reversible.

Undo restored an assumed state. AWS's own quarantine policy was removed, a key that was already Inactive was re-enabled, and a scoped Okta role came back org-wide (ir-11). A retry after a lost response stored the post-change state as the one to restore. Open: 30 of the 50 reversible actions have no snapshot. 13 read their before-state inside `execute`, so a retry reads it again, and 17 undo to an assumed opposite state (`isolate_host`, `suspend_user` and `start_cloudtrail_logging` among them).

Checked by: `tests/unit/test_action_snapshots.py::test_a_retried_demotion_restores_the_role_kept_before_the_first_try`, `tests/unit/test_action_snapshots.py::test_a_role_the_first_try_removed_is_done_with_the_grant_kept`, `tests/unit/test_action_snapshots.py::test_an_entra_assignment_the_first_try_removed_is_done_with_the_grant_kept`, `tests/unit/test_action_snapshots.py::test_a_role_that_was_never_there_still_fails_on_a_first_try`, `tests/unit/test_action_snapshots.py::test_an_inbox_rule_the_first_try_deleted_can_still_be_recreated`, `tests/unit/test_action_snapshots.py::test_an_instance_retried_restores_the_groups_it_had_before_isolation`, `tests/unit/test_actions.py::test_undoing_a_disable_turns_on_only_a_key_that_was_on`, `tests/unit/test_actions.py::test_undo_leaves_the_quarantine_aws_attached_itself`, `tests/conformance/test_action_lifecycle.py::test_a_retry_after_a_lost_answer_keeps_the_state_from_before_the_first_try`, `tests/unit/test_guidelines_rsp.py::test_every_reversible_action_keeps_what_it_changed`.

### RSP-G5 A step acts on what a rule named

A new or changed playbook step whose action is not `notify.*` takes every target parameter from `{{ rule.<id>.<kind> }}` for a rule the playbook lists, or from `{{ platform.<p>.<kind> }}` (RFC 0026, D272). `playbooks.plan` fans these out to one step per value up to `FAN_OUT_AT_MOST` and fails the step as ambiguous above that (D177). Any other parameter is filled by a single-answer lookup (D257). `{{ entity.<kind> }}` appears only in `notify.*` text. Every kind a step reads is one the rule's finding emits through `engine.entities_of` from `compiler.EVIDENCE_COLUMNS`.

Cases are unions of findings, so `entity.*` rendered the alphabetically first value of the whole case. A leaked-key run could disable the legitimate CI key, leave the attacker's key active and report done (ir-5). Open: 20 shipped playbooks still act on `entity.*`, 54 placeholders in 49 acting steps, the required step of `contain_leaked_cloud_key` (`{{ entity.key }}`) among them. Multi-rule actor steps keep `entity.*` until RFC 0026's playbook-level scope exists. The `playbook.merge` lint has no `entity.*` check yet, and adding one changes the acting steps `_ours()` merges in `tests/conformance/test_playbook_merge.py`. The positive fixtures of `aws_access_key_created` (resource) and `edr_high_severity_detection` (file_hash) do not emit the kind their steps read.

Checked by: `tests/unit/test_playbook_plan.py::test_a_target_with_two_values_is_a_step_for_each`, `tests/unit/test_playbook_plan.py::test_more_values_than_the_cap_is_one_ambiguous_step`, `tests/conformance/test_playbook_targets.py::test_each_step_acts_on_what_its_findings_name`, `tests/unit/test_guidelines_rsp.py::test_a_step_acts_on_what_a_rule_named` (a ratchet over `ENTITY_SCOPED` that fails on a new or changed step reading `entity.*`), `tests/conformance/test_guidelines_rsp.py::test_a_step_reads_a_kind_its_rule_emits`, `tests/conformance/test_guidelines_rsp.py::test_a_merged_playbook_may_not_act_on_entity`.

### RSP-G6 Persistence a rule records gets removed

A rule whose finding records an object the attacker created to keep access maps that object's id into `resource_uid` and is answered by a playbook step that removes it through `{{ rule.<that rule>.resource }}`. Any other parameter of that step is filled by a single-answer lookup declared in the action's `resolve`, or read from the event paths the action names (D291). A rule tagged with one of the persistence techniques (ATT&CK T1098.001, T1098.003, T1114.003, T1564.008, T1556.006) that cannot be answered this way is listed with its reason in `LEAVES_PERSISTENCE`: no removing action, no object (a sign-in or a protection turned off), a step that still reads `entity.*`, or no step.

Playbooks revoked sessions, reported done and left the persistence in place. The second access key from CreateAccessKey in the v0.1 exit scenario was never mapped or disabled (ir-6), and BEC forwarding rules were left to the model. Open: 55 of the 64 shipped rules with those tags are listed and 9 are answered. 4 of the listed rules have no step that removes the object (`aws_admin_policy_attached`, `entra_app_granted_mailbox_or_directory_permission`, `entra_global_admin_assigned`, `github_collaborator_given_admin`).

Checked by: `tests/unit/test_guidelines_rsp.py::test_persistence_a_rule_records_has_a_step_that_removes_it`, `tests/unit/test_mapping_aws_cloudtrail.py::test_the_key_create_access_key_made_is_its_resource`, and the `must_propose` of `aws.disable_access_key` in `evals/scenarios/leaked_aws_key/expected.yaml`, which `evals/run.py` checks.

### RSP-G7 Every close goes through one function

Every way a case reaches closed or a benign verdict (`case.close`, `case.set_state`, `engine.set_verdict`, `unattended._close`, `sentinel.apply` and the crew's closes in `loop.run_case`, the one for findings that no longer exist included) goes through one kernel function, `engine.close` (still to be written, see Open), that decides by who closed it and with what verdict. A person's close, or a `benign_expected` or `false_positive` verdict, rejects proposed and approved-but-unstarted actions with `actions.BY_CASE`, cancels runs through `playbooks.cancel_case_runs` and returns `still_in_force` (D176). A crew or deadline close of a malicious or suspicious case leaves its containment approvable and runnable (D152, D240). That amends D176, under which `execute` refuses any action on a closed case, and the change that applies it records the decision. `actions._case_says_no` and `playbooks.advance` apply the same decision.

An approved L1 still disabled a key seconds after a false-positive verdict (ir-15). Open: `engine.close` does not exist yet. On a crew-closed malicious case an action a person revives under D152 is refused as closed first, `unattended._close` rejects pending actions on every case, malicious included, `engine.set_verdict(false_positive)` rejects pending actions and cancels no run, and only `case.close` and `set_state` by a person cancel runs.

Checked by: `tests/conformance/test_case_close.py::test_a_false_positive_close_names_the_containment_still_in_force`, `tests/conformance/test_case_close.py::test_a_person_asks_again_for_what_their_close_rejected`, `tests/conformance/test_action_lifecycle.py::test_closing_a_case_rejects_what_was_approved_and_stops_its_runs`, `tests/conformance/test_guidelines_rsp.py::test_every_close_path_has_the_same_effect`, `tests/unit/test_guidelines_rsp.py::test_only_the_close_function_closes`.

### RSP-G8 Paging reads the worst severity on the case

Every paging and chase decision reads `engine.FLOORED`, the higher of `cases.severity` and the worst finding severity on the case (D165, amending D51 and RFC 0011). D165 names four sites: `manager.deliver`'s `critical_severity` stale check, the `malicious_uncontained` page (`manager._malicious_uncontained` and `uncontained`), the `unattended.DEADLINE_HOURS` lookup in `_stalled_cases`, and `unattended._worth_paging`. A new paging or chase site reads `engine.FLOORED` as well. A severity the Investigator sets through `loop._resevere` or `engine.set_severity` changes the case's budget and display, and never lowers that floor. Every other gate that reads case severity reads the floor too, the `severity_at_least` check in `actions.decide` for `notify.*` included.

The Investigator could lower a case's severity on a one-line reason that attacker-written log content can steer. A critical case lowered to low turned its page into a digest line, stretched the deadline from 1h to 72h and was closed unattended (ai-3). The first fix of ai-3 missed the `notify.*` policy gate in `actions.decide`.

Checked by: `tests/conformance/test_operator_signals.py::test_a_critical_case_lowered_to_low_keeps_its_one_hour_deadline_and_pages`, `tests/conformance/test_operator_signals.py::test_a_model_lowering_a_case_does_not_settle_its_critical_page`, `tests/unit/test_guidelines_rsp.py::test_paging_reads_one_severity`. The gates outside `manager.py` and `unattended.py` are review.

### RSP-G9 Containment and reachability each have one predicate

Whether a case was contained is answered only by `engine.CONTAINED` (a done action that is not `notify.*` and not a dry run in its row or its result, D240), and whether shoc can reach a person only by `manager.reachable()` plus the notice outcome (D241). No capability, report, metric, ops alert or console route restates either in its own SQL.

Restated predicates drifted. A deployment with no pager and no Slack channel read as delivered and health stayed green. Open: `shoc/agents/ops.py` (`ops.metrics`) still takes `contained_at` from the first done action of any kind, so a page or a dry-run plan counts as containment in time-to-contain (live-5), and `close_case` in `shoc/capabilities/cases.py` restates the predicate in its `still_in_force` query.

Checked by: `tests/conformance/test_autonomy.py::test_a_case_closed_without_its_containment_waits_for_a_person`, `tests/conformance/test_manager.py::test_with_no_way_to_reach_a_person_every_view_says_so_first`, `tests/unit/test_guidelines_rsp.py::test_containment_is_one_predicate`. Reachability is review.

### RSP-G10 The chase waits for the page to settle

`unattended._undecided_actions` grants an L2 its second window or abandons it only on a settled notice outcome. `paged` or `merged` grants the window, and a final `failed` abandons it with the reason written into the case. A notice still retrying (`delivered_at` NULL with `retry_at` set) leaves `chased_at` set for a later pass. An L2 without a fallback expires (D181). docs/response.md and the Commander prompt in `shoc/agents/roles.py` describe expiry exactly as `unattended.py` does it.

A single PagerDuty 503 abandoned the L2 at once, and the retried page then asked the operator about an action that was already rejected (po-3). The docs said an L2 without a fallback is rejected while the code let it expire after 4h.

Checked by: `tests/conformance/test_autonomy.py::test_a_paged_action_still_undecided_is_abandoned`, `tests/conformance/test_autonomy.py::test_an_undecided_action_on_a_severe_case_pages_instead`, `tests/conformance/test_operator_signals.py::test_an_approval_stays_open_while_its_page_is_retried`, `tests/conformance/test_guidelines_rsp.py::test_an_l2_is_not_abandoned_while_its_page_retries`. The docs and prompt wording are review.

### RSP-G11 A state change names the state it leaves

Every `UPDATE shoc.actions SET state=...` in `shoc/cases/actions.py`, and every `INSERT ... ON CONFLICT DO UPDATE SET state`, names the state it leaves in its WHERE clause (`AND state='approved'`, `AND state='running'`, `AND state <> 'running'`, `AND state='done'` for undo). An empty RETURNING re-reads the row and reports `already <state>`, so a worker job, a playbook step, a second undo and a person's reject never both act.

Two workers could run one approved action, and the second overwrote the success with failed and an empty undo, so undo was refused (ir-10). Open: `approve()`, the settle in `execute()`, `_hand_to_manager`, `undo()` and the upsert in `propose()` carry no state guard.

Checked by: `tests/conformance/test_action_lifecycle.py::test_two_workers_that_both_read_it_approved_act_once`, `tests/unit/test_guidelines_rsp.py::test_every_action_state_change_names_the_state_it_leaves`.

### RSP-G12 shoc protects the identities it acts as

Every response provider in `shoc/actions/base.NEEDS` names who it acts as, in a credential field listed in `own.ACTS_AS` or as an `acts_as` value its probe records (a provider in `credentials.NAMELESS`). `own.protected()`, computed at decision time from `own_identities`, enabled shoc admins and operators, and the identities of stored credentials (D182), holds any agent or playbook action against those at L2. Those identities are never copied into `own_identities`, and break-glass accounts are registered with `own.add`, never by a name glob (D253).

An L1 step could disable shoc's own AWS response key, which made undo impossible, or sign out the only admin (ir-8). A break-glass account whose name missed the `*admin*` glob could lose Global Admin automatically. Open: anthropic, cloudflare, gitlab, openai, sentinelone, stripe and wazuh name no identity. GitLab's probe already returns "signed in as", and only its absence from `credentials.NAMELESS` keeps it from being recorded.

Checked by: `tests/conformance/test_own_targets.py::test_shocs_own_response_key_waits_for_a_person`, `tests/conformance/test_own_targets.py::test_the_login_a_response_token_acts_as_is_protected`, `tests/conformance/test_own_targets.py::test_an_enabled_shoc_admin_is_not_signed_out_without_a_person`, `tests/unit/test_guidelines_rsp.py::test_every_response_provider_says_who_it_acts_as`.

## Agents and model use

### AGT-G1 A role is offered reads and its named merges

A crew role is offered, through `roles.<ROLE>.tools`, `HUNTER_PACK_TOOLS` and `tools.WRITES`, only reads plus the content merges its spec names (today `graph.refresh`, `detection.merge`, `detection.revert`, `hunt.merge`). A proposal, a case state or severity change, a notice, a memory row, a suppression or an indicator leaves a role only through its typed output, where `loop._propose`, `actions.from_crew` and `routing.route` apply the gates (D179). A capability an agent principal can still call holds that caller to L2 and clamps its own numeric windows.

The IR Commander was offered `action.propose` as a tool, so a log-steered call skipped target grounding and the blast-radius gate (ai-1). The Surveyor's `graph.refresh` accepted any window and overwrote the daily node counts mid-case (D251).

Checked by: `tests/unit/test_security_invariants.py::test_no_crew_role_is_offered_a_response_capability`, `tests/unit/test_agent_tools.py::test_a_role_is_offered_reads_and_only_the_writes_its_spec_names`, `tests/unit/test_agent_tools.py::test_a_question_cannot_hand_the_commander_a_proposal`, `tests/conformance/test_response.py::test_an_agent_that_calls_action_propose_never_acts_alone`, `tests/unit/test_guidelines_agt.py::test_the_crews_writes_are_the_four_named_merges`, `tests/unit/test_guidelines_agt.py::test_a_role_is_offered_only_its_own_tool_lists`.

### AGT-G2 Quieting needs the checks behind it and can be taken back

A crew closes quiet or teaches anything only when `checks.Confidence.unsettled()` is empty for that run and the stored `cases.confidence` clears `checks.BENIGN_CLOSE_FLOOR` (D237). That covers `routing._suppress`, `routing._remember` and the Challenger's `routing.suppress_draft` via `loop._suppression`. A backlog item that can lead to a D77 narrowing (`routing._recurring`) is written outside that gate and is gated when it is merged, by the weekly recheck. Every such row carries the case uid or `routing.closure_mark`. `routing.undo_closure` reverts merges, revokes suppressions and expires the crew note, and reopens the case's backlog items, which wait for the recheck and merge gate again.

A benign verdict wrote a 7-day suppression and a 180-day memory note whatever the measured confidence said, so one injected scheduled-backup line could silence a rule for an entity (ai-2). Undoing the close left the note behind for every later dossier.

Checked by: `tests/conformance/test_dispositions.py::test_a_benign_verdict_the_checks_do_not_back_goes_to_a_person`, `tests/conformance/test_dispositions.py::test_a_crew_close_below_the_floor_quiets_nothing_and_a_persons_does`, `tests/conformance/test_dispositions.py::test_a_closure_taken_back_takes_its_note_in_memory_with_it`, `tests/unit/test_guidelines_agt.py::test_quieting_is_called_only_from_the_gated_paths`, `tests/unit/test_guidelines_agt.py::test_route_quiets_only_past_the_floor`, `tests/conformance/test_guidelines_agt.py::test_a_closure_taken_back_leaves_nothing_quiet`.

### AGT-G3 All prompt text is quoted, model-written text included

Text enters a prompt only through `safety.quote` or `safety.quote_events`. That includes text a model wrote after reading logs (a role's reasoning, `containment_note`, notice bodies, peer questions and answers, crew memory), people's injects and a tool's error. Every function that builds a prompt from case, notice or memory data is an entry point of the obeying-model check in `tests/conformance/test_guidelines_agt.py::test_every_prompt_builder_quotes_the_logs`.

Every injection path the audit found entered through text one step removed from the raw log, such as a peer answer, a people-said line or a notice body the Manager reworded (ai-9). The suite replayed only `run_case`, so prompts built in `manager.word`, `recheck.run`, ops and sentinel were never checked.

Checked by: `tests/conformance/test_injection.py::test_an_obeying_model_neither_unquotes_the_logs_nor_records_the_attackers_verdict`, `tests/conformance/test_crew.py::test_log_content_reaches_the_model_only_as_quoted_data`, `tests/unit/test_llm.py::test_a_log_line_cannot_close_the_block_it_is_quoted_in`, `tests/conformance/test_guidelines_agt.py::test_every_prompt_builder_quotes_the_logs`.

### AGT-G4 Independent reads see only the case

The checks that measure a verdict (`checks.reads`, `checks.check_claims`, `recheck.run`) get only the base text from `dossier.build_dossier`, called with `exclude_case` for a recheck, plus the cited events. They never see the openspace transcript, `_people_said`, peer or CTI answers, or the crew's memory note on that case. A read that failed or named no verdict counts in the denominator as a vote that did not agree. The change that does this amends RFC 0020, which drops a failed read.

The reads were shown the previous verdict, people's messages and CTI's answer, so agreement measured copying (ai-8). Open: `checks.reads` still skips a failed read or one with no verdict, so two timeouts leave agreement at 1 of 1, and an L1 can clear `min_confidence` on a verdict no independent read checked. RFC 0020 is not amended yet.

Checked by: `tests/conformance/test_crew.py::test_the_independent_reads_see_the_case_not_what_was_said_about_it`, `tests/conformance/test_dispositions.py::test_a_closure_taken_back_takes_its_note_in_memory_with_it` (the recheck's `exclude_case`), `tests/unit/test_guidelines_agt.py::test_a_failed_read_counts_against_agreement`.

### AGT-G5 Citations and targets are checked against what the agent saw

Every citation is validated, and every action target grounded, against what that agent was shown in this run (`openspace.Evidence` built from the case's finding events plus the agent's `usage.seen` via `loop._seen_by`). Every `validate_citations` call passes that Evidence. Targets match by exact normalised value from typed OCSF entity fields, `case_entities` and platform lookups, never by substring of joined raw text. A later run's Evidence is seeded only from messages whose citations were checked that way. Every call to `Policy.decide` and every `actions.Proposal` or `CrewProposal` passes `grounded`, `blast_radius` and, for decide, `confidence` explicitly, and an unmeasured value counts as the one that refuses. The change to exact matching amends RFC 0020.

`action.propose` built a Proposal on the defaults `grounded=True` and `blast_radius=None`, which the policy reads as grounded with nobody asked. Open: `loop._grounded` still matches substrings of the joined evidence text, which includes attacker-written raw fields, so `admin` is grounded by `administrator` and a value planted in a user agent can unlock an L1 (ai-14). `Proposal` and `CrewProposal` still default to `grounded=True` and `blast_radius=None`, and `manager._page` and `playbooks.advance` rely on those defaults.

Checked by: `tests/conformance/test_crew.py::test_a_challenger_cites_only_what_the_case_showed_it`, `tests/conformance/test_crew.py::test_a_target_the_evidence_never_showed_does_not_run_on_its_own`, `tests/unit/test_guidelines_agt.py::test_citations_are_checked_against_the_evidence_shown`, `tests/unit/test_guidelines_agt.py::test_decide_and_proposals_name_their_measurements`, `tests/unit/test_guidelines_agt.py::test_grounding_matches_whole_values`.

### AGT-G6 Every model call has a deadline and a ceiling

Every model call site (`llm.complete_typed`, `loop._ask`, and the reads and claim check in `checks.derive`) has a token ceiling and is held to the deadline of the job it runs in by `timeout=` or an enclosing `llm.limit`. `deadline=` alone stops only tool lookups, so a call with no tools still runs to `CALL_SECONDS`. `complete_typed` holds one turn (the call in flight, the final answer and the retry) to one `CALL_SECONDS` (D239). `worker.HUNG_AFTER_SECONDS` is derived in shoc/worker.py from the longest `Budget.for_case`, and the margin past that budget covers every call that can run after it: the CTI question, the Challenger and the rebuttal, then derive's `crew_samples + 1` calls, or `(3 + crew_samples + 1) x CALL_SECONDS`. Each completion's tokens are charged to `cases.tokens_used` exactly once.

`_converse` checked only tokens, so slow gateway calls pushed a batch of critical cases past the 30-minute watchdog, which killed the worker and re-ran the same cases (ai-5). The Commander's tokens were charged once per proposal and again on the decision. Open: the formula's margin is 2400s against the 3600s that tail can take, and 13 call sites are bounded only by the per-turn `CALL_SECONDS` (`checks.reads` and `check_claims`, `detection_engineer._work_one`, `hunter.triaged` and `_work_item`, `integrator.repair`, `ops.review`, `reporter.narrate`, `sentinel._shape`, `surveyor.read`, `intel._triage` and `_read`, `review.review_action`).

Checked by: `tests/unit/test_crew_bounds.py::test_a_turn_past_its_deadline_looks_nothing_up_and_still_answers`, `tests/conformance/test_pages.py::test_the_managers_answer_shares_one_budget_with_its_colleagues`, `tests/conformance/test_crew.py::test_the_commanders_turn_is_counted_once`, `tests/unit/test_guidelines_agt.py::test_every_model_call_has_a_deadline`, `tests/unit/test_guidelines_agt.py::test_the_watchdog_formula_covers_derives_calls`.

### AGT-G7 Spend ceilings are checked before the call

Every path that starts model work (`worker._sweep_cases` and `_queue_investigations`, `hunt.daily`, intel reading, `source.onboard`, `ask`) checks its ceilings before the call: the case's lifetime ceiling (`loop.LIFETIME_RUNS`, a multiple of `Budget.for_severity`, D238), the tenant's `spend_usd_per_day` for informational and low cases (`loop.CAPPED_SEVERITIES`), and the role ceilings in `llm.BUDGETS` (`hunt_tokens_per_day`, `intel_reports_per_day`, `intel_tokens_per_day`). Ceilings count tokens where they can, so an unpriced model is still bounded. Reaching one hands the case to a person and raises one ops alert. Shipping a non-zero default for `spend_usd_per_day` needs a decision that amends D106.

`spend_usd_per_day` defaulted to 0 and applied only to priced models. The live instance counted 29M tokens in 30 days as $0, and one finding's case spent 3.7M tokens over four crew attempts (live-9). Open: there is no tenant-wide daily token ceiling, `spend_usd_per_day` still defaults to 0.0, a medium or higher case runs past the spend cap, the lifetime ceiling raises no ops alert, and `worker._sweep_cases` queues a case past its lifetime ceiling (`run_case` then stops before any model call).

Checked by: `tests/conformance/test_crew.py::test_a_case_past_its_lifetime_ceiling_goes_to_a_person`, `tests/conformance/test_crew.py::test_past_the_daily_spend_cap_a_low_case_goes_to_a_person`, `tests/conformance/test_ops.py::test_a_model_with_no_price_is_an_alert_not_free`, `tests/conformance/test_guidelines_agt.py::test_the_sweep_does_not_queue_a_case_past_its_lifetime_ceiling`.

### AGT-G8 A model failure is named for what it is

`loop.run_case`, the case sweep and ops classify each model failure where they catch it. A stop at the run's budget or deadline is `loop.BudgetExhausted` and goes to needs_human without counting as a provider failure. A `loop._too_soon` skip is neither a failure nor a crew attempt. A 401, 402 or 403, or hours with no successful call by `shoc.llm_spend.last_ok_at` (D199), raises one `manager.tell(condition='coverage_dark', group_key='llm')` page with fixed wording. While the provider is failing, `unattended._stalled_cases` neither closes nor pages per case a case the crew never read (`tokens_used = 0`, D245).

When credit ran out (402), unattended closed every medium and low case nobody had read and paged each high case separately, and no page named the one thing the operator could fix (ai-4).

Checked by: `tests/conformance/test_crew.py::test_a_model_that_cannot_be_reached_is_said_out_loud`, `tests/unit/test_crew_bounds.py::test_an_invalid_answer_past_the_deadline_is_still_asked_for_once_more`, `tests/unit/test_crew_bounds.py::test_the_retry_never_sends_an_empty_assistant_turn`, `tests/conformance/test_operator_signals.py::test_spent_model_credit_pages_once_naming_the_cause`, `tests/conformance/test_operator_signals.py::test_a_case_nobody_read_is_held_while_the_model_is_down`.

## Stores, queries and jobs

### DAT-G1 Dialect differences are fixed in shoc/store

Every difference in how a backend evaluates or returns event-store SQL is fixed once inside shoc/store, with SQL text in `shoc/store/sql.py` (`FIXUPS` or the per-dialect transform in `translate`) and result shape and units in the adapter's `query()` and `apply_retention()` (D214, D299). The capability, agent or detection module that ran into it stays unchanged. Every shipped statement translates on all five dialects with no DISTINCT or GROUP BY over a JSON column and `ESCAPE '!'` on every LIKE (D249), and a specific rewrite (the LIKE escape, `JSON_EXTRACT_SCALAR` on BigQuery) has its translated text pinned.

On BigQuery an object path read NULL and DISTINCT over the JSON raw column was refused, and on Databricks a backslash in LIKE was taken as an escape (wh-3). Each fix landed in one caller. With warehouse conformance out of CI, translation tests are the only guard. Open: `events.summarize` accepts `by` = `raw`, `unmapped` or `observables` and emits GROUP BY on the JSON column, which BigQuery refuses.

Checked by: `tests/unit/test_compiler.py::test_every_shipped_rule_translates_to_every_dialect`, `tests/unit/test_compiler.py::test_like_values_are_matched_literally_with_one_escape_on_every_dialect`, `tests/unit/test_own.py::test_the_intake_read_runs_on_bigquery_where_raw_is_json`, `tests/unit/test_warehouse_load.py::test_a_warehouse_returns_json_columns_as_objects`, `tests/unit/test_guidelines_dat.py::test_every_shipped_statement_translates_safely`.

### DAT-G2 A statement is bound in full and within budget

`sql.prepare` raises `missing query parameter(s)` on every dialect, BigQuery included (D300), and `sql.bind` refuses a statement over `sql.max_params(store.dialect)` with a StoreError. A caller with more values spreads them over several statements and merges the rows (D250), and never slices the list (`uids[:500]`). A placeholder inside `jsonb_build_object` or `json_build_object`, or in a `coalesce` or CASE whose other values are all placeholders or NULL, carries a `::type` cast, because nothing else gives Postgres its type. A negated predicate on a nullable column (NOT LIKE, `<>`, NOT IN) wraps the column in `coalesce` or tests IS NULL.

BigQuery's bind sent nothing for a missing name, so a predicate became unknown and dropped rows quietly (wh-16). Databricks refuses a 257th parameter, so `timeline.build` and `events.query` failed on the largest incidents, and the slices that kept other callers under the cap dropped true positives (wh-7). Open: `sql.bind` has no budget guard, `own._events`, the integrator and `timeline._match` still slice, `engine.transition`'s `closed_by` CASE has an uncast placeholder, and `events.parse_terms` compiles `field!=v` and `field!~v` with no `coalesce`, so a NULL column drops the row.

Checked by: `tests/unit/test_events_query.py::test_a_long_citation_list_stays_within_the_databricks_budget`, `tests/unit/test_timeline_budget.py::test_the_pivots_stay_within_the_budget_however_many_entities_a_case_has`, `tests/unit/test_compiler.py::test_a_missing_parameter_is_refused_before_the_store_on_every_dialect`, `tests/unit/test_guidelines_dat.py::test_a_statement_past_the_dialect_budget_is_refused`, `tests/unit/test_guidelines_dat.py::test_a_parameter_inside_a_json_builder_is_cast`. Slicing and negated predicates are review.

### DAT-G3 Every session has a deadline and is closed

Every session opens through `shoc/db/pool.py` (`connect` and `connect_readonly`, which apply `pool.limit`) or through `open_store`, except `worker.listen`'s LISTEN session and the readiness probe in `rest.py`. Each adapter enforces `Config.statement_timeout_seconds` on the server and with a client deadline that cancels the statement, queue time included (D211). The surface that builds a Context closes the store it opened (D295), and any function that opens a store closes it in a `finally` or returns it. Only `connect_owner` is exempt from session limits, and each migration runs under `SET LOCAL lock_timeout` and retries on LockNotAvailable (D196).

A statement with no deadline held the worker's loop until the 30-minute watchdog killed it, and the requeued job hung the same way (wh-5). A migration waited forever behind a reader while every other query queued behind it, and stores left open kept a Snowflake session and a temp directory per request. Open: `actions._gates`, `actions._resolve` (one store per field in a loop) and `cli.cmd_migrate` never close their stores, and no test checks Redshift's statement timeout.

Checked by: `tests/unit/test_warehouse_timeouts.py::test_every_warehouse_is_opened_with_the_configured_timeout`, `tests/unit/test_warehouse_timeouts.py::test_databricks_asks_the_server_to_stop_a_statement_too`, `tests/conformance/test_schema_and_sessions.py::test_serve_and_worker_sessions_stop_waiting_on_locks`, `tests/conformance/test_schema_and_sessions.py::test_a_migration_behind_a_reader_tries_again`, `tests/unit/test_guidelines_dat.py::test_sessions_open_only_through_the_pool`, `tests/unit/test_guidelines_dat.py::test_a_job_closes_every_store_it_opens`, `tests/unit/test_guidelines_dat.py::test_every_store_opened_is_closed_where_it_was_opened`.

### DAT-G4 Every staged name has a random part

Every batch file, stage object, S3 key, staging table and worker session name has a random component (`batch.batch_name()` for batches, D210, and `pool.PROCESS` for sessions, D192), and is never built from time, pid, thread id or hostname alone. A session-local TEMP table dropped on commit (`PostgresStore._insert`'s `_stage_<ms>`) is exempt. No remote object is written with `OVERWRITE = TRUE` or `WRITE_TRUNCATE`. Every staged copy of raw events has an expiry, or a sweep in `apply_retention` keyed on the age in its name (D212).

Every shoc container runs as PID 1 and serve loads webhooks in threads, so names built from milliseconds and pid collided and one batch's MERGE stored another batch's rows (wh-1). A restarted worker took its predecessor's session name, so the dead worker's jobs looked alive for 30 minutes. Open: Databricks `load_batch` still runs `PUT ... OVERWRITE`, onto a `batch_name()` path.

Checked by: `tests/unit/test_warehouse_load.py::test_two_batches_written_in_one_millisecond_get_two_files`, `tests/conformance/test_store_isolation.py::test_two_loads_in_one_millisecond_both_land`, `tests/unit/test_warehouse_load.py::test_retention_sweeps_the_batches_a_killed_load_left_staged`, `tests/unit/test_worker_identity.py::test_a_restarted_worker_does_not_pass_for_the_one_that_died`, `tests/unit/test_guidelines_dat.py::test_staged_names_carry_a_random_part`.

### DAT-G5 Every event read filters on the tenant

Every canonical statement that reads `ocsf_events` filters each reference to the table on `tenant_id = :tenant_id`, subquery, EXISTS and join aliases included, even though each tenant has its own namespace. Every load goes through `shoc.ingest.batch.load`, which refuses rows stamped for another tenant (D215). A tenant id names its namespace unchanged (D301), and no tenant can take a scratch tenant's name (`<tenant>_gate`, `<tenant>_hunt_gate`).

`Config._safe` mapped `acme-corp` and `acme_corp` to one namespace, and made a tenant named `acme_gate` the merge-gate scratch of `acme`, whose `reset()` deleted `acme`'s events (wh-13).

Checked by: `tests/unit/test_warehouse_load.py::test_a_batch_holding_another_tenants_rows_is_refused`, `tests/conformance/test_store_isolation.py::test_reset_and_retention_leave_another_tenant_alone`, `tests/unit/test_tenant_ids.py::test_an_id_that_folding_would_merge_with_another_is_refused`, `tests/unit/test_tenant_ids.py::test_the_running_tenant_may_not_be_another_tenants_scratch`, `tests/unit/test_guidelines_dat.py::test_every_events_read_filters_on_the_tenant`, `tests/unit/test_guidelines_dat.py::test_every_load_goes_through_the_batch`.

### DAT-G6 Every job kind has a tier and a held lease

Every job kind that `shoc.db.jobs.enqueue` can queue has an entry in `worker.JOB_CAPABILITIES` and an entry in `jobs.TIER` or in the routine set kept as `ROUTINE` in `tests/unit/test_guidelines_dat.py`. Pages, approved actions and webhook delivery are tier 0, and `detect.run`, `source.sync`, playbooks and `case.investigate` are tier 1 (D191). A worker checks stopping before each claim, claims one job per pass and renews that job's lease with `jobs.renew` while it runs (D192). `jobs.finish` and `jobs.fail` write only while `locked_by` is this worker and the state is `running`.

A FIFO claim taken four at a time made a critical page wait behind 25 investigations, and the fourth job's lease ran out before it started, so a second worker ran it again (sre-6). The first holder's late outcome then overwrote the second run's.

Checked by: `tests/conformance/test_worker.py::test_every_job_kind_the_worker_handles_is_listed`, `tests/conformance/test_worker.py::test_a_page_is_claimed_before_older_model_work`, `tests/conformance/test_worker.py::test_the_fast_lane_leaves_routine_model_work_and_takes_a_critical_case`, `tests/conformance/test_worker.py::test_a_long_job_keeps_its_lease_while_its_worker_runs_it`, `tests/conformance/test_worker.py::test_a_worker_whose_job_was_taken_back_does_not_write_over_it`, `tests/conformance/test_worker.py::test_a_stopped_worker_takes_no_job_after_the_one_in_hand`, `tests/unit/test_guidelines_dat.py::test_every_job_kind_has_a_tier`, `tests/unit/test_guidelines_dat.py::test_every_queued_job_kind_is_handled`.

### DAT-G7 A job that fails always counts an attempt

Every way a job leaves `running` other than success goes through `jobs.fail` or the shared `jobs.TAKE_BACK` statement, so it counts an attempt, backs off, records `last_error` and is parked as failed after 5 attempts. Only `shoc/db/jobs.py` changes a job's state, and a delete touches only pending jobs. The choice between failing the job and reconnecting reads the queue connection's state (`conn.closed` or `conn.broken`) and never the exception class. A job kind that can run close to `worker.HUNG_AFTER_SECONDS` has its own time budget that raises inside the job.

A job that killed its worker, or hit QueryCanceled, a deadlock or a lock timeout on a live connection, went back to pending with no cap and no error recorded (data-4). It killed a worker every 30 minutes and never appeared in `health.jobs`.

Checked by: `tests/conformance/test_worker.py::test_a_job_that_keeps_losing_its_worker_is_parked`, `tests/conformance/test_worker.py::test_a_query_that_times_out_fails_its_job_instead_of_reconnecting`, `tests/conformance/test_worker.py::test_a_failure_is_retried_with_backoff_then_parked`, `tests/conformance/test_worker.py::test_a_job_in_hand_when_the_database_went_away_comes_back_at_once`, `tests/unit/test_guidelines_dat.py::test_jobs_change_state_only_in_jobs_py`.

### DAT-G8 Every table has a retention when it is created

Every table that `shoc/db/migrations` creates is classified in the same change: pruned in `worker.PRUNE` with its window, bounded by a DELETE where it is written (`PRUNED_WHERE_WRITTEN`: iocs, intel_queue, push_deliveries, own_token_requests, store_loads, exposures, snapshots), or kept with its reason (incident record, configuration, credential, audit chain, told-once guard) in `KEPT` (D193). Event retention goes through `EventStore.apply_retention`. Every idempotency-key prefix shoc enqueues is classified either as a guard in `worker.GUARD_KEYS` or as purgeable in `PURGEABLE_KEYS`, a prefix whose key carries a job id or a time bucket, so purging it after the 7-day window cannot repeat an effect. `KEPT`, `PRUNED_WHERE_WRITTEN` and `PURGEABLE_KEYS` live in `tests/unit/test_guidelines_dat.py` until they move into shoc/worker.py. docs/deploy.md states each backend's real retention behaviour (Postgres monthly partitions, Delta files until VACUUM).

Only event partitions expired, so jobs, stream payloads, hunt rows copying events, graph nodes, lookups and memory kept personal data past `SHOC_RETENTION_DAYS` (priv-3).

Checked by: `tests/conformance/test_worker.py::test_the_nightly_retention_prunes_the_control_plane`, `tests/unit/test_guidelines_dat.py::test_every_table_has_a_retention`, `tests/unit/test_guidelines_dat.py::test_every_idempotency_prefix_is_classified`.

### DAT-G9 Scheduled control-plane reads use an index

Every control-plane statement that runs on a schedule or a console poll (`jobs.tick`, `jobs.requeue_stale`, `jobs.claim`, `health.status` and `health.jobs`, `ops.check`, the shift report, `worker.prune`) is backed by an index on the columns it filters, created by a numbered migration.

`tick`'s EXISTS check, the health counts and the stream readers scanned `jobs` and `stream_events` in full, about 2 million job rows a year for one tenant, on every tick and every console health poll (data-7). Open: `health.status` counts a tenant's jobs in every state, and every `tenant_id` index on `jobs` is partial on one state, so it needs an index on `shoc.jobs (tenant_id, state)`.

Checked by: `tests/conformance/test_guidelines_dat.py::test_scheduled_reads_use_an_index`.

### DAT-G10 Warehouse layout follows the ingestion-time read

Each warehouse events table is laid out so the detection cycle's `ingested_at` range prunes it: a partition or cluster key on `ingested_at`, file statistics kept on it as Databricks does, or no key at all where load order already keeps `ingested_at` close (Snowflake, D64 and D209). No key holds the constant `tenant_id`. BigQuery partitions by load day (D298), and its reads carry a byte cap once `SHOC_BIGQUERY_MAX_BYTES_BILLED` is set. On a warehouse backend only cycle-aligned worker jobs write to or wake the warehouse, and serve request handlers never do (D292). A layout change records a decision that amends D64, D101 or D131.

BigQuery partitioned by event time while every cycle reads by ingestion time, so each statement billed the whole 90 days (wh-6). GitHub webhooks loaded inline and woke detection a minute later, which kept a per-minute warehouse awake all day. Open: Redshift's events table is `SORTKEY ("time")` with nothing on `ingested_at`.

Checked by: `tests/unit/test_warehouse_load.py::test_snowflake_creates_the_events_table_without_a_clustering_key`, `tests/unit/test_databricks_sql.py::test_migrate_keeps_file_statistics_on_ingested_at`, `tests/unit/test_bigquery_cost.py::test_the_table_is_partitioned_by_what_detection_reads`, `tests/unit/test_bigquery_cost.py::test_only_a_read_carries_the_byte_cap`, `tests/unit/test_guidelines_dat.py::test_each_warehouse_prunes_on_ingested_at`. The serve path is review.

### DAT-G11 A NOT NULL column gets its default in SQL

An INSERT or UPDATE that may pass NULL for a NOT NULL column with a default sends the default from SQL (`coalesce(%s::jsonb, '{}'::jsonb)`), because an explicit NULL never falls back to the column's default.

An INSERT into `shoc.actions` that passed NULL for `result` (`jsonb NOT NULL DEFAULT '{}'`) failed instead of taking the default.

Checked by: review.

### DAT-G12 The runtime role gets every privilege its SQL needs in the same change

serve and worker connect as `shoc_app`, which owns no schema and has only what `migrate.RUNTIME_SQL` and `deploy/postgres-init/10-shoc-role.sh` grant it. A change whose SQL needs a new privilege at run time (a temporary table, DDL, a new schema object) adds the grant to both in the same change, and `migrate.pending` never runs DDL on a database that is already set up, because `CREATE ... IF NOT EXISTS` still needs CREATE.

The Postgres load's temporary staging table needed TEMPORARY, which the init script had revoked from PUBLIC, and every helper that called `migrate()` on the runtime connection failed on the bootstrap's `CREATE TABLE IF NOT EXISTS`. Both passed on a rig that ran as the owner and would have stopped every load after the deploy.

Checked by: the conformance suite in CI, which runs as `shoc_app` with `SHOC_MIGRATE_DSN` as the owner (`.github/workflows/ci.yml`).

## API, auth, secrets and privacy

### SEC-G1 A surface finds a capability by its own name only

Each surface resolves a capability by that surface's exact name (`rest_path` in `shoc/api/rest.py`, `mcp_name` through `mcp.tool()`, `cli_words` in `cli.py`) and passes the resolved Capability object to `Capability.invoke` (D183). No surface falls back to `registry.get` or to another surface's spelling.

MCP looked a tool up by `mcp_name` for the L2 confirmation while `invoke()` fell back to `registry.get`, so a model that wrote `action.approve` with dots ran an L2 capability with no confirmation (appsec-1).

Checked by: `tests/unit/test_mcp_confirm.py::test_an_l2_tool_has_one_name_and_its_dotted_name_is_unknown`, `tests/conformance/test_rest.py::test_an_l2_tool_called_by_its_dotted_name_is_unknown`, `tests/unit/test_guidelines_sec.py::test_call_tool_knows_an_l2_tool_only_by_its_mcp_name`.

### SEC-G2 Hand-written routes and unauthenticated work are bounded

Every route in `build_app` that is not generated from the registry (`/`, `/v1/openapi.json`, `/auth/*`, `/slack/commands`, `/slack/interactions`, `/ingest/{source}`, `/mcp`, `/v1/stream`, `/metrics`, `/healthz`, `/readyz`) is listed with its reason in the test's `HAND_WRITTEN`. It authenticates or verifies its signature before reading the body, reads the body only through one of the two capped readers in the test's `BODY_READERS` (`rest._body`, and `signin._post.handle` for the sign-in routes) with a route cap (`config.max_request_bytes`, `SLACK_MAX_BODY`), answers any non-ShocError through `rest._error`, and refuses `pool.ALL_TENANTS` wherever it reads a tenant header. Work that an unauthenticated client, a Slack user, an external_agent or a feed can trigger is bounded in bytes (`report.MAX_BYTES` streamed with `iter_bytes`), in threads (a module-level ThreadPoolExecutor with a fixed `max_workers`, never a thread per request) and in model tokens (a per-principal `signin.Throttle` such as `slack.QUESTIONS`).

`/slack` and `/ingest` read unbounded chunked bodies before authentication, and every route returned `str(exc)` with the database host and role (appsec-9). `/auth/forgot` opened a thread and a Postgres connection per request, and any Slack member could spend the shared model credit through `/shoc ask`. Open: `mail.send_later` starts a thread per lock mail from sign-in.

Checked by: `tests/conformance/test_api_hardening.py::test_an_unexpected_error_is_logged_and_never_returned`, `tests/unit/test_report.py::test_a_body_is_read_no_further_than_the_cap_or_the_deadline`, `tests/unit/test_guidelines_sec.py::test_every_hand_written_route_is_listed`, `tests/unit/test_guidelines_sec.py::test_routes_read_bodies_only_through_rest_body`, `tests/unit/test_guidelines_sec.py::test_no_unbounded_threads`. The `pool.ALL_TENANTS` refusal is review.

### SEC-G3 Outbound fetches are vetted at every hop

A URL that came from a caller, a config row, a feed or a model is fetched only through `shoc.detect.report.get` (D261), which resolves with getaddrinfo, refuses any address that is not global (`osint.is_public_address`, D286), pins the vetted address while keeping Host and SNI, re-vets each of at most `REDIRECTS` hops and streams under `MAX_BYTES`. A vendor client that follows redirects vets each hop (`report.vet_redirect`, which `osint._client(redirects=True)` installs, or a `Pinned` transport) and carries no key outside the Authorization header. httpx follows no redirect by default.

The report fetcher checked only the hostname string and then followed redirects, so a 302 to the cloud metadata address leaked instance credentials back through the CTI summary (appsec-2). Keys in `Auth-Key`, `x-apikey` or `X-OTX-API-KEY` headers rode cross-origin redirects, because httpx strips only Authorization. Open: `connectors/base.py:client` follows redirects with the caller's headers, Anthropic's `x-api-key`, GitLab's `PRIVATE-TOKEN` and AWS's `x-amz-security-token` among them.

Checked by: `tests/unit/test_report.py::test_a_report_url_may_not_point_inside_the_network`, `tests/unit/test_report.py::test_a_public_name_that_resolves_inside_is_refused`, `tests/unit/test_report.py::test_a_redirect_to_the_metadata_service_is_refused`, `tests/unit/test_intel_feeds.py::test_a_feed_redirect_is_an_error_and_the_key_stays_home`, `tests/unit/test_oidc.py::test_the_network_helpers_refuse_plain_http_and_private_hosts`, `tests/unit/test_guidelines_sec.py::test_every_http_client_vets_or_refuses_redirects`.

### SEC-G4 A stored secret stays with its host

Every configure path that reuses a stored secret when the caller gives none (`sources.configure`'s `COALESCE(EXCLUDED.secret, ...)`, `cases/credentials.save`'s `{**stored, **given}`, the `intel_feeds` and `lookup_sources` upserts in `capabilities/intel.py`, `llm.configure`, `sso.configure`) calls `shoc.cases.credentials.same_host` (D294). It compares the scheme, host and port of every http(s) setting plus `HOST_SETTINGS` (`cloud`, `storage_account`), and refuses with "<settings>: a new host, port or scheme needs its credential again; the stored one never goes anywhere else" when any differs.

`source.configure` with a new `org_url` and no secret sent the stored Okta SSWS token to the new host on the next sync (appsec-3). `llm.configure` and `sso.configure` each grew their own check while four other paths kept the hole. Open: `same_host` does not compare `region`, so the PagerDuty routing key follows a move from the US to the EU host, and `llm.configure` (D190) and `sso.configure` still use their own checks.

Checked by: `tests/conformance/test_llm_config.py::test_the_key_does_not_follow_a_new_provider_or_host`, `tests/unit/test_guidelines_sec.py::test_every_secret_reuse_calls_the_host_check`, `tests/conformance/test_guidelines_sec.py::test_a_new_host_needs_its_credential_again`, `tests/conformance/test_guidelines_sec.py::test_every_host_setting_is_covered`.

### SEC-G5 A capability that weakens the deployment waits for a person

A capability that removes or disables a source, deletes a credential, adds an outbound destination (`stream.subscribe`, an intel feed URL, an LLM base URL, a Slack channel) or shortens retention is L2 and human-only. If a service principal must call it under D100 (`events.retain`), it refuses any value below the configured setting (D293). The MCP `destructiveHint` (D134) comes from a closed verb vocabulary in `shoc/api/mcp.py`, `DESTRUCTIVE` plus `ADDITIVE` (still to be written, see Open), that classifies every verb the registry uses. Moving these capabilities from L0 to L2 is a decision of its own, and the change that applies it records it in docs/decisions.md.

`source.remove`, `stream.subscribe`, `intel.configure` and `events.retain` were L0, so a prompt-injected assistant could blind shoc or add a webhook that receives every finding without a person seeing a prompt (appsec-4). `retain` was missing from `mcp.DESTRUCTIVE` because the hint was guessed from a name suffix. Open: `source.remove`, `source.configure`, `stream.subscribe` and `intel.configure` are still L0, the registry carries no tag for egress or blinding, so the test keeps the `WEAKENS` list itself, and `mcp.ADDITIVE` does not exist, which leaves 34 verbs unclassified.

Checked by: `tests/unit/test_guidelines_sec.py::test_every_write_verb_is_classified`, `tests/unit/test_guidelines_sec.py::test_egress_and_blinding_need_a_person`.

### SEC-G6 A confirmation prompt shows what the person approves

Every MCP confirmation prompt (`mcp.describe`) is written from fixed fields in the `FIRST_FIELDS` order, renders `config.apply` as `configcode.plan(...).render()`, and puts crew- or model-written text last under "Crew rationale (unverified)". A prompt over `PROMPT_LIMIT` is refused with `confirmation_required` and the shoc CLI command, and is never cut (D184).

The prompt was cut at 600 characters in the key order the model sent, so the domain or issuer that mattered could sit past the cut, and an action's rationale echoing attacker log text read as shoc's own words (appsec-8).

Checked by: `tests/unit/test_mcp_confirm.py::test_a_prompt_too_long_to_show_is_refused_not_cut`, `tests/unit/test_mcp_confirm.py::test_who_and_what_come_first_whatever_order_the_model_sent`, `tests/unit/test_mcp_confirm.py::test_the_crews_rationale_comes_last_and_labelled`, `tests/unit/test_mcp_confirm.py::test_config_apply_is_confirmed_as_its_plan`.

### SEC-G7 Exception text stays in the process

REST and MCP answers go through `rest._error` or MCP's `internal_error` with a request id, and audit rows record `type(exc).__name__` for anything that is not a ShocError. Any error string stored where a reader, the crew, a model prompt or a third party can see it (`Observation.error`, `shoc.intel_lookups`, `RunStats.error` and `detail`, `jobs.last_error`, webhook health, intel feed errors) is built by a redacting helper such as `osint._failure` or `connectors/base.explain`, which names the status and host and never the URL, query string or vendor body.

httpx puts the full URL in its message, so Shodan's and ipapi.is's query-string keys reached `intel.lookup` answers, the 12-hour cache and the model's prompt (priv-1). Open: the pattern `f"{type(exc).__name__}: {exc}"` appears at 42 sites under shoc/. `intel.refresh` (`FeedResult.error`, stored as `intel_feeds.last_error`) and `base.run` (`RunStats.detail`) still use it, and leak no key today only because those keys travel in headers.

Checked by: `tests/unit/test_osint.py::test_a_refused_key_is_not_repeated_in_the_error_or_cached`, `tests/unit/test_registry.py::test_an_unexpected_failure_is_audited_by_its_class_not_its_message`, `tests/unit/test_guidelines_sec.py::test_no_error_repeats_a_secret`.

### SEC-G8 The audit path accepts any input

`shoc.db.audit.subject_of`, `audit.record` and the read-audit path in `Capability.invoke` are total over any input a capability accepts. They mask by field name (`audit.SECRET_FIELDS` or a `_secret` suffix), keep only identifiers and citations, and return None for a value they cannot parse (D187). Every capability input field that carries a credential is named so the mask catches it. The same holds for every audit, metric or logging helper: it never raises into the call it records.

The audit subject parsed `hxxps://evil[.]example[.]test` as a malformed IPv6 URL and raised, which failed `intel.remove` itself (priv-7). A secret in a field named `routing_key` or `access_key` would land in an undeletable audit row in clear.

Checked by: `tests/unit/test_audit_subject.py::test_a_defanged_url_is_no_subject_and_no_error`, `tests/unit/test_audit_subject.py::test_a_subject_names_identifiers_and_masks_secrets_and_free_text`, `tests/unit/test_registry.py::test_a_refusal_stands_when_its_audit_row_cannot_be_written`, `tests/unit/test_guidelines_sec.py::test_any_input_gives_a_bounded_subject_or_none`, `tests/unit/test_guidelines_sec.py::test_no_input_field_hides_a_secret_from_the_mask`. Metric and logging helpers are review.

### SEC-G9 The master key is checked before any work

`SHOC_MASTER_KEY` is the deployment's only root secret. Every secret column is written through `shoc.db.secrets.seal` bound to (tenant, table, row key) and read through `open_secret`. Every process that opens secrets or appends to `shoc.audit_log` (`cmd_serve`, `cmd_worker`, `cmd_mcp`, `cmd_apply`, the generated capability commands in `cli._capability_runner`) calls `secrets.check_master_key` and `audit.check_key` before it takes work. `cmd_migrate` needs only the first. `cmd_rotate_key` runs `check_master_key` on the new key and checks the chain's key through `audit.rotate`'s fingerprint compare. A stricter key rule warns on keys already in use and refuses only new ones (OPS-G6).

A process with a mismatched key could commit a token or role change and then fail to write its audit row (appsec-11). Compose fell back to well-known database passwords, which let anything on the network reach the superuser who can disable the audit triggers (D282). Open: `cmd_mcp`, `cmd_apply` and the generated capability commands call neither check, and `deploy/postgres-init/10-shoc-role.sh` still defaults to `shoc`, `shoc_app` and `shoc_agent`, which Compose never reaches.

Checked by: `tests/unit/test_startup_checks.py::test_the_example_master_key_is_refused`, `tests/conformance/test_api_hardening.py::test_serve_will_not_start_on_a_key_the_audit_log_was_not_keyed_with`, `tests/conformance/test_keys_and_roles.py::test_migrate_reseals_a_secret_from_before_binding`, `tests/unit/test_guidelines_sec.py::test_every_entry_point_checks_the_keys`, `tests/unit/test_guidelines_sec.py::test_every_secret_column_is_sealed`, `tests/unit/test_guidelines_sec.py::test_compose_password_fallbacks_are_refused`. The generated capability commands are review.

### SEC-G10 An outside identity gets only what was granted

An outside identity becomes a Caller only from an explicit grant (`slack.caller_for` from the approvers and readers maps and the configured `team_id`, `mcp.caller_from_env` from an exact ROLES name, `people.sso_person` from a role an admin invited or, for an uninvited email, the D120 default reader). Anyone unlisted gets `Caller(scopes=())`. Slack replies are ephemeral except the Approve and Reject confirmations (D186). A role change ends the role tokens issued to that email (D189), and each account creation or grant writes an audit row.

Every Slack member, guests and Slack Connect users included, could ask the crew about any employee's sign-ins and have the cited answer posted to the whole channel (priv-5). A demoted admin kept admin through a role token issued to their email. Open: `people.sso_person` writes no audit row when it creates a reader, and the `auth.signin` row that follows names the method and not the role.

Checked by: `tests/conformance/test_slack.py::test_a_listed_reader_can_only_read_and_anyone_else_nothing`, `tests/conformance/test_slack.py::test_a_bystander_gets_help_and_nothing_else`, `tests/conformance/test_signin.py::test_a_role_change_ends_role_tokens_issued_under_another_role`, `tests/unit/test_security_invariants.py::test_the_mcp_role_is_the_only_way_to_exceed_external_agent`, `tests/unit/test_guidelines_sec.py::test_slack_answers_ephemerally_and_strangers_get_no_scope`, `tests/conformance/test_guidelines_sec.py::test_an_sso_account_creation_is_audited`.

### SEC-G11 Every outside destination is documented and minimised

Every destination outside the deployment appears under "Data and privacy" in docs/security-model.md with what it receives, where it rests and the setting that turns it off (the model provider, keyed OSINT sources, intel feeds, Slack, PagerDuty, SMTP, webhooks, the SSO IdP, warehouse backends). The document names each by vendor, and the test maps each host in code to those words. Downloads (indicator feeds, lists and report sources) are named as downloads. Each value is minimised in code before it leaves (D218). Userinfo, query and fragment are stripped, own-domain hosts stay local, requests to api.openai.com send `store: false`, the vendor's regional host comes from a region setting, and webhooks require https to a public receiver (D275).

Full raw records went to the model provider, URLs with reset tokens and internal hostnames went to VirusTotal and urlscan, and EU PagerDuty accounts were paged through the US host (priv-4). No document told a DPO any of it. Open: the document's sentence on downloads leaves out the report sources (the RSS presets).

Checked by: `tests/unit/test_osint.py::test_a_third_party_is_never_told_a_urls_query_or_user`, `tests/conformance/test_intel_reading.py::test_a_third_party_gets_no_query_string_and_no_own_host`, `tests/unit/test_actions.py::test_an_eu_pagerduty_account_is_paged_through_its_eu_host`, `tests/conformance/test_stream.py::test_plain_http_is_refused_to_a_public_host_only`, `tests/unit/test_llm_http.py::test_openai_is_told_not_to_store_responses`, `tests/unit/test_guidelines_sec.py::test_every_outbound_host_is_documented`.

## Operability and deployment

### OPS-G1 A stopped shoc is visible from outside shoc

Every way shoc can stop is visible without shoc's help. The worker pings `SHOC_HEARTBEAT_URL` only at the end of an `ops.check` that read Postgres to the end (D242), and serve's `/readyz` runs `SELECT 1`. Each stopped-work state (no `detect.run` reaching done within max(3 x cycle, 1h), a source that never succeeded, overdue schedules) pages from `manager.coverage` with SQL alone (D170). `worker._ops_check` runs the steps that decide a page first and wraps each step in `step()`, so an exception in `ops.review`, `_publish_alert` or the `source.onboard` enqueue never skips the page.

Every outage signal came from inside shoc and needed Postgres plus a live worker, so a dead host told nobody (sre-2). In the worker's `ops.check`, `ops.review` ran before `manager.coverage` with `from_config` outside its try, so a model ConfigError skipped the dark-source page every hour (sre-10).

Checked by: `tests/conformance/test_pages.py::test_detection_that_stopped_finishing_pages`, `tests/conformance/test_rest.py::test_readyz_answers_only_while_postgres_does`, `tests/conformance/test_pages.py::test_a_source_that_never_succeeded_pages_from_when_it_was_set_up`, `tests/conformance/test_worker.py::test_the_hourly_check_pings_the_outside_monitor_only_when_it_ran`, `tests/unit/test_heartbeat.py::test_a_failed_ping_is_said_without_its_url`, `tests/conformance/test_operator_signals.py::test_the_hourly_check_decides_its_pages_before_a_step_that_raises`, `tests/conformance/test_guidelines_ops.py::test_a_model_failure_never_skips_the_coverage_page`.

### OPS-G2 A source is judged on its own delivery clock

`ops.source_health`, `health.status`, `health.quality` and `metrics.export` judge a source on the clock of how it delivers. A polled source uses max(`stale_after_minutes`, 3 x interval), a push-only source (`connectors.accepts_push` and no `<tenant>:sync:<source>` schedule row) uses `PUSH_QUIET_DAYS` (D197), and a source that never succeeded ages from `connector_config.created_at`. A missing `last_ok_at` or `finished_at` is never coalesced to now() (D172), and neither `last_ok_at` nor a cursor advances for a run whose store load raised.

A webhook-only GitHub source raised high alerts after 60 quiet minutes, while a source with a wrong credential since day one never paged and showed age 0 in /metrics (live-7).

Checked by: `tests/conformance/test_ops.py::test_a_webhook_only_source_is_quiet_on_a_quiet_day_not_dark`, `tests/conformance/test_ops.py::test_a_webhook_only_source_silent_for_a_week_is_dark`, `tests/conformance/test_ops.py::test_a_polled_source_keeps_its_own_clock`, `tests/conformance/test_ops.py::test_a_source_that_has_never_succeeded_is_stale`, `tests/conformance/test_ops.py::test_status_and_sources_never_disagree`, `tests/conformance/test_pages.py::test_metrics_show_when_a_source_and_detection_last_succeeded`, `tests/unit/test_connectors.py::test_a_store_failing_partway_keeps_the_cursor_at_the_last_page_stored`.

### OPS-G3 An alert is something a person can act on

An item goes into `ops.alerts`, `reporter.exceptions` or the weekly only when a person can act on it. Its instruction names the switch the code reads (`reporter._dry_run_switch` over `Policy.dry_run_for`), its text is built only from non-empty fields, and "high" and "top rules" count over `status NOT IN ('self','suppressed')`. A malicious case closed without real containment stays in front of a person until someone acknowledges it (D240). Expected states, such as a source still filling `HUNT_DAYS` of history (D246) or a quiet push source, raise nothing. A healthy install raises nothing at medium or above. A healthy install has a reachable pager or channel, a response credential for each source it reads, and `SHOC_DRY_RUN` set either way. A Compose install with `SHOC_DRY_RUN=1` and no response credentials asks for both.

The operator reads shoc only when something reaches them. Four of six live alerts were a new source's learning note, digests read "No detection for no rule maps to T1119", and 259 "high" findings were shoc's own (live-12). Two malicious, uncontained closures stayed hidden because no action had been proposed. Open: `detection_engineer.py` still words a source-gap line from the backlog item's title, so that digest line can come back.

Checked by: `tests/conformance/test_ops.py::test_high_findings_and_top_rules_leave_out_shocs_own_and_suppressed`, `tests/conformance/test_manager.py::test_dry_run_left_to_the_policy_is_still_named_and_turning_it_off_acts`, `tests/conformance/test_manager.py::test_a_malicious_case_closed_with_nothing_proposed_waits_for_a_person`, `tests/conformance/test_guidelines_ops.py::test_a_healthy_new_install_says_nothing`. Digest wording is review.

### OPS-G4 A read result fits an MCP client

Every read capability returns a result that fits an MCP client's result limit at production volume. `finding.list`, `action.list`, `case.list` and the notices inside `report.get` project each row to the keys their list views read and cut bodies the way `reporter._held` cuts at 300 characters. Only the matching `*.get` returns full evidence. This amends D296, which gives people and the crew whole `action.list` rows, and the change that applies it records the decision.

On the live instance the weekly reached 171k characters, `finding.list` 307k for 170 rows and `action.list` 103k for 50 rows, so Claude over MCP, the absent operator's main interface, got a truncated answer (live-13). Open: `action.list` cuts rows (`LISTED_CHARS`) only for external_agent callers, so a person's MCP client gets whole rows, `case.list` returns whole rows, and `rule.list`, `playbook.list` and `capability.list` exceed 100k characters as shipped.

Checked by: `tests/conformance/test_ops.py::test_a_finding_list_carries_only_the_evidence_a_row_is_read_by`, `tests/conformance/test_guidelines_ops.py::test_every_list_fits_an_mcp_result`.

### OPS-G5 Each operator switch is resolved in one function

Each operator switch is resolved in one function that every reader calls. Dry run is `Policy.dry_run_for(action_type, Config.dry_run)`, with `Config.dry_run` typed `bool | None` and None only while `SHOC_DRY_RUN` is unset (D180), and `actions.decide`, the reporter, `playbook_runs` and health all call it. `SHOC_*` variables are read only in `shoc/config.py`, and shoc.yaml keys that nothing reads are refused (D273). `source.configure`, `slack.configure` and `config.apply` merge into the existing sealed blob, and `config.plan` compares sealed secrets so a rotation shows as an update (D274).

`cfg.dry_run or None` turned `SHOC_DRY_RUN=0` into "ask the policy", which said dry run, while the exception report read the env flag and stayed silent (live-3). shoc.yaml accepted a `dry_run` key and ignored it, and `shoc apply` reported nothing to do for a rotated secret. Open: 11 `SHOC_*` reads sit outside config.py (in `cli.py`, `capabilities/llm.py`, `agents/ops.py`, `api/auth.py`, `db/secrets.py` and `api/mcp.py`). `playbooks.start` and `playbooks.job_key` read `dry_run` without `dry_run_for`, so a run is recorded live while the policy holds every action as a plan, and health reads no dry-run switch.

Checked by: `tests/unit/test_policy.py::test_shoc_dry_run_set_either_way_wins_over_the_policy`, `tests/unit/test_configcode.py::test_a_key_shoc_does_not_read_is_refused`, `tests/conformance/test_configcode.py::test_a_rotated_credential_is_an_update_and_apply_seals_it`, `tests/unit/test_guidelines_ops.py::test_settings_are_read_in_one_place`, `tests/unit/test_guidelines_ops.py::test_dry_run_is_resolved_by_the_policy`.

### OPS-G6 A release never stops an install the last one left running

A new check on existing state (the master key, a password in `SHOC_DSN`, the schema, policy.yaml, stored config) warns through `health.status` and `reporter.exceptions` and refuses only what is public or new: the example master key (D194), `SHOC_NEW_MASTER_KEY`, a new configure call or an empty database. An install that upgrades itself unattended has nobody at hand when a start is refused. serve and worker wait on `migrate.drift` and report `schema_ahead` instead of crashing (D195). From the first release on, a migration keeps the previous release's queries working, because Helm's pre-upgrade hook runs it while the old pods still serve. A move to another event-store backend counts as an upgrade, and its connector cursors are handled so the new store has no hole.

Requiring a 32-character `SHOC_MASTER_KEY` at start would have refused every install keyed with a passphrase, and wave 1's length check briefly stopped `shoc migrate` on installs already keyed with a short key (sre-7). The upgrade test only migrated an empty database, so nothing exercised an install with data (D304). Migrations 014 (a rename), 020 (SET NOT NULL) and 025 (DROP DEFAULT) predate any release and are listed in the test.

Checked by: `tests/unit/test_startup_checks.py::test_the_example_master_key_is_refused`, `tests/unit/test_startup_checks.py::test_a_short_key_in_use_is_warned_about_but_still_starts`, `tests/unit/test_startup_checks.py::test_a_short_new_key_is_refused`, `tests/conformance/test_schema_and_sessions.py::test_code_with_a_migration_not_applied_waits_for_shoc_migrate`, `tests/conformance/test_schema_and_sessions.py::test_a_schema_migrated_by_a_newer_release_is_reported`, `tests/conformance/test_migrations.py::test_no_migration_destroys_data`, `tests/unit/test_guidelines_ops.py::test_no_new_migration_breaks_the_previous_release`.

### OPS-G7 Deploy files follow the code and ship locked down

deploy/docker-compose.yml, deploy/.env.example and deploy/helm/shoc stay in step with `shoc/config.py` and are safe as shipped. Every `SHOC_*` variable the code reads passes through `x-shoc-env` and is documented in docs/deploy.md (D283), except the six that docs/deploy.md keeps on the host: `SHOC_NEW_MASTER_KEY`, `SHOC_ALLOW_WEAK_KEY`, `SHOC_CLI_USER`, `SHOC_MCP_ROLE`, `SHOC_MCP_USER` and `SHOC_CONTENT_DIR`. `SHOC_SECRET_*` go through an optional env_file. After the first release, `SHOC_VERSION` and the console image default to the released, cosign-signed version that release-please bumps. Both Dockerfiles pin FROM by digest, the console builds with `npm ci` alone, every service bounds its json-file logs, and shoc, worker and worker-urgent run read_only with `cap_drop: [ALL]` and no-new-privileges (D282). The Secret the Helm migrate hook reads is a lower-weight pre-install hook.

Compose passed only the variables `x-shoc-env` listed, so `SHOC_HEARTBEAT_URL`, `SHOC_DISK_BUDGET_GB`, `SHOC_CYCLE_SECONDS` and `SHOC_INTEL_FEEDS` never reached a container, even though `health.status` told the operator to set the first (po-9). Open: both compose files default to `:edge`, release.yml publishes no console image, and release-please's extra-files bump only `shoc/__init__.py`, so neither the compose files nor the chart's `appVersion` would follow a release.

Checked by: `tests/unit/test_deploy.py::test_serve_and_workers_run_hardened`, `tests/unit/test_deploy.py::test_every_service_rotates_its_logs`, `tests/unit/test_deploy.py::test_the_charts_secret_exists_before_the_migrate_hook_reads_it`, `tests/unit/test_deploy.py::test_base_images_are_pinned_by_digest`, `tests/unit/test_deploy.py::test_the_console_build_requires_its_lockfile`, `tests/unit/test_deploy.py::test_serve_and_worker_never_see_the_owners_dsn`, `tests/unit/test_guidelines_ops.py::test_every_setting_reaches_the_containers`, `tests/unit/test_guidelines_ops.py::test_released_images_are_the_default`.

### OPS-G8 Every documented command runs as written

Every command in README.md and docs/ is written for the install it sits under and runs as written. Compose steps go through `docker compose run --rm shoc ...` (owner commands through `migrate`) and parse with `shoc.cli.build_parser()`. A demo replay names its own `--tenant`. No secret appears on a command line or in an MCP client's config. Every count, cadence or default the prose states (detection every 15 minutes from `SHOC_CYCLE_SECONDS`, playbooks and rules shipped, connectors) is checked against the code by a test.

Quick start step 3 ran a bare `shoc` on a Docker host that has none, its demo replayed an attack into the production tenant, and the MCP snippet put `SHOC_MASTER_KEY` into the assistant's config (po-6). The README said five-minute cycles and 38 playbooks. Open: docs/agents.md writes `shoc memory add-fact` and docs/connectors.md `shoc source push-key` where the CLI words are `add_fact` and `push_key`, docs/response.md passes `--dry-run true`, docs/ontology.md says 268 rules and 38 playbooks, the README and docs/index.md replay without `--tenant`, and the quick start's checkout MCP snippet still carries `SHOC_MASTER_KEY` and a DSN password, because `cmd_mcp` needs the key to write the audit log.

Checked by: `tests/unit/test_scaffold.py::test_a_scaffolded_connector_names_every_test_that_judges_it`, `tests/unit/test_guidelines_ops_docs.py::test_every_documented_command_parses`, `tests/unit/test_guidelines_ops_docs.py::test_a_demo_replay_names_its_tenant`, `tests/unit/test_guidelines_ops_docs.py::test_no_secret_on_a_documented_command_line`, `tests/unit/test_guidelines_ops_docs.py::test_no_secret_in_a_documented_mcp_client_config`, `tests/unit/test_guidelines_ops_docs.py::test_documented_numbers_match_the_code`.

## Console

### UI-G1 No all-clear until every query answered and shoc can see

No console summary (the Overview heading and Standing facts, the Health pipeline stages, the rail and tab-title count) shows an all-clear until every query it reads has answered and shoc can see. No configured source, no source delivering, a failing model on Overview or an absent one on Health › Crew (D278), a `notify.page` that reached nobody, and a list that failed each get their own non-good word, ranked above "Nothing needs you". An unknown value reads as a dash or "Can't tell", never 0.

Overview chose "Nothing needs you" in green from the inbox alone, and Health drew Crew and Notify as done while shoc had no sources, no model or no working pager (ux-4).

Checked by: `console/tests/overview.test.tsx::reads Nothing connected, never an all clear, while no source is configured`, `console/tests/overview.test.tsx::says nothing needs you only once every list answered`, `console/tests/pipeline.test.ts::fails Crew with no model, as Services says not connected`, `console/tests/pipeline.test.ts::counts a page that reached nobody in 24h: failed, blocked, or let go by the Manager or by nobody`, `console/tests/needs.test.ts::reports a failed list as failed, never as an empty inbox`, `console/tests/cases-screen.test.tsx::reads Can't tell with tab counts unknown and Retry when case.list fails, never an empty queue`.

### UI-G2 A label names the kernel fact

Every tab, counter and state chip (`console/src/lib/labels.ts`, `lib/cases.ts`, `routes/overview/handover.ts`) is worded as the kernel fact it is computed from. A case counts as contained only through the `contained` predicate in `routes/case/moments.ts` (a non-notify action that ran, D139). The Cases tab for cases in response reads "Responding" (D277). A dry run reads "planned". A window with no stored visit reads "Last 24 hours". Failed and blocked actions get their own counter, drawn first in bad tone.

"Contained" meant the containment phase, "Last visit" meant a default 24 hours, and "done" hid failed containment, so the absent operator read success where nothing had run (ux-2).

Checked by: `console/tests/cases-screen.test.tsx::names the response phase for what it is, never contained`, `console/tests/overview.test.tsx::names no last visit it never saw`, `console/tests/overview.test.tsx::counts failed and blocked responses first, in bad, and leaves pages and older ones out`, `console/tests/labels.test.ts::says planned for a dry run and expired for an approval nobody gave`.

### UI-G3 The console never filters a capped list

No inbox row, rail count or fact is built by filtering a capped list in the browser (`CASE_CAP` 200 and `ACTION_CAP` 500 in `console/src/lib/reads.ts`, `MEMORY_CAP` 100 in `lib/queries.ts`). The console passes the filter to the capability (`case.list`'s verdict, state or unacknowledged), and the kernel applies it before the LIMIT under CON-G7. A count read off a capped list shows through `capped()` in `format.ts` as "N+".

`needs.ts` read needs_human cases from the capped `useCaseLog`, so the oldest undecided case dropped out of the inbox when the operator had been away longest (ux-6). It now asks `case.list` for them through `useWaitingVerdicts`.

Checked by: `console/tests/needs.test.ts::keeps a waiting verdict and its expired approval that the capped case log no longer holds`, `console/tests/guidelines.test.tsx::asks case.list for needs_human cases itself`. The kernel side is checked under CON-G7.

### UI-G4 Every query key has a freshness owner

Every query key a screen renders has at least one freshness owner in console/src/lib. That is an entry in `invalidations()` in `live.ts` for each contract event type that changes it (or a place in the test's explicit NOTHING list), or a `refetchInterval` whose route test is built from `ROUTES` in `lib/nav.ts`. `source.list` is polled every 30s on Connections and Health only, and elsewhere stays fresh through the stream. A refresh in `later` (a `Later` with its `key` and `ms`) fires within twice its `ms` however long a burst of events lasts.

Event types that refreshed nothing (`hunt.item`, `intel.report`), a polling regex that still named the retired /sources route, and a trailing debounce that restarted on every finding each left screens stale while the stream read "live" (fe-6).

Checked by: `console/tests/live.test.ts::refreshes something on every event type the contract lists, or says why not`, `console/tests/live.test.ts::still refreshes a list within twice its spell while a burst does not let up`, `console/tests/reads.test.ts::is polled on Connections and Health, where it shows, and nowhere else`, `console/tests/guidelines.test.ts::polls source.list on every route from ROUTES that renders it`.

### UI-G5 One stream per tab, released when hidden

The SSE reader in `console/src/lib/stream.ts` is the only long-lived connection a tab holds. It closes after `HIDDEN` (30s) in a hidden tab and resumes with `since=<last seq>`. On `event: signed_out` or a 403 it stops without retrying. Each of those branches is tested against a fake ReadableStream body.

Over HTTP/1.1 each tab's stream held one of the six sockets the browser shares per host, so about six tabs froze every shoc tab in the middle of an incident (fe-1). The reader that owns sign-out, resume and the 15s silence watchdog had no test.

Checked by: `console/tests/live.test.ts::gives its stream's socket back after 30s, and picks up from the last event once in view`, `console/tests/stream.test.ts::delivers a frame split across reads once`, `console/tests/stream.test.ts::stops on \`event: signed_out\` and raises the signed-out banner`, `console/tests/stream.test.ts::stops quietly on a 403: a missing scope is no ended session`, `console/tests/stream.test.ts::reconnects after a close from the last event it saw`, `console/tests/stream.test.ts::drops a connection silent for 15s and opens another`.

### UI-G6 Slow reads get the long deadline and no blind retry

A capability that reads the event store or calls a model, an OSINT source or a vendor API is in the `SLOW` set in `console/src/lib/api.ts` and gets `SLOW_DEADLINE`, 150s, the same as nginx's `proxy_read_timeout` for /v1 in console/deploy/nginx.conf. `retryable` retries only `network` failures (status 0, 502, 503), never a `timeout`, a 504 or a kernel 5xx, because a retry runs the same warehouse statement again (D279).

The 30s default failed store and vendor reads while the kernel was still working, and the old retry re-ran timed-out warehouse scans twice, which meant up to 7.5 minutes of skeleton and three billed statements (fe-4). Carrying a `slow` flag in contract/v1.json would change the contract under D24, so that needs its own decision. Open: `finding.get`, `health.cost`, `health.status`, `hunt.pack`, `hunt.results`, `intel.add`, `openspace.post` and `ops.alerts` read the store with the 30s deadline.

Checked by: `console/tests/api.test.ts::calls a deadline a timeout, not an unreachable shoc, and gives store and vendor reads the long one`, `console/tests/api.test.ts::tries a read again only when shoc could not be reached`, `tests/unit/test_guidelines_ui.py::test_every_slow_capability_is_in_the_consoles_slow_set` (store and model use). Vendor and OSINT reads are review.

### UI-G7 Copied vocabularies are checked against the kernel

Every kernel vocabulary the console copies by hand is checked against its source. The ACTIONS labels are checked against contract/v1.json `actions`, and the key fields in `types.ts` against the `output_schema` of the capabilities the console renders. The case state, verdict and disposition labels in `labels.ts` have a label for every id in `STATES`, `VERDICTS` (plus `LEGACY_VERDICTS`) and `DISPOSITIONS` in `shoc/cases/engine.py`, with `CASE_STATES` in engine order. On the kernel side, every `publish()` call for an event type sends the same payload keys.

Eleven action types fell back to "Revoke sessions" with no platform, the lifecycle showed raw NIST ids, and `case.opened` from `engine.move` carried no severity, so a critical case raised no toast (ux-11). Open: `events.loaded` (`pushed` from rest.py), `finding.new` (`source` from intel, `events` from rules) and `report.ready` (`held` against `items`) are published with two shapes.

Checked by: `console/tests/labels.test.ts::names every action type policy.show lists (contract/v1.json actions)`, `console/tests/labels.test.ts::names every case phase in plain words, none of them a NIST id`, `console/tests/contract.test.ts::reads exactly the fields each capability returns`, `tests/unit/test_contract.py::test_event_types_are_read_from_the_code_and_only_grow`, `tests/unit/test_guidelines_ui.py::test_every_publish_of_an_event_type_sends_the_same_payload_keys`, `tests/unit/test_guidelines_ui.py::test_the_consoles_case_vocabularies_match_the_engine`.

### UI-G8 A confirm lists every effect

Every console confirm lists each effect the kernel will have, cascades and predictable failures included. `CloseDialog`, and any path to case state closed, names each proposed or approved action that `close_case` will reject. `ProposeDialog` says "will fail · connect <platform>" when `useCredentials()` has no credential for the action's provider and dry run is off. A new kernel cascade updates its confirm in the same PR.

The close confirm said only "Close as Attack" while the kernel rejected the waiting L2 "Disable AWS key" (ux-1).

Checked by: `console/tests/case.test.tsx::offers Approve and close on an attack with an action waiting, and only then`, `console/tests/propose.test.tsx::says an action with no credential will fail, and links to connect one`, `tests/conformance/test_case_close.py::test_a_person_asks_again_for_what_their_close_rejected`.

### UI-G9 Log, feed and crew strings are data

Every string from logs, feeds or crew prose is rendered as text (the no-restricted-syntax rule in console/eslint.config.js), linked only through `safeHref` in `lib/url.ts` (http and https only) or a module constant, and never sent to `ask` as an operator turn. A `?entity=` value is accepted only as a single kind:value token with no whitespace or control characters.

An `?entity=` link could put any 200-character sentence into the crew chat as the operator's own words, and rule references and intel report URLs were rendered as links whatever their scheme (fe-8). Open: `routes/intel/Queue.tsx` tests `row.url` with `hostOf` from `routes/intel/feeds.ts`, which trims, and then links the untrimmed `row.url` instead of going through `safeHref`.

Checked by: the no-restricted-syntax rule in console/eslint.config.js, `console/tests/chat.test.ts::takes no sentence in an entity's value, whatever its kind says`, `console/tests/guidelines.test.ts::links only through safeHref or a module constant`.

### UI-G10 A secret leaves the browser cache with its form

Every mutation in `console/src/lib/queries.ts` that sends a credential field, or calls a capability that returns a secret, passes `gcTime: 0`. Credential fields are the contract `input_schema` properties `secret`, `api_key`, `bot_token`, `signing_secret` and `client_secret`, and secret outputs are the capabilities in `SECRET_RETURNING` in `tests/unit/test_security_invariants.py`. A mutation that calls such a capability without sending a secret (`useConfigureFeed`, `useAddReportSource`, `useToggleSource`) is listed in the test. Per-person browser state (`shoc.chat`, recent lookups and records) is stored with the `user.me` id and dropped on a mismatch and on Log out (D280).

`credential.configure`, `slack.configure`, `llm.configure` and `sso.configure` kept their secrets in the mutation cache for 5 minutes, and so did `useConnectSource`, `useConfigureLookup` and `usePushKey` until a later fix (fe-17). An expired session handed the previous person's crew thread to the next one.

Checked by: `console/tests/secrets.test.tsx::leaves the mutation cache once %s's form closes`, `console/tests/chat.test.ts::stay for the same person and go when someone else signs in on this browser`, `console/tests/chat.test.ts::go on Log out`, `console/tests/guidelines.test.ts::passes gcTime 0 for every capability that takes or returns a secret`.

### UI-G11 State shown by colour is also said in text

Every state the rail, strips and badges show by colour, a dot or position is also carried in text a screen reader announces (an aria-label, or an sr-only span outside any display:none rule in `console/src/components/ui/shoc.css`).

The collapsed rail hid the "needs you" count from sight and from screen readers at once (ux-14).

Checked by: `console/tests/rail.test.tsx::keeps the inbox count when collapsed, as a crew dot a screen reader hears`. Each new display:none rule is review.

### UI-G12 A writing control never acts on arrow keys

A control that writes (`finding.set_status`, case state, approvals) is a menu, a button or a Seg in `manual` mode, so arrow keys only move focus.

Arrow keys on a finding's status Seg wrote an audited status change as soon as a keyboard user looked at the options (ux-14).

Checked by: `console/tests/seg.test.tsx::only moves with the arrow keys when it writes, and picks on Enter or Space`. Each new writing Seg is review.

### UI-G13 Every costly command asks before it runs

Every command in `console/src/lib/commands.ts` that writes, spends model tokens or scans the warehouse declares a `level` and goes through a confirm when it arrives as a `?do=` link or a palette hand-off, either with `confirm: true` or through a handler that opens its own dialog (listed in `CONFIRMS_ITSELF`).

`case.investigate` ran a full crew pass from a pasted `?do=` link with no question. Open: `source.pull`, `pack.run` and `indicator.sweep` ask but declare no level, and `rule.replay` has neither, so a `?do=rule.replay` link runs the 7-day `rule.backtest` at once.

Checked by: `console/tests/commands.test.ts::asks before a link re-investigates a case, which spends model tokens`, `console/tests/commands.test.ts::asks before a hand-off that writes, and runs it only on the confirm`, `console/tests/guidelines.test.ts::leaves no levelled command without a confirm`, `console/tests/guidelines.test.ts::gives every command that asks before it runs a level`. A command with neither level nor confirm is review.

## Tests and simplicity

### TST-G1 Fixture order is stated in time

In `tests/fixtures/rules/<id>/*.json` and `evals/scenarios/*/events.json`, every record whose place in time matters (a sequence rule's `first` and `then`, a `first_seen` baseline, the edges of a threshold window) carries its own `_day_offset`, spaced more than the 120-second spread of `shoc.ingest.replay.expand` apart. `expand` stamps the first record of a file nearest now and each later one a second earlier, and a literal vendor timestamp falls outside the 1-hour detect window. A record without `_day_offset` is therefore ordered by its position, latest first, so a sequence fixture that has no offsets yet lists its later event first.

When qa-11 gave entra a `TIME_FIELD`, two Entra sequence rules stopped firing on their positive fixtures and fired on their negative ones, which had been quiet only because of record order in the file. `entra_device_registered_after_device_code` and `entra_mfa_registered_after_risky_sign_in` were fixed by listing the later event first. Open: all 11 sequence rules still rely on position.

Checked by: `tests/unit/test_mapping_safety.py::test_replay_places_every_source_on_a_path_its_mapping_reads`, `tests/unit/test_guidelines_tst.py::test_a_sequence_fixture_states_its_order`, `tests/unit/test_guidelines_tst.py::test_known_unordered_lists_only_sequence_rules`, `tests/conformance/test_guidelines_con.py::test_a_sequence_rule_is_quiet_on_its_positive_fixture_reversed`.

### TST-G2 Fakes answer by route and keep the real signature

Every vendor HTTP call in a test (connectors, `shoc/actions`, `notify.page`, OSINT lookups) is faked through one helper in tests/support.py (still to be written, see Open) that answers by (method, path), records each request and raises on any request it has no answer for. A test installs its transport once, so every request in it goes through the same fake. An autouse fixture in tests/conftest.py makes any real httpx send fail unless the test is marked for a warehouse run. A monkeypatched stand-in for a shoc function (`jobs.claim`, `jobs.become_cron_leader`, `worker.wait_for_jobs`, `batchwriter.load`) keeps the real signature: it wraps the real function or accepts `*args, **kwargs`, and the test asserts that it was called. A test that waits polls a condition with a deadline in a `while` loop and sleeps a fixed time nowhere else. A test that runs `worker.run` in a thread waits on a `threading.Event`, and an exception in that thread fails the test.

`test_connectors.transport` answered in call order and returned 200 {} once its script ran out, so a gcp_audit order change made a test assert on the wrong reply (lean-13). When `jobs.claim` gained `most_tier`, a fixed-signature fake raised TypeError in the worker thread, and the reconnect test failed for an unrelated reason (qa-20). A scratch harness that patched clients one at a time left one unpatched and sent a request with a dummy key to a live feed. Open: the route helper and the no-network fixture do not exist yet, so 21 test files build `httpx.MockTransport` themselves, the guideline tests' own `test_guidelines_con._serve` and `test_guidelines_sec._answer` among them, and `test_guidelines_ing.py::test_a_listing_connector_stops_at_its_limit` reuses the call-order `test_connectors.transport`. They move to the route helper once it exists. Five fixed sleeps remain, and `test_worker.py::test_a_queued_job_wakes_an_idle_worker` patches `worker.ensure_default_schedules` with two parameters where `worker.run` passes three.

Checked by: `tests/unit/test_guidelines_tst.py::test_no_new_fixed_sleeps`, `tests/unit/test_guidelines_tst.py::test_fakes_keep_the_real_signature`, `tests/unit/test_guidelines_tst.py::test_the_signature_check_sees_a_missing_keyword`, and the `filterwarnings` entry `error::pytest.PytestUnhandledThreadExceptionWarning` in pyproject.toml. The route helper, the no-network fixture and one transport per test are review.

### TST-G3 A test proves the production path with exact values

Every assertion compares an exact value worked out without the code under test, such as `["data"]["loaded"] == 0`, and never makes a bare check on the capability envelope. A store check counts rows through a second store or raw SQL. An eval scenario passes only on the outcome it expects, with `gap` only for untriaged tuples and no false positives. A test parametrised over shipped content (`ruleset.load()`, `hunts.load()`, `playbooks.load()`, evals/scenarios, `ocsf.available_sources()`) runs each item through the production path and asserts on what comes out, and an empty parameter list fails collection. Every PR names the line in shoc/ whose revert makes each new test fail.

The GitHub redelivery assertion checked only that a dict was truthy, and the store tenant check passed because of its own `WHERE tenant_id` clause (qa-15). A wheel that lost content/ loaded zero rules while `shoc rules check` printed 0/0 and exited 0 (qa-10).

Checked by: `tests/unit/test_rules_content.py::test_release_ships_the_full_rule_pack`, `tests/unit/test_guidelines_tst.py::test_no_assertion_on_the_envelope_alone`, `empty_parameter_set_mark = "fail_at_collect"` in pyproject.toml, `tests/conformance/test_playbook_coverage.py::test_the_playbook_acts_on_the_rules_positive_fixture`. The revert note is review.

### TST-G4 Tests leave shared state as they found it

The session fixtures `config`, `conn` and `store` in tests/conftest.py are read-only, and their fields change only through `monkeypatch.setattr`. Every conformance test that writes a shoc table takes `clean`. The table lists of `clean` and of the `conn` teardown cover every shoc table with a `tenant_id` column, the append-only audit tables aside. A test that touches `shoc.jobs`, the cron lock or the worker loop asserts only on jobs it enqueued. Findings, cases, actions, jobs, schedules and connector state are created through a capability or one factory per table in tests/support.py that fills every NOT NULL column and takes the UNIQUE key columns as arguments. A UNIQUE value that outlives `clean` (`shoc.jobs.idempotency_key`, push delivery ids) includes the test tenant id or a uuid.

`config.max_request_bytes = 1024` stayed set for the rest of the session, and `push_deliveries` outlived `clean`, so a shared delivery id made `loaded == 1` depend on test order (qa-16). Jobs left running by earlier tests were taken back by `requeue_stale` in later ones and changed the claim order. Open: `clean` does not empty `api_tokens`, the two table lists are kept by hand, nine tests assign `config.llm_provider` directly, and the per-table factories and a job-leak guard do not exist yet, so 69 INSERTs into findings, cases, actions, jobs, schedules and connector state in 21 files seed tables themselves, the guideline tests' `test_guidelines_con._seed_lists`, `test_guidelines_ops` and `test_guidelines_agt` among them.

Checked by: `tests/conformance/test_guidelines_tst.py::test_clean_empties_every_tenant_table`, `tests/unit/test_guidelines_tst.py::test_session_fixtures_are_not_assigned`. Seeding through factories and the job-leak guard are review.

### TST-G5 Config is loaded at entry points only

Library code in shoc/ takes `config` and `store` as required arguments, and `Config.load()` is called only at entry points (`cli.main`, `worker.run`, `rest.build_app`, `mcp.serve_stdio`, `mcp.session_manager`). In tests, every `replay()` and `malicious_case()` call passes the parametrised store. The test `config` fixture runs with `llm_provider` none and `SHOC_DRY_RUN` unset unless `SHOC_TEST_ALLOW_MODEL=1` (D303), and crew tests drive `ScriptedClient` (D28). Conformance `ctx` and stores connect as the runtime role (D62, D302).

Scenario replays ignored the parametrised store and replayed into Postgres during a warehouse run (qa-2). In a shell with `SHOC_LLM_PROVIDER` set, the crew tests called the real model and spent the shared credit, and the suite ran as the schema owner. Open: 32 `config or Config.load()` fallbacks and 2 `Config()` default reads remain in library code.

Checked by: `tests/conformance/test_isolation.py::test_the_suite_runs_as_an_ordinary_role`, `tests/conformance/test_runtime_role.py::test_capabilities_run_as_a_role_that_does_not_own_the_schema`, `tests/unit/test_guidelines_tst.py::test_config_is_loaded_only_at_entry_points`, `tests/unit/test_scenario_hygiene.py::test_every_replay_in_the_suite_goes_to_the_store_under_test`.

### TST-G6 A fix lands on every sibling

Behaviour that lives in sibling modules moves into one function, or every sibling is covered by one parametrised test, and a fix to one sibling lands on all of them in the same change. The sibling sets are the merged-content loaders (`rules.merged`, `hunts.merged`, `playbooks.merged`), the EventStore adapters, the detection and hunt backlogs, the connectors' OAuth token caches, finding and case id hashing, ISO time parsing and the public-address check. These have one home: `osint.is_public_address` (D286), `batch.batch_name` (DAT-G4), ISO time parsing (ocsf's `iso8601` transform, wrapped for connectors as `base.utc`, ING-G8), the token cache (`_TOKENS` with `cached()` and `keep()` in `connectors/base.py`), prefixed ids (`shoc.ids.make_id`) and the adapters' statement timeouts (DAT-G3). The shared staging directory in `store/base.py` does not exist yet. CI conformance runs Postgres only, so each adapter duty gets a unit test that needs no warehouse.

D162 gave Databricks a shared staging directory and thread-unique names while Snowflake, Redshift and BigQuery kept the old ones (lean-1). `rules.merged` lacked the skip-a-broken-row guard the hunt and playbook loaders had, and nine time parsers disagreed on naive datetimes. Open: ten `.replace("Z", "+00:00")` parsers outside ocsf, two staging directories built from time (databricks and snowflake `_staging_dir`; Postgres's session-local TEMP table is exempt as in DAT-G4), ids hashed outside `make_id` (hunter `TUP-`, manager `N-`, intel `RPT-` and `HUNT-`, stream `WH-`), Redshift's statement timeout with no unit test, a merged hunt pack with a shipped id dropped without a reason, and `playbooks.load` with no `skipped` list.

Checked by: `tests/conformance/test_rules.py::test_a_merged_rule_that_no_longer_loads_or_takes_a_shipped_id_is_left_out`, `tests/unit/test_warehouse_timeouts.py::test_every_warehouse_is_opened_with_the_configured_timeout`, `tests/unit/test_guidelines_tst.py::test_each_helper_has_one_home`, `tests/conformance/test_guidelines_tst.py::test_a_broken_merged_row_leaves_the_shipped_set`.

### TST-G7 Fixtures use visibly fake vendor ids

Beyond the documentation addresses CLAUDE.md requires, tests/fixtures/ and evals/scenarios/ use visibly fake vendor ids: Stripe `acct_` and `mk_` ids containing `fake` (`acct_1PfakeLiveAcct01`), and a zero-padded Cloudflare account id (16 or more leading zeros). `evals.capture` refuses an `--out` path inside the repository.

A Stripe `acct_` id marked livemode true and a 32-hex Cloudflare account id came from real exports and shipped in every wheel through `_rule_fixtures` (qa-13). `evals.capture` could write a customer's logs into a tree that CI tests and the wheel ships. Open: three `mk_` ids in the `stripe_secret_key_created_or_viewed` fixtures and two Cloudflare account ids in the 18 fixture files of 9 `cloudflare_*` rules and the cloudflare mapping fixture (19 files).

Checked by: `tests/unit/test_guidelines_tst.py::test_fixtures_use_fake_vendor_ids`, `tests/unit/test_scenario_hygiene.py::test_no_scenario_is_a_capture_nobody_scrubbed`, `tests/unit/test_scenario_hygiene.py::test_a_capture_is_never_written_into_the_repository`.
