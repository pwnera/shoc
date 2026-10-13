-- 067 what each source's pulls re-read, left out and placed at ingest time (ING-1, STO-2, D150, D164)
--
-- A poll by event time now re-reads the last 15 minutes of each stream, and
-- counts per stream the events found there that no earlier run had read: they
-- arrived late, and without the overlap they were never ingested. The store
-- leaves out a row Postgres refuses, and an event whose own time is unreadable
-- or implausible is placed at ingest time. Each was only a log line; these keep
-- running counts that health.sources shows.
ALTER TABLE shoc.connector_state
    ADD COLUMN IF NOT EXISTS late_events jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS events_skipped bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS times_replaced bigint NOT NULL DEFAULT 0;

-- Each kept key now carries its stream and its row's time, 16 bytes instead of
-- 8, so it stays exactly as long as a re-read can return its row. The old keys
-- are dropped: the first poll after this sends its re-read rows to the store
-- once more, which keeps one row per event_uid and time.
UPDATE shoc.connector_state SET stored_keys = NULL WHERE stored_keys IS NOT NULL;
