-- 065 when each account of a source starts, and whether a hunt run advanced
-- (DET-8, DET-9, DET-11, D79)
--
-- A member account that joins an organisation trail inherited the source's
-- start, months back, so every identity and operation in it was first-seen on
-- its first day. Each account keeps the time of its own first event, as
-- {account: timestamptz}. An account a source named before this keeps the
-- source's start, as it had.
ALTER TABLE shoc.source_history
    ADD COLUMN IF NOT EXISTS account_starts jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE shoc.source_history h
   SET account_starts = (
       SELECT jsonb_object_agg(a, coalesce(h.first_event_at, h.first_loaded_at))
         FROM unnest(h.account_uids) AS a)
 WHERE h.account_starts = '{}'::jsonb AND cardinality(h.account_uids) > 0;

-- Whether a hunt run moved its pack's cursor. A gap the ceiling, a missing
-- model or a failed triage left is read again the next day (D106); comparing
-- the cursor with the run's window start could not tell, once a late load had
-- pulled that start back (DET-9).
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS advanced boolean NOT NULL DEFAULT false;
