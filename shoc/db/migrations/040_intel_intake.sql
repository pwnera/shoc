-- 040 reports are picked before they are read (DET-7, RFC 0029)
--
-- A queued item is scored on what its feed says about it, without a model, and
-- read best-first under the tenant's daily cap. Items that are skipped, linked
-- to a story already read, or dropped stay in the queue with the reason, so
-- the next poll neither scores nor reads them again; rows are deleted 30 days
-- after they were queued.
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS summary      text NOT NULL DEFAULT '';
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS published_at timestamptz;
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS score        real NOT NULL DEFAULT 0;
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS reason       text NOT NULL DEFAULT '';
-- waiting, skipped, same_story or dropped
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS state        text NOT NULL DEFAULT 'waiting';
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS same_as      text NOT NULL DEFAULT '';
-- The triage call's tokens, and when it ran; they count toward its day.
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS tokens       integer NOT NULL DEFAULT 0;
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS triaged_at   timestamptz;
ALTER TABLE shoc.intel_queue ADD COLUMN IF NOT EXISTS changed_at   timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS intel_queue_waiting
    ON shoc.intel_queue (tenant_id, score DESC, queued_at) WHERE state = 'waiting';
