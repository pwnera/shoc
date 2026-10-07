-- 032 each webhook remembers the last event it was sent (API-2)
--
-- Delivery read from sequence 0 on every run and so resent the first batch
-- forever. A subscriber now starts at the stream's head when it subscribes and
-- moves forward only when it answers 2xx. Hooks that already exist start at
-- the head too, rather than replaying the history they never got past.
ALTER TABLE shoc.webhooks ADD COLUMN IF NOT EXISTS last_seq bigint NOT NULL DEFAULT 0;

UPDATE shoc.webhooks w
SET last_seq = coalesce(
    (SELECT max(seq) FROM shoc.stream_events s WHERE s.tenant_id = w.tenant_id), 0
);
