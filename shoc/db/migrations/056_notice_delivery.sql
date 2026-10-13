-- 056 a page the pager could not take is tried again (RSP-4, OPS-1, RFC 0015)
--
-- A failed page was settled at once: one PagerDuty 503 or network blip lost it
-- for good, and the same notice told again that day was the same row. Now the
-- Manager leaves it undelivered, counts the try in `attempts`, keeps why in
-- `last_error` and comes back at `retry_at` (1, 5 and 15 minutes), then settles
-- it as failed. A pager nobody configured, or a page the policy refuses, is
-- settled at once: waiting does not change it (shoc/agents/manager.py).
ALTER TABLE shoc.notices ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;
ALTER TABLE shoc.notices ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE shoc.notices ADD COLUMN IF NOT EXISTS retry_at timestamptz;

-- When detection last finished: the hourly check pages when it is too long ago,
-- and /metrics exports it on every scrape. Without this both read every done
-- job of the week the nightly prune keeps (OPS-1).
CREATE INDEX IF NOT EXISTS jobs_done ON shoc.jobs (tenant_id, kind, finished_at)
    WHERE state = 'done';
