-- 059 indexes for the queue's live and failed jobs and the stream's time reads (DET-3, OPS-1)
--
-- The only index on jobs besides its keys covered pending jobs. The cron
-- leader's look for a schedule's queued copy, its look for running jobs whose
-- worker is gone, and the sweep's look for a case's crew run read every job
-- ever finished, and so did `health.jobs`. The hourly Ops check and the reports
-- read the stream by time, which only its sequence was indexed for.
CREATE INDEX IF NOT EXISTS jobs_active ON shoc.jobs (tenant_id, kind)
    WHERE state IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS jobs_failed ON shoc.jobs (tenant_id, finished_at)
    WHERE state = 'failed';
CREATE INDEX IF NOT EXISTS stream_tenant_created ON shoc.stream_events (tenant_id, created_at);
