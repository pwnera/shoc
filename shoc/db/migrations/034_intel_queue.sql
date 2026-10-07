-- 036 a report source's unread items wait their turn (DET-7)
--
-- A poll read at most `max_items` reports and forgot the rest, so on a feed
-- that publishes more than that between polls the older items scrolled off
-- before anything read them. Every item a poll sees and has not read is now
-- queued here, with its text when the source carries it, and each poll reads
-- from the front of the queue.
CREATE TABLE IF NOT EXISTS shoc.intel_queue (
    tenant_id  text NOT NULL,
    feed       text NOT NULL,
    url        text NOT NULL,
    title      text NOT NULL DEFAULT '',
    text       text NOT NULL DEFAULT '',
    attempts   integer NOT NULL DEFAULT 0,
    queued_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, url)
);
CREATE INDEX IF NOT EXISTS intel_queue_next ON shoc.intel_queue (tenant_id, feed, queued_at);

-- URLhaus now stores each URL as a `url` indicator (DET-4). The hosts it stored
-- as domains and addresses would keep matching every page on a shared host
-- until they expired, so they go now.
DELETE FROM shoc.iocs WHERE source = 'abuse.ch/urlhaus' AND type IN ('ip', 'domain');

SELECT shoc.enable_tenant_rls();
