-- 024 intel sources: indicator lists, report feeds, hand-added indicators (DET-4, DET-7, RFC 0016)
--
-- A source's name and its parser are now two columns, so a tenant can follow
-- several RSS feeds or indicator lists. An empty parser means the name is the
-- parser, which is what every row written before this migration meant.
ALTER TABLE shoc.intel_feeds ADD COLUMN IF NOT EXISTS parser text NOT NULL DEFAULT '';

-- The source a polled report came from; empty for one somebody handed in. The
-- index is how a poll skips the items it has already read.
ALTER TABLE shoc.intel_reports ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS intel_reports_url ON shoc.intel_reports (tenant_id, url);
