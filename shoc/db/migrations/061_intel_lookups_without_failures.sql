-- 061 cached lookups keep answers only, and no URL's query (DET-6, SEC-1)
--
-- A failed keyed lookup was cached with its error text, and httpx's text for an
-- HTTP error is the whole request URL: Shodan's and ipapi.is's key rides in its
-- query string. A URL was also cached under its full text, a reset token or a
-- presigned signature included. `osint._to_cache` now keeps answers only, under
-- the URL a third party was asked about (scheme, host and path). A cached row
-- is only a saved answer, so these go, and the next lookup asks again.
DELETE FROM shoc.intel_lookups
 WHERE payload->'observations' @> '[{"ok": false}]'::jsonb
    OR (type = 'url' AND (value LIKE '%?%' OR value LIKE '%#%' OR value LIKE '%@%'));
