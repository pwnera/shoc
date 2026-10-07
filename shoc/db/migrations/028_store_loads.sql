-- 028 when the event store last took a batch (DET-3, D71)
--
-- A detection cycle reads what was ingested since each rule's watermark. When
-- nothing has been loaded since then there is nothing to read, and on a
-- warehouse reading it anyway wakes compute that bills by the minute. One row
-- per tenant, stamped after each load commits, lets the cycle know that from
-- Postgres alone.
CREATE TABLE IF NOT EXISTS shoc.store_loads (
    tenant_id  text PRIMARY KEY,
    loaded_at  timestamptz NOT NULL
);

SELECT shoc.enable_tenant_rls();
