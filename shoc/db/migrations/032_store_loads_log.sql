-- 033 every load the event store committed, with the oldest event it carried (DET-3)
--
-- A cycle reads by `ingested_at`, which is stamped when an event is mapped, and
-- goes back only 10 minutes behind its watermark. A load that commits later
-- than that, such as a slow warehouse load or a kept batch replayed, would never
-- be read. Each load now leaves a row with the oldest `ingested_at` it held, and
-- a cycle reads back to it when the load committed after its watermark. Rows
-- older than a week are pruned as loads arrive.
ALTER TABLE shoc.store_loads ADD COLUMN IF NOT EXISTS stamped_from timestamptz;
ALTER TABLE shoc.store_loads DROP CONSTRAINT IF EXISTS store_loads_pkey;
CREATE INDEX IF NOT EXISTS store_loads_tenant ON shoc.store_loads (tenant_id, loaded_at);
