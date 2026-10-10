-- 055 event-store reads kept until a load can change them (STO-1, OPS-1, D161)
--
-- Source quality, the operations each product sends and the store's own count
-- were read from the event store by every console view, the hourly Ops check
-- and the reports. On a warehouse each read woke compute. `shoc.store.kept`
-- keeps the answer here with the Postgres time the read began, and answers
-- from it until a load commits after that time (`shoc.store_loads`).
CREATE TABLE IF NOT EXISTS shoc.store_reads (
    tenant_id  text NOT NULL,
    name       text NOT NULL,
    read_at    timestamptz NOT NULL,
    value      jsonb NOT NULL,
    PRIMARY KEY (tenant_id, name)
);
SELECT shoc.enable_tenant_rls();
