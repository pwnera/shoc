-- 066 a pushed delivery waits in Postgres for the next cycle on a warehouse (ING-2, STO-3)
--
-- Each GitHub delivery loaded straight into the event store: on a warehouse a
-- stage, a MERGE and a REMOVE per delivery, then a detection run a minute
-- later, so the warehouse never idled, and a load that failed lost the event
-- (GitHub does not redeliver on its own). On a warehouse the webhook now keeps
-- the delivery's records here and answers at once; the worker loads them in
-- one batch at the start of the cycle's detection run and deletes them once
-- the load succeeded. Postgres loads inline as before. A delivery whose load
-- failed is tried alone after the others; after five failures once a day, its
-- error on the source's health.
CREATE TABLE IF NOT EXISTS shoc.push_spool (
    spool_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    records      jsonb NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    attempts     integer NOT NULL DEFAULT 0,
    tried_at     timestamptz,
    last_error   text
);
CREATE INDEX IF NOT EXISTS push_spool_tenant ON shoc.push_spool (tenant_id, spool_id);

SELECT shoc.enable_tenant_rls();
