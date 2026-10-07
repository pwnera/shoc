-- 034 a pushed delivery loads once, whatever its id looks like (ING-2)
--
-- GitHub signs a webhook's body alone, with no timestamp, so a captured
-- delivery can be sent again at any time and still verify. The store keeps one
-- row per event id and time, and a delivery's time came from its id only while
-- GitHub's ids were version-1 UUIDs. Each delivery id is kept here instead, and
-- one seen before loads nothing. Ids older than the event retention are pruned.
CREATE TABLE IF NOT EXISTS shoc.push_deliveries (
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    delivery     text NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source, delivery)
);
CREATE INDEX IF NOT EXISTS push_deliveries_received
    ON shoc.push_deliveries (tenant_id, received_at);

SELECT shoc.enable_tenant_rls();
