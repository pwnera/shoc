-- 063 where the last audit walk ended (SEC-1, OPS-1)
--
-- `health.audit` walked every row of a tenant's chain from the first and
-- recomputed each HMAC, from the hourly check and from each console view that
-- listed recent rows. The log is never pruned, so each call grew with it. A
-- walk that finds the chain whole keeps its last row here, and the next one
-- starts after it. The worker still walks the whole chain once a day, timed by
-- its own clock and not by anything in this table, so a rewrite of rows an
-- earlier walk passed is still found (shoc/db/audit.py, check).
CREATE TABLE IF NOT EXISTS shoc.audit_checkpoints (
    tenant_id   text PRIMARY KEY,
    seq         bigint NOT NULL,
    hash        text NOT NULL,
    verified_at timestamptz NOT NULL DEFAULT now()
);
SELECT shoc.enable_tenant_rls();
