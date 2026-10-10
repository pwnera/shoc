-- 054 when a rule last read every load committed before it (DET-3, D160)
--
-- A cycle reads 10 minutes behind its watermark, and skipped a rule only when
-- no load of its products fell after that. So the cycle a load woke read it,
-- and the scheduled cycle after it read it again: on 2026-10-10 the Databricks
-- Free Edition instance woke its warehouse at :30 and :45 of most hours to
-- reread loads from :15 and :30. Each rule now keeps the Postgres time its last
-- complete read began, the clock `shoc.store_loads` is stamped on, and a cycle
-- skips it when no load of its products committed after that.
ALTER TABLE shoc.rule_state ADD COLUMN IF NOT EXISTS loads_seen_at timestamptz;
