-- 023 the query each hunt run executed (DET-9)
--
-- A hunt's outcome can only be argued with if the query behind it can be read
-- back: the SQL as the store ran it, in its dialect, and the values bound to it.
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS query text NOT NULL DEFAULT '';
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS query_params jsonb NOT NULL DEFAULT '{}'::jsonb;
