-- 052 the rows a source's last run read and stored (ING-1, ING-3, STO-3, D71, D150)
--
-- Every poll starts 15 minutes before the newest event it read, so a quiet
-- source fetches the same page each time, and the store dropped it only after
-- it was loaded: three warehouse statements a page on Databricks, every poll,
-- which kept a serverless warehouse from ever stopping. Each run now keeps an
-- 8-byte digest of the (event_uid, time) of every row it read and stored, and
-- the next run sends the store only the rows it does not find here.
ALTER TABLE shoc.connector_state ADD COLUMN IF NOT EXISTS stored_keys bytea;
