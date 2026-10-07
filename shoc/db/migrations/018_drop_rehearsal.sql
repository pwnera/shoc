-- 018 drop the weekly attack rehearsal (AGT-7)
--
-- The rehearsal is out of scope for now. Its capability, schedule and personas
-- are gone from the code; this stops what a database that ran it would still
-- schedule. Migrations never drop a table, so shoc.rehearsals stays, unread.
DELETE FROM shoc.schedules WHERE kind = 'rehearsal.run';
DELETE FROM shoc.jobs WHERE kind = 'rehearsal.run' AND state = 'pending';
