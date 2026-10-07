-- 016 openspace repeats and crew attempts (AGT-1, OPS-1)
--
-- Two counters that used to be kept by writing into the record they describe.
--
-- `repeats` lets an identical message be collapsed instead of appended. A crew
-- run that cannot reach its model posts the same Sentinel observation and the
-- same Orchestrator failure every time it is retried, so a case a flaky gateway
-- touched for a day held dozens of byte-identical messages and no more
-- information than the first one.
--
-- `crew_attempts` is where the sweep counts its tries. It used to count
-- Sentinel observations in the last hour, which made the retry counter and the
-- noise the same thing: the only way to remember a failed attempt was to write
-- another copy of it into the case.

ALTER TABLE shoc.openspace_messages
    ADD COLUMN IF NOT EXISTS repeats integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_repeat_at timestamptz;

ALTER TABLE shoc.cases
    ADD COLUMN IF NOT EXISTS crew_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS crew_attempted_at timestamptz;
