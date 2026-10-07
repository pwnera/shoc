-- 014 The openspace: peer requests and interruptions (AGT-1, AGT-2, RFC 0010)
--
-- The case room becomes the openspace. The table is renamed rather than
-- recreated, so policies, indexes and the cases foreign key survive and no
-- message is copied.
ALTER TABLE IF EXISTS shoc.room_messages RENAME TO openspace_messages;
ALTER INDEX IF EXISTS shoc.room_case_round RENAME TO openspace_case_round;

-- An agent may now address a peer directly instead of only speaking to the
-- case: `to_agent` is who a request is for, and who an answer is for.
ALTER TABLE shoc.openspace_messages ADD COLUMN IF NOT EXISTS to_agent text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS openspace_unanswered
    ON shoc.openspace_messages (tenant_id, case_uid, to_agent)
    WHERE kind = 'request';

-- Three kinds join the protocol: `request` and `answer` for one agent asking
-- another for something, `interject` for an agent that was not scheduled to
-- speak and recognised its own subject.
ALTER TABLE shoc.openspace_messages DROP CONSTRAINT IF EXISTS room_message_kind;
ALTER TABLE shoc.openspace_messages DROP CONSTRAINT IF EXISTS openspace_message_kind;
ALTER TABLE shoc.openspace_messages ADD CONSTRAINT openspace_message_kind CHECK (kind IN (
    'observation','hypothesis','evidence','challenge','concede',
    'proposal','decision','inject','request','answer','interject'));
