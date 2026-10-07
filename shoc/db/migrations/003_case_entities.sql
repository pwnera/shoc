-- 003 correlate cases by the entities a finding touches, not by one string (RSP-1)
ALTER TABLE shoc.findings ADD COLUMN IF NOT EXISTS entities text[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS shoc.case_entities (
    tenant_id text NOT NULL,
    case_uid  text NOT NULL REFERENCES shoc.cases(case_uid) ON DELETE CASCADE,
    entity    text NOT NULL,
    PRIMARY KEY (tenant_id, case_uid, entity)
);
CREATE INDEX IF NOT EXISTS case_entities_lookup ON shoc.case_entities (tenant_id, entity);
