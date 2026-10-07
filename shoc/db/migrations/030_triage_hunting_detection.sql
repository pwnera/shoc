-- 030 what triage, the Detection Engineer and the Hunter need to tell shoc's own
-- activity, a person's decision and a source's first day apart from an attack
-- (AGT-3, AGT-13, DET-8, DET-9, DET-11, RFC 0021, RFC 0022, D77, D78, D79)

-- A person who closes a case closes it for good: a later finding on the same
-- entity opens a new case that names this one. Two cases on one entity in the
-- same state are therefore ordinary, and the constraint that forbade it would
-- have failed the second close.
DO $$
DECLARE c text;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'shoc.cases'::regclass AND contype = 'u'
    LOOP
        EXECUTE format('ALTER TABLE shoc.cases DROP CONSTRAINT %I', c);
    END LOOP;
END $$;

ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS related_case_uid text;
-- Who set the disposition: 'human', 'crew' or 'system'. A human's is final.
ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS closed_by text;
ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS disposition_reason text NOT NULL DEFAULT '';
-- A lifetime token ceiling, set on a case a hunt opened (RFC 0022).
ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS token_cap integer;

-- shoc's own footprint and the people who run it (RFC 0021). One row per value:
--   credential  the non-secret id of a credential shoc was given (a Google
--               OAuth client id, a Tailscale client id, a Cloudflare token id)
--   address     an address shoc calls out from
--   operator    an account of the person who runs shoc
--   automation  an account of the company's own automation
-- `scope` is what the credential was granted, for the setup check.
CREATE TABLE IF NOT EXISTS shoc.own_identities (
    tenant_id   text NOT NULL,
    kind        text NOT NULL,
    value       text NOT NULL,
    source      text NOT NULL DEFAULT '',
    scope       text NOT NULL DEFAULT '',
    note        text NOT NULL DEFAULT '',
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, value),
    CONSTRAINT own_identity_kind CHECK (kind IN ('credential','address','operator','automation'))
);

-- Every token request shoc makes with one of those credentials. An event by
-- shoc's credential that does not line up with one of these was not shoc.
CREATE TABLE IF NOT EXISTS shoc.own_token_requests (
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    credential   text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS own_token_requests_at
    ON shoc.own_token_requests (tenant_id, credential, requested_at);

-- When each source's data starts and which accounts it speaks for. Written
-- with LEAST and kept when the source is removed, so removing and adding a
-- source does not restart its learning period, and data loaded by hand (a
-- replay, a test) never counts as a source's history.
CREATE TABLE IF NOT EXISTS shoc.source_history (
    tenant_id        text NOT NULL,
    source           text NOT NULL,
    products         text[] NOT NULL DEFAULT '{}',
    first_loaded_at  timestamptz NOT NULL DEFAULT now(),
    first_event_at   timestamptz,
    last_loaded_at   timestamptz NOT NULL DEFAULT now(),
    account_uids     text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, source)
);
ALTER TABLE shoc.connector_config
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

-- A narrowing of a shipped rule lapses (D77): its item reopens with the
-- events it hid, so nothing stays excluded because nobody looked again.
ALTER TABLE shoc.merged_rules ADD COLUMN IF NOT EXISTS lapses_at timestamptz;
ALTER TABLE shoc.merged_rules ADD COLUMN IF NOT EXISTS case_uid text NOT NULL DEFAULT '';

-- The Hunter reads by ingestion time from where it stopped (RFC 0022), and
-- says per pack whether it could look at all.
ALTER TABLE shoc.hunt_packs ADD COLUMN IF NOT EXISTS ingested_through timestamptz;
ALTER TABLE shoc.hunt_packs ADD COLUMN IF NOT EXISTS readiness text NOT NULL DEFAULT '';
ALTER TABLE shoc.hunt_packs ADD COLUMN IF NOT EXISTS ready_at timestamptz;
ALTER TABLE shoc.hunt_packs ADD COLUMN IF NOT EXISTS inconclusive_streak integer NOT NULL DEFAULT 0;
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS ingested_from timestamptz;
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS ingested_to timestamptz;
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS ruled_out jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS unseen jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE shoc.hunt_runs ADD COLUMN IF NOT EXISTS finding_uid text NOT NULL DEFAULT '';

-- A case a hunt opened used to count as a true positive the moment it opened,
-- and promotion was proposed before the case closed benign. The counter is
-- recomputed from closed cases now.
UPDATE shoc.hunt_packs SET true_positives = 0;

SELECT shoc.enable_tenant_rls();
