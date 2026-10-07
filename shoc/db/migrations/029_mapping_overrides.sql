-- 029 a tenant's repaired mapping paths, over the shipped YAML (AGT-13, ING-3, D74)
--
-- When a vendor moves a field, the Integrator (or a person) writes the new
-- paths here. They are merged over the shipped mapping's `fields:` for this
-- tenant only; `constants` and `derive` stay as shipped. `fill` keeps, per
-- column, the share of recent events it filled before and after, which is the
-- check the patch had to pass. Deleting the row restores the shipped mapping.
CREATE TABLE IF NOT EXISTS shoc.mapping_overrides (
    tenant_id   text NOT NULL,
    source      text NOT NULL,
    fields      jsonb NOT NULL,
    reason      text NOT NULL DEFAULT '',
    fill        jsonb NOT NULL DEFAULT '{}'::jsonb,
    written_by  text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

-- What the model was last shown for a source, so it is asked once per change
-- of shape rather than every day the same fields stay empty.
ALTER TABLE shoc.source_onboarding
    ADD COLUMN IF NOT EXISTS repair_tried text NOT NULL DEFAULT '';

SELECT shoc.enable_tenant_rls();
