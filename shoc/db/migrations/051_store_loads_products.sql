-- 051 the products each load brought (DET-3, D71, D149)
--
-- A cycle skipped the store only when nothing at all was loaded since a rule's
-- watermark, so a GitHub push woke all 182 rules, 167 of them over other
-- products. Each load now names the `metadata_product` values it held, and a
-- rule reads the store only when one of its products was loaded since its
-- watermark. A row from before this column counts for every product.
ALTER TABLE shoc.store_loads ADD COLUMN IF NOT EXISTS products text[];
