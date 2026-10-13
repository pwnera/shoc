-- 064 an indicator keeps the TLP marking its source shared it under (DET-4, DET-6)
--
-- A MISP event's tlp:* tag, an OTX pulse's tlp field or a report's TLP:<colour>
-- line is the sharing term the company accepted to get the intel. A value
-- marked amber, amber+strict or red is not sent to a third-party lookup; ''
-- means no marking. Rows stored before this carry none.
ALTER TABLE shoc.iocs ADD COLUMN IF NOT EXISTS tlp text NOT NULL DEFAULT '';
