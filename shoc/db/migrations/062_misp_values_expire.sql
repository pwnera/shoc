-- 062 a MISP value stored before it had an expiry gets one (DET-4)
--
-- MISP values were stored at 0.8 with no expiry. The upsert keeps an indicator
-- permanent whenever either side has no expiry and keeps the higher confidence,
-- so these rows never expired and never dropped to the 0.7 MISP values now get.
-- They get the 30 days a new one does, counted from now; the next pull extends
-- the ones MISP still lists.
UPDATE shoc.iocs
   SET expires_at = now() + interval '30 days',
       confidence = LEAST(confidence, 0.7)
 WHERE source = 'misp' AND expires_at IS NULL;
