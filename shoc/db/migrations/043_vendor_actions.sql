-- 043 an action is named after the vendor it calls (RSP-4, RFC 0031)
--
-- `waf.block_ip` is `cloudflare.block_ip`. The `idp` and `edr` actions, and the
-- `idp`, `edr` and `waf` credentials, are renamed after this by `shoc migrate`
-- (`credentials.split_legacy`): a secret is sealed to its credential's name,
-- and which vendor an `idp` action called is read from its credential or its
-- case. The audit log keeps the names of the time.
UPDATE shoc.actions SET type = 'cloudflare.block_ip' WHERE type = 'waf.block_ip';
UPDATE shoc.actions SET fallback = 'cloudflare.block_ip' WHERE fallback = 'waf.block_ip';
UPDATE shoc.playbook_steps SET action_type = 'cloudflare.block_ip'
WHERE action_type = 'waf.block_ip';
