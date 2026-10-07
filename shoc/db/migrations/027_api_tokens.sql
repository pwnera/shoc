-- 027 bearer tokens issued through the registry (API-1, SEC-1, RFC 0019)
--
-- One row per token. The token itself is never stored, only its SHA-256: it is
-- 32 random bytes, so the hash cannot be reversed and needs no salt. A person's
-- token names a role; a machine's names a kind and its scopes. Rows are never
-- deleted: `revoked_at` ends a token, and the first row ever written ends
-- single-user mode for good, so revoking every token locks the API rather than
-- opening it.
CREATE TABLE IF NOT EXISTS shoc.api_tokens (
    tenant_id   text NOT NULL,
    token_id    text NOT NULL,
    hash        text NOT NULL UNIQUE,
    who         text NOT NULL,
    role        text,
    kind        text NOT NULL DEFAULT 'human',
    scopes      text[] NOT NULL DEFAULT '{}',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,
    revoked_at  timestamptz,
    revoked_by  text,
    PRIMARY KEY (tenant_id, token_id),
    CONSTRAINT api_token_role CHECK (role IS NULL OR role IN ('admin','operator','deployer','reader')),
    CONSTRAINT api_token_kind CHECK (kind IN ('human','agent','external_agent','service'))
);

SELECT shoc.enable_tenant_rls();
