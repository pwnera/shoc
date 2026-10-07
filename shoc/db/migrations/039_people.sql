-- 039 people sign in: accounts, their links and the company's identity provider (SEC-3, RFC 0028)
--
-- A person signs in with an email, a password and an authenticator code, or
-- through the company's OIDC provider. A signed-in browser is an api_tokens row
-- carrying the account's user_id and no role of its own, so the account's role
-- applies on every request and a disabled account signs out.
--
-- `secret` columns are sealed with the row as associated data and re-sealed by
-- `shoc rotate-key` (shoc.db.secrets.SEALED). A link keeps only its SHA-256, and
-- the authenticator an enrolling link offers is derived from the link, never
-- stored. Accounts, links and sessions are never deleted: links end by used_at
-- or expiry, sessions by revoked_at or expiry, people by disabled_at.
-- `sso.configure` with clear deletes the provider's row.
CREATE TABLE IF NOT EXISTS shoc.users (
    tenant_id     text NOT NULL,
    user_id       text NOT NULL,
    email         text NOT NULL,
    role          text NOT NULL DEFAULT 'reader',
    password_hash text,
    secret        bytea,
    totp_step     bigint NOT NULL DEFAULT 0,
    sso_issuer    text,
    sso_subject   text,
    code_failures integer NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    disabled_at   timestamptz,
    disabled_by   text,
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT user_role CHECK (role IN ('admin','operator','deployer','reader')),
    CONSTRAINT user_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON shoc.users (tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS users_sso
    ON shoc.users (tenant_id, sso_issuer, sso_subject) WHERE sso_subject IS NOT NULL;

CREATE TABLE IF NOT EXISTS shoc.user_links (
    tenant_id   text NOT NULL,
    link_id     text NOT NULL,
    hash        text NOT NULL,
    user_id     text NOT NULL,
    enrol       boolean NOT NULL,
    wrong_codes integer NOT NULL DEFAULT 0,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    PRIMARY KEY (tenant_id, link_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS user_links_hash ON shoc.user_links (hash);
CREATE INDEX IF NOT EXISTS user_links_user ON shoc.user_links (tenant_id, user_id);

-- One provider per tenant, so a domain belongs to one provider within it.
CREATE TABLE IF NOT EXISTS shoc.sso_providers (
    tenant_id              text NOT NULL,
    provider               text NOT NULL DEFAULT 'oidc',
    issuer                 text NOT NULL,
    client_id              text NOT NULL,
    domains                text[] NOT NULL DEFAULT '{}',
    authorization_endpoint text NOT NULL,
    token_endpoint         text NOT NULL,
    jwks_uri               text NOT NULL,
    secret                 bytea,
    updated_by             text NOT NULL,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider),
    CONSTRAINT sso_provider CHECK (provider = 'oidc')
);

ALTER TABLE shoc.api_tokens ADD COLUMN IF NOT EXISTS user_id text;
CREATE INDEX IF NOT EXISTS api_tokens_user ON shoc.api_tokens (tenant_id, user_id);

SELECT shoc.enable_tenant_rls();
