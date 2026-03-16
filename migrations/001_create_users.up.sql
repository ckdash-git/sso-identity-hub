-- 001_create_users.sql
-- Creates the primary user identity table backed by the identity domain aggregate.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');

CREATE TABLE IF NOT EXISTS sso_users (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    casdoor_id       TEXT        NOT NULL UNIQUE,
    email            TEXT        NOT NULL UNIQUE,
    display_name     TEXT        NOT NULL DEFAULT '',
    avatar_url       TEXT        NOT NULL DEFAULT '',
    organization_id  TEXT        NOT NULL DEFAULT '',
    status           user_status NOT NULL DEFAULT 'active',
    mfa_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_methods      TEXT[]      NOT NULL DEFAULT '{}',
    -- JSONB column stores arbitrary provider-specific IDs (Azure OID, SCIM externalId, etc.)
    external_ids     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    last_login_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sso_users_email        ON sso_users (email);
CREATE INDEX idx_sso_users_casdoor_id   ON sso_users (casdoor_id);
CREATE INDEX idx_sso_users_status       ON sso_users (status);
