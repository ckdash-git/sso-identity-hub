-- 002_create_sessions.sql
-- Session table stores per-browser authenticated sessions.
-- The sid column is the OIDC Session ID embedded in ID tokens — it is the
-- key used to match back-channel logout tokens to active local sessions.

CREATE TYPE session_state AS ENUM ('active', 'revoked', 'expired');

CREATE TABLE IF NOT EXISTS sso_sessions (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID         NOT NULL REFERENCES sso_users(id) ON DELETE CASCADE,
    sid           TEXT         NOT NULL UNIQUE,  -- OIDC session ID (sid claim)
    access_token  TEXT         NOT NULL,
    refresh_token TEXT         NOT NULL,
    client_id     TEXT         NOT NULL DEFAULT '',
    ip_address    TEXT         NOT NULL DEFAULT '',
    user_agent    TEXT         NOT NULL DEFAULT '',
    state         session_state NOT NULL DEFAULT 'active',
    expires_at    TIMESTAMPTZ  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX idx_sso_sessions_user_id    ON sso_sessions (user_id);
CREATE INDEX idx_sso_sessions_sid        ON sso_sessions (sid);
CREATE INDEX idx_sso_sessions_state      ON sso_sessions (state);
CREATE INDEX idx_sso_sessions_expires_at ON sso_sessions (expires_at);
