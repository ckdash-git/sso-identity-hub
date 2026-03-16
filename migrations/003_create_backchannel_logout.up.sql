-- 003_create_backchannel_logout.sql
-- Audit log for every back-channel logout attempt dispatched to third parties.
-- Retaining this data is important for compliance — it proves that downstream
-- applications were notified in a timely manner when a session was terminated.

CREATE TYPE logout_delivery_status AS ENUM ('pending', 'delivered', 'failed');

CREATE TABLE IF NOT EXISTS backchannel_logout_log (
    id              UUID                   PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID                   NOT NULL REFERENCES sso_sessions(id) ON DELETE CASCADE,
    user_id         UUID                   NOT NULL REFERENCES sso_users(id) ON DELETE CASCADE,
    endpoint_url    TEXT                   NOT NULL,
    logout_token    TEXT                   NOT NULL,  -- the signed JWT delivered (for audit)
    status          logout_delivery_status NOT NULL DEFAULT 'pending',
    attempt_count   INT                    NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    error_message   TEXT,
    created_at      TIMESTAMPTZ            NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bcl_session_id ON backchannel_logout_log (session_id);
CREATE INDEX idx_bcl_status     ON backchannel_logout_log (status);
CREATE INDEX idx_bcl_user_id    ON backchannel_logout_log (user_id);
