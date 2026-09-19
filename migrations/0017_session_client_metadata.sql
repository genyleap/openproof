ALTER TABLE openproof.sessions
    ADD COLUMN IF NOT EXISTS user_agent text NULL,
    ADD COLUMN IF NOT EXISTS remote_address text NULL;

ALTER TABLE openproof.sessions
    DROP CONSTRAINT IF EXISTS sessions_user_agent_length,
    ADD CONSTRAINT sessions_user_agent_length
        CHECK (user_agent IS NULL OR length(user_agent) <= 1024);

ALTER TABLE openproof.sessions
    DROP CONSTRAINT IF EXISTS sessions_remote_address_length,
    ADD CONSTRAINT sessions_remote_address_length
        CHECK (remote_address IS NULL OR length(remote_address) <= 128);
