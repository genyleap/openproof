CREATE TABLE openproof.passkey_registration_ceremonies (
    id text PRIMARY KEY,
    identity_id text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    expires_at_ms bigint NOT NULL,
    consumed_at_ms bigint
);
CREATE INDEX passkey_registration_expiry_idx
    ON openproof.passkey_registration_ceremonies(expires_at_ms);

CREATE TABLE openproof.passkey_credentials (
    credential_id text PRIMARY KEY,
    identity_id text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    public_key_x text NOT NULL,
    public_key_y text NOT NULL,
    sign_count bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    created_at_ms bigint NOT NULL,
    last_used_at_ms bigint NOT NULL
);
CREATE INDEX passkey_credentials_identity_idx
    ON openproof.passkey_credentials(identity_id, created_at_ms);
