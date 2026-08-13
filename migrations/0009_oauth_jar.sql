CREATE TABLE openproof.oauth_client_request_signing_keys (
    client_id TEXT PRIMARY KEY REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE openproof.oauth_jar_replays (
    client_id TEXT NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    jwt_id TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (client_id, jwt_id)
);

CREATE INDEX oauth_jar_replays_expires_idx ON openproof.oauth_jar_replays(expires_at_ms);
