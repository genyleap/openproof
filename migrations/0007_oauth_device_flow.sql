CREATE TABLE openproof.oauth_device_authorizations (
    device_digest BYTEA PRIMARY KEY,
    user_code_digest BYTEA NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    resource TEXT NULL,
    status SMALLINT NOT NULL CHECK (status BETWEEN 0 AND 3),
    issued_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    poll_interval_ms BIGINT NOT NULL CHECK (poll_interval_ms > 0),
    identity_id TEXT NULL REFERENCES openproof.identities(id) ON DELETE RESTRICT,
    provider TEXT NULL,
    assurance SMALLINT NULL,
    factors SMALLINT NULL,
    phishing_resistant BOOLEAN NULL,
    authenticated_at_ms BIGINT NULL,
    last_poll_at_ms BIGINT NULL,
    CHECK (expires_at_ms > issued_at_ms),
    CHECK ((status IN (0, 2) AND identity_id IS NULL AND provider IS NULL
            AND assurance IS NULL AND factors IS NULL
            AND phishing_resistant IS NULL AND authenticated_at_ms IS NULL)
        OR (status IN (1, 3) AND identity_id IS NOT NULL AND provider IS NOT NULL
            AND assurance IS NOT NULL AND factors IS NOT NULL
            AND phishing_resistant IS NOT NULL AND authenticated_at_ms IS NOT NULL))
);

CREATE TABLE openproof.oauth_device_authorization_scopes (
    device_digest BYTEA NOT NULL REFERENCES openproof.oauth_device_authorizations(device_digest) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (device_digest, scope)
);

CREATE INDEX oauth_device_authorizations_expires_idx
    ON openproof.oauth_device_authorizations(expires_at_ms);
