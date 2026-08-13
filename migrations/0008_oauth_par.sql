CREATE TABLE openproof.oauth_pushed_authorization_requests (
    request_digest BYTEA PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT NULL,
    nonce TEXT NULL,
    maximum_authentication_age_ms BIGINT NULL,
    resource TEXT NULL,
    response_mode SMALLINT NOT NULL CHECK (response_mode BETWEEN 0 AND 1),
    issued_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    CHECK (expires_at_ms > issued_at_ms)
);

CREATE TABLE openproof.oauth_pushed_authorization_request_scopes (
    request_digest BYTEA NOT NULL REFERENCES openproof.oauth_pushed_authorization_requests(request_digest) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (request_digest, scope)
);

CREATE INDEX oauth_pushed_authorization_requests_expires_idx
    ON openproof.oauth_pushed_authorization_requests(expires_at_ms);
