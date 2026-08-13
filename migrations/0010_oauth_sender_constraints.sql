-- RFC 9449 / RFC 8705 sender constraints and DPoP replay state.
ALTER TABLE openproof.oauth_token_families
    ADD COLUMN sender_constraint_kind smallint NULL
        CHECK (sender_constraint_kind IS NULL OR sender_constraint_kind BETWEEN 0 AND 1),
    ADD COLUMN sender_constraint_value text NULL
        CHECK (sender_constraint_value IS NULL OR length(sender_constraint_value) BETWEEN 1 AND 256),
    ADD CONSTRAINT oauth_token_family_sender_constraint_pair
        CHECK ((sender_constraint_kind IS NULL) = (sender_constraint_value IS NULL));

CREATE TABLE openproof.oauth_dpop_replays (
    jwk_thumbprint  text NOT NULL CHECK (length(jwk_thumbprint) BETWEEN 1 AND 128),
    jwt_id          text NOT NULL CHECK (length(jwt_id) BETWEEN 1 AND 256),
    expires_at_ms   bigint NOT NULL,
    PRIMARY KEY (jwk_thumbprint, jwt_id)
);
CREATE INDEX oauth_dpop_replays_expiry
    ON openproof.oauth_dpop_replays (expires_at_ms);

CREATE TABLE openproof.oauth_mtls_forwarding_replays (
    certificate_thumbprint text NOT NULL CHECK (length(certificate_thumbprint) BETWEEN 1 AND 128),
    nonce                  text NOT NULL CHECK (length(nonce) BETWEEN 1 AND 256),
    expires_at_ms          bigint NOT NULL,
    PRIMARY KEY (certificate_thumbprint, nonce)
);
CREATE INDEX oauth_mtls_forwarding_replays_expiry
    ON openproof.oauth_mtls_forwarding_replays (expires_at_ms);
