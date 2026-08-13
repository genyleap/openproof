ALTER TABLE openproof.identity_profiles
    ADD COLUMN phone_number text NULL,
    ADD COLUMN phone_number_verified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT identity_profiles_phone_verification_consistency
        CHECK (NOT phone_number_verified OR phone_number IS NOT NULL);

CREATE TABLE openproof.account_verification_challenges (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    purpose         smallint NOT NULL CHECK (purpose BETWEEN 0 AND 3),
    channel         smallint NOT NULL CHECK (channel BETWEEN 0 AND 1),
    destination     text NOT NULL CHECK (length(destination) BETWEEN 1 AND 1000),
    secret_digest   bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at_ms   bigint NOT NULL,
    expires_at_ms   bigint NOT NULL CHECK (expires_at_ms > created_at_ms)
);
CREATE INDEX account_verification_by_identity_purpose
    ON openproof.account_verification_challenges(identity_id, purpose);
CREATE INDEX account_verification_expiry
    ON openproof.account_verification_challenges(expires_at_ms);

CREATE TABLE openproof.pending_external_identity_reservations (
    provider            text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    external_subject    text NOT NULL CHECK (length(external_subject) BETWEEN 1 AND 1000),
    identity_id         text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    expires_at_ms       bigint NOT NULL,
    PRIMARY KEY(provider, external_subject)
);
CREATE INDEX pending_external_identity_reservations_expiry
    ON openproof.pending_external_identity_reservations(expires_at_ms);
