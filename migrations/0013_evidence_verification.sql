-- One-time challenges used to bind external evidence proofs to an authenticated identity.
CREATE TABLE openproof.evidence_verification_challenges (
    digest          text PRIMARY KEY CHECK (length(digest) = 64),
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    issued_at_ms    bigint NOT NULL,
    expires_at_ms   bigint NOT NULL CHECK (expires_at_ms > issued_at_ms),
    consumed_at_ms  bigint NULL CHECK (consumed_at_ms IS NULL OR consumed_at_ms >= issued_at_ms)
);
CREATE INDEX evidence_verification_challenges_expiry
    ON openproof.evidence_verification_challenges(expires_at_ms)
    WHERE consumed_at_ms IS NULL;
