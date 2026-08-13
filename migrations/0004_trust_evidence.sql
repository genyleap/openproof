-- Provider-neutral verified evidence. Trust assessments are derived, not persisted.
CREATE TABLE openproof.evidence (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    kind            text NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    claim           text NOT NULL CHECK (length(claim) BETWEEN 1 AND 128),
    value           text NOT NULL CHECK (length(value) BETWEEN 1 AND 4096),
    confidence      smallint NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    status          smallint NOT NULL CHECK (status BETWEEN 0 AND 1),
    verified_at_ms  bigint NOT NULL,
    expires_at_ms   bigint NULL CHECK (expires_at_ms IS NULL OR expires_at_ms > verified_at_ms)
);
CREATE INDEX evidence_by_identity ON openproof.evidence(identity_id, status, kind);
