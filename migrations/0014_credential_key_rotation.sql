-- Durable, non-secret journal for offline credential-envelope key rotations.
-- The encrypted credential rows and this record are committed in one transaction.
CREATE TABLE openproof.credential_key_rotations (
    sequence        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    purpose         text NOT NULL CHECK (purpose IN ('totp')),
    from_version    integer NOT NULL CHECK (from_version > 0),
    to_version      integer NOT NULL CHECK (to_version > from_version),
    rekeyed_rows    bigint NOT NULL CHECK (rekeyed_rows >= 0),
    unchanged_rows  bigint NOT NULL CHECK (unchanged_rows >= 0),
    rotated_at_ms   bigint NOT NULL,
    UNIQUE (purpose, to_version)
);
