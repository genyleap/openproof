-- Non-secret journal for offline multi-purpose master-key rotations.
-- Every state row whose verifier is derived from the retired master is removed
-- in the same transaction as this record. Durable one-way credentials use the
-- independent keys required by the rotation command.
CREATE TABLE openproof.master_key_rotations (
    sequence                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    from_version                integer NOT NULL CHECK (from_version > 0),
    to_version                  integer NOT NULL CHECK (to_version > from_version),
    from_fingerprint            bytea NOT NULL CHECK (octet_length(from_fingerprint) = 32),
    to_fingerprint              bytea NOT NULL CHECK (octet_length(to_fingerprint) = 32),
    authentication_transactions bigint NOT NULL CHECK (authentication_transactions >= 0),
    sessions                    bigint NOT NULL CHECK (sessions >= 0),
    account_challenges          bigint NOT NULL CHECK (account_challenges >= 0),
    authorization_codes         bigint NOT NULL CHECK (authorization_codes >= 0),
    token_families              bigint NOT NULL CHECK (token_families >= 0),
    device_authorizations       bigint NOT NULL CHECK (device_authorizations >= 0),
    pushed_requests             bigint NOT NULL CHECK (pushed_requests >= 0),
    rotated_at_ms               bigint NOT NULL,
    UNIQUE (to_version),
    CHECK (from_fingerprint <> to_fingerprint)
);
