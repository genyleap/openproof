-- OpenProof production schema. All timestamps are Unix epoch milliseconds so
-- the storage representation exactly matches foundation::Instant.

CREATE SCHEMA IF NOT EXISTS openproof;

CREATE TABLE IF NOT EXISTS openproof.organizations (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 500),
    state           smallint NOT NULL CHECK (state BETWEEN 0 AND 2),
    created_at_ms   bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openproof.identities (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    organization_id text NOT NULL REFERENCES openproof.organizations(id),
    kind            smallint NOT NULL CHECK (kind BETWEEN 0 AND 3),
    status          smallint NOT NULL CHECK (status BETWEEN 0 AND 5),
    created_at_ms   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS identities_by_organization
    ON openproof.identities (organization_id, id);

CREATE TABLE IF NOT EXISTS openproof.external_identities (
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    external_subject text NOT NULL CHECK (length(external_subject) BETWEEN 1 AND 1000),
    identity_id     text NOT NULL REFERENCES openproof.identities(id),
    linked_at_ms    bigint NOT NULL,
    PRIMARY KEY (provider, external_subject)
);
CREATE INDEX IF NOT EXISTS external_identities_by_identity
    ON openproof.external_identities (identity_id);

CREATE TABLE IF NOT EXISTS openproof.authentication_transactions (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    interaction     smallint NOT NULL CHECK (interaction BETWEEN 0 AND 4),
    nonce_digest    bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    binding_digest  bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    correlation_id  text NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
    state           smallint NOT NULL CHECK (state BETWEEN 0 AND 3),
    created_at_ms   bigint NOT NULL,
    expires_at_ms   bigint NOT NULL CHECK (expires_at_ms > created_at_ms)
);
CREATE INDEX IF NOT EXISTS authentication_transactions_expiry
    ON openproof.authentication_transactions (expires_at_ms);

CREATE TABLE IF NOT EXISTS openproof.authentication_transaction_metadata (
    transaction_id  text NOT NULL REFERENCES openproof.authentication_transactions(id)
                    ON DELETE CASCADE,
    key             text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
    value           text NOT NULL CHECK (length(value) <= 8192),
    PRIMARY KEY (transaction_id, key)
);

CREATE TABLE IF NOT EXISTS openproof.sessions (
    id                  text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    identity_id         text NOT NULL REFERENCES openproof.identities(id),
    provider            text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    assurance           smallint NOT NULL CHECK (assurance BETWEEN 0 AND 4),
    factors             smallint NOT NULL CHECK (factors BETWEEN 0 AND 7),
    phishing_resistant  boolean NOT NULL,
    state               smallint NOT NULL CHECK (state BETWEEN 0 AND 2),
    token_digest        bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    authenticated_at_ms bigint NOT NULL,
    issued_at_ms        bigint NOT NULL,
    last_seen_at_ms     bigint NOT NULL,
    absolute_expires_at_ms bigint NOT NULL,
    idle_timeout_ms     bigint NOT NULL CHECK (idle_timeout_ms > 0),
    revoked_at_ms       bigint NULL,
    CHECK (authenticated_at_ms <= issued_at_ms),
    CHECK (issued_at_ms <= last_seen_at_ms),
    CHECK (last_seen_at_ms < absolute_expires_at_ms),
    CHECK ((state = 1) = (revoked_at_ms IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS sessions_by_identity_state
    ON openproof.sessions (identity_id, state);
CREATE INDEX IF NOT EXISTS sessions_expiry
    ON openproof.sessions (absolute_expires_at_ms, last_seen_at_ms);

CREATE TABLE IF NOT EXISTS openproof.password_credentials (
    identity_id     text PRIMARY KEY REFERENCES openproof.identities(id) ON DELETE CASCADE,
    password_hash   text NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 4096),
    changed_at_ms   bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openproof.totp_credentials (
    identity_id         text PRIMARY KEY REFERENCES openproof.identities(id) ON DELETE CASCADE,
    encrypted_seed      bytea NOT NULL,
    key_version         integer NOT NULL CHECK (key_version > 0),
    last_accepted_step  bigint NULL CHECK (last_accepted_step >= 0),
    enrolled_at_ms      bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS openproof.recovery_codes (
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    code_digest     bytea NOT NULL CHECK (octet_length(code_digest) = 32),
    issued_at_ms    bigint NOT NULL,
    PRIMARY KEY (identity_id, code_digest)
);

CREATE TABLE IF NOT EXISTS openproof.audit_events (
    sequence        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id        text NOT NULL UNIQUE,
    occurred_at_ms  bigint NOT NULL,
    correlation_id  text NOT NULL,
    organization_id text NULL,
    identity_id     text NULL,
    category        text NOT NULL,
    action          text NOT NULL,
    outcome         text NOT NULL,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    previous_hash   bytea NULL CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    event_hash      bytea NOT NULL CHECK (octet_length(event_hash) = 32)
);
CREATE INDEX IF NOT EXISTS audit_events_by_correlation
    ON openproof.audit_events (correlation_id, sequence);
CREATE INDEX IF NOT EXISTS audit_events_by_identity
    ON openproof.audit_events (identity_id, sequence);

-- An append-only outbox makes security-event publication part of the same
-- transaction as the authoritative state change.
CREATE TABLE IF NOT EXISTS openproof.security_event_outbox (
    sequence        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id        text NOT NULL UNIQUE,
    occurred_at_ms  bigint NOT NULL,
    payload         jsonb NOT NULL,
    published_at_ms bigint NULL,
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
CREATE INDEX IF NOT EXISTS security_event_outbox_pending
    ON openproof.security_event_outbox (sequence) WHERE published_at_ms IS NULL;
