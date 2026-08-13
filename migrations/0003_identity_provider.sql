-- Central Identity Provider, OAuth/OIDC and application/client registry.
-- Secrets and bearer credentials are represented only by keyed digests.

CREATE TABLE openproof.applications (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    organization_id text NOT NULL REFERENCES openproof.organizations(id),
    identifier      text NOT NULL CHECK (length(identifier) BETWEEN 2 AND 64),
    display_name    text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    environment     smallint NOT NULL CHECK (environment BETWEEN 0 AND 2),
    status          smallint NOT NULL CHECK (status BETWEEN 0 AND 2),
    created_at_ms   bigint NOT NULL,
    updated_at_ms   bigint NOT NULL CHECK (updated_at_ms >= created_at_ms)
);
CREATE UNIQUE INDEX applications_identifier_per_organization
    ON openproof.applications (organization_id, identifier);
CREATE INDEX applications_by_organization
    ON openproof.applications (organization_id, environment, status);

CREATE TABLE openproof.oauth_clients (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 256),
    application_id  text NOT NULL REFERENCES openproof.applications(id) ON DELETE CASCADE,
    display_name    text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    kind            smallint NOT NULL CHECK (kind BETWEEN 0 AND 3),
    status          smallint NOT NULL CHECK (status BETWEEN 0 AND 2),
    secret_digest   bytea NULL CHECK (secret_digest IS NULL OR octet_length(secret_digest) = 32),
    created_at_ms   bigint NOT NULL,
    updated_at_ms   bigint NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK ((kind IN (1,2) AND secret_digest IS NULL)
        OR (kind IN (0,3) AND secret_digest IS NOT NULL))
);
CREATE INDEX oauth_clients_by_application
    ON openproof.oauth_clients (application_id, status);

CREATE TABLE openproof.oauth_client_redirect_uris (
    client_id       text NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    redirect_uri    text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE openproof.oauth_client_scopes (
    client_id       text NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE openproof.identity_profiles (
    identity_id         text PRIMARY KEY REFERENCES openproof.identities(id) ON DELETE CASCADE,
    display_name        text NULL,
    preferred_username  text NULL,
    email               text NULL,
    email_verified      boolean NOT NULL DEFAULT false,
    locale              text NULL,
    picture_url         text NULL,
    created_at_ms       bigint NOT NULL,
    updated_at_ms       bigint NOT NULL CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE openproof.oauth_authorization_codes (
    code_digest         bytea PRIMARY KEY CHECK (octet_length(code_digest) = 32),
    client_id           text NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    identity_id         text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    redirect_uri        text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
    code_challenge      text NOT NULL CHECK (length(code_challenge) = 43),
    nonce               text NULL CHECK (nonce IS NULL OR length(nonce) <= 512),
    provider            text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    assurance           smallint NOT NULL CHECK (assurance BETWEEN 0 AND 4),
    factors             smallint NOT NULL CHECK (factors BETWEEN 0 AND 7),
    phishing_resistant  boolean NOT NULL,
    authenticated_at_ms bigint NOT NULL,
    issued_at_ms        bigint NOT NULL,
    expires_at_ms       bigint NOT NULL CHECK (expires_at_ms > issued_at_ms)
);
CREATE INDEX oauth_authorization_codes_expiry
    ON openproof.oauth_authorization_codes (expires_at_ms);

CREATE TABLE openproof.oauth_authorization_code_scopes (
    code_digest     bytea NOT NULL REFERENCES openproof.oauth_authorization_codes(code_digest)
                    ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (code_digest, scope)
);

CREATE TABLE openproof.oauth_token_families (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    client_id       text NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    assurance       smallint NOT NULL CHECK (assurance BETWEEN 0 AND 4),
    factors         smallint NOT NULL CHECK (factors BETWEEN 0 AND 7),
    phishing_resistant boolean NOT NULL,
    authenticated_at_ms bigint NOT NULL,
    revoked_at_ms   bigint NULL
);
CREATE INDEX oauth_token_families_subject
    ON openproof.oauth_token_families (identity_id, client_id);

CREATE TABLE openproof.oauth_token_family_scopes (
    family_id       text NOT NULL REFERENCES openproof.oauth_token_families(id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (family_id, scope)
);

CREATE TABLE openproof.oauth_access_tokens (
    token_digest    bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    family_id       text NOT NULL REFERENCES openproof.oauth_token_families(id) ON DELETE CASCADE,
    state           smallint NOT NULL CHECK (state BETWEEN 0 AND 1),
    issued_at_ms    bigint NOT NULL,
    expires_at_ms   bigint NOT NULL CHECK (expires_at_ms > issued_at_ms),
    revoked_at_ms   bigint NULL,
    CHECK ((state = 1) = (revoked_at_ms IS NOT NULL))
);
CREATE INDEX oauth_access_tokens_family
    ON openproof.oauth_access_tokens (family_id, state);
CREATE INDEX oauth_access_tokens_expiry
    ON openproof.oauth_access_tokens (expires_at_ms);

CREATE TABLE openproof.oauth_refresh_tokens (
    token_digest    bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    family_id       text NOT NULL REFERENCES openproof.oauth_token_families(id) ON DELETE CASCADE,
    sequence        bigint NOT NULL CHECK (sequence >= 0),
    state           smallint NOT NULL CHECK (state BETWEEN 0 AND 2),
    issued_at_ms    bigint NOT NULL,
    expires_at_ms   bigint NOT NULL CHECK (expires_at_ms > issued_at_ms),
    changed_at_ms   bigint NULL,
    UNIQUE (family_id, sequence)
);
CREATE INDEX oauth_refresh_tokens_family
    ON openproof.oauth_refresh_tokens (family_id, sequence);
CREATE INDEX oauth_refresh_tokens_expiry
    ON openproof.oauth_refresh_tokens (expires_at_ms);
