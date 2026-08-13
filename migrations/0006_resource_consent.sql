-- Durable OAuth resource/audience registry, service identities, and end-user consent.

CREATE TABLE openproof.oauth_resources (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    audience        text NOT NULL UNIQUE CHECK (length(audience) BETWEEN 1 AND 2048),
    display_name    text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    status          smallint NOT NULL CHECK (status BETWEEN 0 AND 2),
    created_at_ms   bigint NOT NULL,
    updated_at_ms   bigint NOT NULL CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE openproof.oauth_resource_scopes (
    resource_id     text NOT NULL REFERENCES openproof.oauth_resources(id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (resource_id, scope)
);

CREATE TABLE openproof.service_identities (
    client_id       text PRIMARY KEY REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    identity_id     text NOT NULL UNIQUE REFERENCES openproof.identities(id) ON DELETE CASCADE,
    active          boolean NOT NULL,
    created_at_ms   bigint NOT NULL,
    updated_at_ms   bigint NOT NULL CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE openproof.service_identity_audiences (
    client_id       text NOT NULL REFERENCES openproof.service_identities(client_id) ON DELETE CASCADE,
    audience        text NOT NULL REFERENCES openproof.oauth_resources(audience) ON UPDATE CASCADE,
    PRIMARY KEY (client_id, audience)
);

CREATE TABLE openproof.service_identity_scopes (
    client_id       text NOT NULL REFERENCES openproof.service_identities(client_id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE openproof.oauth_consents (
    id              text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    identity_id     text NOT NULL REFERENCES openproof.identities(id) ON DELETE CASCADE,
    client_id       text NOT NULL REFERENCES openproof.oauth_clients(id) ON DELETE CASCADE,
    audience        text NOT NULL CHECK (length(audience) BETWEEN 1 AND 2048),
    granted_at_ms   bigint NOT NULL,
    expires_at_ms   bigint NULL CHECK (expires_at_ms IS NULL OR expires_at_ms > granted_at_ms),
    revoked_at_ms   bigint NULL CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= granted_at_ms)
);
CREATE INDEX oauth_consents_active_lookup
    ON openproof.oauth_consents (identity_id, client_id, audience, granted_at_ms DESC);

CREATE TABLE openproof.oauth_consent_scopes (
    consent_id      text NOT NULL REFERENCES openproof.oauth_consents(id) ON DELETE CASCADE,
    scope           text NOT NULL CHECK (length(scope) BETWEEN 1 AND 128),
    PRIMARY KEY (consent_id, scope)
);

ALTER TABLE openproof.oauth_authorization_codes
    ADD COLUMN resource text NULL CHECK (resource IS NULL OR length(resource) BETWEEN 1 AND 2048);

CREATE TABLE openproof.oauth_token_family_audiences (
    family_id       text NOT NULL REFERENCES openproof.oauth_token_families(id) ON DELETE CASCADE,
    audience        text NOT NULL CHECK (length(audience) BETWEEN 1 AND 2048),
    PRIMARY KEY (family_id, audience)
);
