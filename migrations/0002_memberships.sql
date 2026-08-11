ALTER TABLE openproof.identities
    ADD CONSTRAINT identities_organization_identity_unique
    UNIQUE (organization_id, id);

CREATE TABLE openproof.memberships (
    organization_id text NOT NULL,
    identity_id     text NOT NULL,
    state           smallint NOT NULL CHECK (state BETWEEN 0 AND 3),
    invited_at_ms   bigint NOT NULL,
    PRIMARY KEY (organization_id, identity_id),
    FOREIGN KEY (organization_id, identity_id)
        REFERENCES openproof.identities (organization_id, id)
);
CREATE INDEX memberships_by_identity
    ON openproof.memberships (identity_id, organization_id);

CREATE TABLE openproof.membership_roles (
    organization_id text NOT NULL,
    identity_id     text NOT NULL,
    role            text NOT NULL CHECK (length(role) BETWEEN 1 AND 200),
    PRIMARY KEY (organization_id, identity_id, role),
    FOREIGN KEY (organization_id, identity_id)
        REFERENCES openproof.memberships (organization_id, identity_id)
        ON DELETE CASCADE
);
