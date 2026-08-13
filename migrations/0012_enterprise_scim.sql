-- RFC 7643/7644 provisioning metadata. Canonical identity/profile/membership remain the source of truth.
CREATE TABLE openproof.scim_users (
    identity_id    text PRIMARY KEY REFERENCES openproof.identities(id) ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES openproof.organizations(id) ON DELETE CASCADE,
    user_name      text NOT NULL CHECK (length(user_name) BETWEEN 1 AND 320),
    external_id    text NULL CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 1024),
    created_at_ms  bigint NOT NULL,
    updated_at_ms  bigint NOT NULL,
    UNIQUE (organization_id, user_name),
    UNIQUE (organization_id, identity_id)
);
CREATE INDEX scim_users_org_idx ON openproof.scim_users(organization_id, identity_id);

CREATE TABLE openproof.scim_groups (
    id             text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES openproof.organizations(id) ON DELETE CASCADE,
    display_name   text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 512),
    external_id    text NULL CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 1024),
    created_at_ms  bigint NOT NULL,
    updated_at_ms  bigint NOT NULL,
    UNIQUE (organization_id, display_name),
    UNIQUE (organization_id, id)
);
CREATE INDEX scim_groups_org_idx ON openproof.scim_groups(organization_id, id);

CREATE TABLE openproof.scim_group_members (
    organization_id text NOT NULL,
    group_id         text NOT NULL,
    identity_id      text NOT NULL,
    PRIMARY KEY (organization_id, group_id, identity_id),
    FOREIGN KEY (organization_id, group_id)
        REFERENCES openproof.scim_groups(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, identity_id)
        REFERENCES openproof.scim_users(organization_id, identity_id) ON DELETE CASCADE
);
CREATE INDEX scim_group_members_identity_idx
    ON openproof.scim_group_members(organization_id, identity_id, group_id);
