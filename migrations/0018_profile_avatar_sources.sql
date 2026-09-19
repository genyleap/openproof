ALTER TABLE openproof.external_identities
    ADD COLUMN IF NOT EXISTS display_name text NULL,
    ADD COLUMN IF NOT EXISTS preferred_username text NULL,
    ADD COLUMN IF NOT EXISTS picture_url text NULL;

ALTER TABLE openproof.external_identities
    ADD CONSTRAINT external_identities_display_name_length
        CHECK (display_name IS NULL OR length(display_name) <= 256),
    ADD CONSTRAINT external_identities_preferred_username_length
        CHECK (preferred_username IS NULL OR length(preferred_username) <= 128),
    ADD CONSTRAINT external_identities_picture_url_length
        CHECK (picture_url IS NULL OR length(picture_url) <= 2048);

ALTER TABLE openproof.identity_profiles
    ADD COLUMN IF NOT EXISTS avatar_source text NOT NULL DEFAULT 'auto',
    ADD CONSTRAINT identity_profiles_avatar_source_length
        CHECK (length(avatar_source) BETWEEN 1 AND 128);
