-- Provider-returned public profile links only; never synthesize these from names
-- or an OpenID Connect sub. Existing linked accounts remain valid without a URL.
ALTER TABLE openproof.external_identities
    ADD COLUMN IF NOT EXISTS profile_url text NULL;

ALTER TABLE openproof.external_identities
    ADD CONSTRAINT external_identities_profile_url_length
        CHECK (profile_url IS NULL OR length(profile_url) <= 2048);
